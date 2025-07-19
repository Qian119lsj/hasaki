#pragma once

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#include "hasaki/endpoint_mapper.h"
#include "hasaki/socks5_client.h"
#include "hasaki/packet_forwarder.h"
#include "hasaki/udp_packet_injector.h"

#include <string>
#include <thread>
#include <vector>
#include <atomic>
#include <memory>

class ProxySession; // 前向声明
class MainWindow; // 前向声明

// IO操作类型
enum IO_OPERATION {
    IO_NONE,   // 无操作
    IO_ACCEPT, // 接受新连接
    IO_RECV,   // 接收数据
    IO_SEND,   // 发送数据
    IO_RECV_UDP,
    IO_SEND_UDP,
    OP_EXIT,
};

// 套接字类型
enum SocketType {
    TYPE_NONE,     // 无套接字类型
    CLIENT_SOCKET, // 客户端套接字
    TARGET_SOCKET  // 目标套接字
};

enum IPVersion { IPV4, IPV6 };
enum ProtocolType { TCP, UDP };

struct PerSocketData {
    SOCKET clientSocket;
    SOCKET serverSocket; // 对于 TCP 客户端，这是它所连接的监听套接字
    IPVersion ipVersion;
    ProtocolType protocolType;
    IO_OPERATION operation;
    sockaddr_storage clientAddr; // 存储客户端地址
    std::string clientAddrStr;
    std::string clientPortStr;
    std::atomic<long> ioCount;
    std::atomic<bool> isClosing;

    PerSocketData() : clientSocket(INVALID_SOCKET), serverSocket(INVALID_SOCKET), ioCount(0) {}
    void TryToCloseSocketData(PerSocketData *pSocketData) {
        // 1. 标记正在关闭，防止新的I/O被投递
        // 使用 exchange 确保原子地设置并获取旧值
        if (pSocketData->isClosing.exchange(true) == true) {
            // 如果已经有其他线程在关闭了，直接返回，防止重复关闭
            return;
        }

        // 2. 关闭 socket 句柄
        // 这一步是关键！closesocket() 会让所有挂起的 I/O 操作立即失败返回。
        // 这会"冲刷(flush)"所有挂起的 I/O，让它们的完成包快速进入 IOCP 队列。
        if (pSocketData->clientSocket != INVALID_SOCKET) {
            closesocket(pSocketData->clientSocket);
            pSocketData->clientSocket = INVALID_SOCKET;
        }

        // 3. 检查是否可以立即释放内存
        // 如果当前没有任何挂起的 I/O 操作，那么现在就可以安全地删除 PerSocketData 了。
        if (pSocketData->ioCount.load() == 0) {
            delete pSocketData;
            pSocketData = nullptr;
        }
        // 如果 ioCount > 0，我们什么都不做。
        // 因为之后那些被 closesocket() 中断的 I/O 操作会陆续返回，
        // 它们在返回时会递减 ioCount，最后一个返回的操作会负责删除 pSocketData。
    }
};

// 每个IO操作的上下文
struct IOContext {
    OVERLAPPED overlapped;                 // 重叠IO结构
    WSABUF wsa_buf;                        // WSA缓冲区
    char buffer[8192];                     // 数据缓冲区
    SOCKET socket;                         // 关联的套接字
    IO_OPERATION operation;                // 操作类型
    SocketType socket_type;                // 套接字类型
    std::shared_ptr<ProxySession> session; // 指向ProxySession的指针
    sockaddr_storage remote_addr;          // 用于UDP的远程地址
    int remote_addr_len;                   // 远程地址长度
    PerSocketData *per_socket_data;

    IOContext() : socket(INVALID_SOCKET), operation(IO_NONE), socket_type(TYPE_NONE), session(nullptr) {
        ZeroMemory(&overlapped, sizeof(OVERLAPPED));
        wsa_buf.buf = buffer;
        wsa_buf.len = sizeof(buffer);
        remote_addr_len = sizeof(remote_addr);
    }

    ~IOContext() = default;

    void reset() {
        ZeroMemory(&overlapped, sizeof(OVERLAPPED));
        wsa_buf.buf = buffer;
        wsa_buf.len = sizeof(buffer);
        remote_addr_len = sizeof(remote_addr);
        ZeroMemory(buffer, sizeof(buffer));
    }

    operator LPOVERLAPPED() { return &overlapped; }
};


// 连接上下文，管理客户端和目标服务器之间的连接
class ProxySession {
public:
    ProxySession(SOCKET client_socket, SOCKET target_socket, const std::string &mapper_key, MappingType mapping_type = MappingType::UNKNOWN);
    ~ProxySession();

    void close();

    SOCKET get_client_socket() const { return client_socket; }
    SOCKET get_target_socket() const { return target_socket; }

    PerSocketData *client_per_socket_data;
    PerSocketData *target_per_socket_data;

private:
    MappingType mapping_type_;
    std::string mapper_key_;
    SOCKET client_socket; // 客户端套接字
    SOCKET target_socket; // 目标服务器套接字
    static void createDelayedRemover(const std::string &key, MappingType type);
};

// 代理服务器类
class ProxyServer {
public:
    ProxyServer(EndpointMapper *endpoint_mapper);
    ~ProxyServer();

    // 设置SOCKS5服务器地址和端口
    void setSocks5Server(const std::string &address, uint16_t port);
    void setPacketForwarder(PacketForwarder *forwarder);
    
    // 获取MainWindow引用
    MainWindow* getMainWindow() const {
        if (packet_forwarder_) {
            return packet_forwarder_->getMainWindow();
        }
        return nullptr;
    }

    // 启动代理服务器
    bool start(uint16_t port, uint16_t worker_threads = 4);

    // 停止代理服务器
    void stop();

private:
    // 工作线程函数
    void worker_thread_func();

    // 发布接受连接请求
    void post_tcp_accept(SOCKET socket, IOContext *io_context);

    // 为UDP投递接收请求
    void post_udp_recv(SOCKET socket, IOContext *io_context);

    // 处理新接受的连接
    bool handle_tcp_accept(PerSocketData *per_socket_data, IOContext *io_context);

    // 处理TCP接收
    bool handle_tcp_receive(PerSocketData *per_socket_data, IOContext *io_context, DWORD bytes_transferred);

    // 处理TCP发送
    bool handle_tcp_send(PerSocketData *per_socket_data, IOContext *io_context, DWORD bytes_transferred);

    // 处理UDP接收
    void handle_udp_receive(PerSocketData *per_socket_data, IOContext *io_context, DWORD bytes_transferred);

    // 处理来自SOCKS5服务器的UDP响应
    void handle_socks5_server_response(PerSocketData *per_socket_data, IOContext *io_context, DWORD bytes_transferred);

    // 处理客户端UDP请求
    void handle_client_udp_request(PerSocketData *per_socket_data, IOContext *io_context, DWORD bytes_transferred, 
                                  const char* remote_ip_str, uint16_t remote_port);
                                  
    // 构造SOCKS5 UDP请求头
    size_t construct_socks5_udp_header(char* header, const std::string& target_addr, uint16_t target_port, MappingType mapping_type);
    
    // 发送UDP数据到SOCKS5服务器
    void send_udp_to_socks5_server(PerSocketData *per_socket_data, SOCKET udp_socket, const char* buffer, size_t buffer_len);

    // 处理UDP发送
    void handle_udp_send(IOContext *io_context, DWORD bytes_transferred);

    // 获取连接的目标地址和端口
    bool get_tcp_connection_target(SOCKET socket, std::string &target_addr, uint16_t &target_port, std::string &mapper_key, MappingType &mapping_type);
    bool get_udp_connection_target(const sockaddr_storage &remote_addr, std::string &target_addr, uint16_t &target_port, std::string &mapper_key,
                                   MappingType &mapping_type);

private:
    // SOCKS5客户端
    Socks5Client socks5_client_;

    PacketForwarder *packet_forwarder_;
    hasaki::UdpPacketInjector udp_packet_injector_; // UDP数据包注入器

    // SOCKS5服务器配置
    std::string socks5_address_;
    uint16_t socks5_port_;
    std::string socks5_udp_relay_addr_;
    uint16_t socks5_udp_relay_port_;
    SOCKET socks5_control_socket_;

    // EndpointMapper引用
    EndpointMapper *endpoint_mapper_;

    // 服务器状态
    uint16_t port_;
    std::atomic<bool> is_running_;

    // IOCP相关
    HANDLE iocp_handle_;
    SOCKET listen_socket_;
    SOCKET udp_socket_;
    LPFN_ACCEPTEX lpfn_acceptex_;

    // 工作线程
    std::vector<std::thread> worker_threads_;
};