#pragma once

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#include "hasaki/endpoint_mapper.h"
#include "hasaki/udp_packet_injector.h"

#include <string>
#include <thread>
#include <vector>
#include <atomic>
#include <memory>
#include <QMap>

namespace hasaki {
struct UdpSession;
struct TcpSession;
class UdpSessionManager;
class TcpSessionManager;
} // namespace hasaki

// IO操作类型
enum IO_OPERATION {
    IO_NONE,   // 无操作
    IO_ACCEPT, // 接受新连接
    IO_RECV_TCP,   // 接收数据
    IO_SEND_TCP,   // 发送数据
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

// 每个IO操作的上下文
struct PerIOContext {
    OVERLAPPED overlapped;                 // 重叠IO结构
    WSABUF wsa_buf;                        // WSA缓冲区
    char buffer[8192];                     // 数据缓冲区
    SOCKET socket;                         // 关联的套接字
    IO_OPERATION operation;                // 操作类型
    SocketType socket_type;                // 套接字类型
    std::weak_ptr<hasaki::TcpSession> tcp_session; // 指向ProxySession的指针
    sockaddr_storage remote_addr;          // 用于UDP的远程地址
    int remote_addr_len;                   // 远程地址长度

    std::shared_ptr<hasaki::UdpSession> udp_session;

    PerIOContext() : socket(INVALID_SOCKET), operation(IO_NONE), socket_type(TYPE_NONE) {
        ZeroMemory(&overlapped, sizeof(OVERLAPPED));
        wsa_buf.buf = buffer;
        wsa_buf.len = sizeof(buffer);
        remote_addr_len = sizeof(remote_addr);
    }

    ~PerIOContext() = default;

    void reset() {
        ZeroMemory(&overlapped, sizeof(OVERLAPPED));
        wsa_buf.buf = buffer;
        wsa_buf.len = sizeof(buffer);
        remote_addr_len = sizeof(remote_addr);
        ZeroMemory(buffer, sizeof(buffer));
    }

    operator LPOVERLAPPED() { return &overlapped; }
};

// 代理服务器类
class ProxyServer {
public:
    ProxyServer(EndpointMapper *endpoint_mapper);
    ~ProxyServer();

    void setSocks5Server(const std::string &address, uint16_t port);
    void setAdapterIpMap(const QMap<QString, int> &adapter_ip_map);
    void setUdpPacketInjector(hasaki::UdpPacketInjector *udp_packet_injector);

    uint16_t getPort() const { return port_; }
    // 启动代理服务器
    bool start(uint16_t port, uint16_t worker_threads = 4);

    // 停止代理服务器
    void stop();

    // 处理UDP数据包
    bool handleUdpPacket(const char *packet_data, uint packet_len, const std::string &src_ip, uint16_t src_port, const std::string &dst_ip, uint16_t dst_port,
                         bool is_ipv6);

private:
    // 工作线程函数
    void worker_thread_func();

    // 发布接受连接请求
    void post_tcp_accept(SOCKET socket, PerIOContext *io_context);

    // 为UDP投递接收请求
    void post_udp_recv(std::shared_ptr<hasaki::UdpSession> udp_session);

    // 处理新接受的连接
    bool handle_tcp_accept(PerIOContext *io_context);

    // 处理TCP接收
    bool handle_tcp_receive(PerIOContext *io_context, DWORD bytes_transferred);

    // 处理TCP发送
    bool handle_tcp_send(PerIOContext *io_context, DWORD bytes_transferred);

    // 处理UDP接收
    void handle_udp_receive(std::shared_ptr<hasaki::UdpSession> udp_session, DWORD bytes_transferred);

    // 构造SOCKS5 UDP请求头
    size_t construct_socks5_udp_header(char *header, const std::string &target_addr, uint16_t target_port, MappingType mapping_type);

    // 处理UDP发送
    void handle_udp_send(PerIOContext *io_context, DWORD bytes_transferred);

    // 获取连接的目标地址和端口
    bool get_tcp_connection_target(SOCKET socket, std::string &target_addr, uint16_t &target_port, std::string &mapper_key, MappingType &mapping_type);

    // 发送数据到SOCKS5服务器
    bool sendToSocks5Server(const std::shared_ptr<hasaki::UdpSession> &session, const char *data, size_t data_len);

private:
    uint16_t port_;
    std::atomic<bool> is_running_;
    QMap<QString, int> adapter_ip_map_;

    std::string socks5_address_;
    uint16_t socks5_port_;

    SOCKET socks5_control_socket_;
    std::string socks5_udp_relay_addr_;
    uint16_t socks5_udp_relay_port_;

    EndpointMapper *endpoint_mapper_;
    hasaki::UdpPacketInjector *udp_packet_injector_;
    hasaki::UdpSessionManager *udp_session_manager_;
    hasaki::TcpSessionManager *tcp_session_manager_;

    SOCKET tcp_listen_socket_;
    HANDLE iocp_handle_;
    LPFN_ACCEPTEX lpfn_acceptex_;
    std::vector<std::thread> worker_threads_;
};