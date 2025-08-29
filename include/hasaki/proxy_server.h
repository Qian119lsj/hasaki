#pragma once

#include "upstream_client.h"
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
#include <QObject>
#include <QTimer>

namespace hasaki {

struct UdpSession;
struct TcpSession;
class UdpSessionManager;
class TcpSessionManager;

// IO操作类型
enum IO_OPERATION {
    IO_NONE,     // 无操作
    IO_ACCEPT,   // 接受新连接
    IO_RECV_TCP, // 接收数据
    IO_SEND_TCP, // 发送数据
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
    OVERLAPPED overlapped;        // 重叠IO结构
    WSABUF wsa_buf;               // WSA缓冲区
    char buffer[8192];            // 数据缓冲区
    SOCKET socket;                // 关联的套接字
    IO_OPERATION operation;       // 操作类型
    SocketType socket_type;       // 套接字类型
    sockaddr_storage remote_addr; // 用于UDP的远程地址
    int remote_addr_len;          // 远程地址长度

    std::shared_ptr<hasaki::TcpSession> tcp_session;
    std::shared_ptr<hasaki::UdpSession> udp_session;

    PerIOContext() : socket(INVALID_SOCKET), operation(IO_NONE), socket_type(TYPE_NONE) { reset(); }

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


// 流量统计结构
struct TrafficStats {
    uint64_t total_bytes_sent = 0;     // 总发送字节数
    uint64_t total_bytes_received = 0; // 总接收字节数
    uint64_t tcp_bytes_sent = 0;       // TCP发送字节数
    uint64_t tcp_bytes_received = 0;   // TCP接收字节数
    uint64_t udp_bytes_sent = 0;       // UDP发送字节数
    uint64_t udp_bytes_received = 0;   // UDP接收字节数
};

// 每秒流量统计
struct SpeedStats {
    uint64_t bytes_per_second_sent = 0;     // 每秒发送字节数
    uint64_t bytes_per_second_received = 0; // 每秒接收字节数
    uint64_t tcp_speed_sent = 0;            // TCP每秒发送
    uint64_t tcp_speed_received = 0;        // TCP每秒接收
    uint64_t udp_speed_sent = 0;            // UDP每秒发送
    uint64_t udp_speed_received = 0;        // UDP每秒接收
};


// 代理服务器类
class ProxyServer : public QObject {
    Q_OBJECT

public:
    ProxyServer(EndpointMapper *endpoint_mapper, QObject *parent = nullptr);
    ~ProxyServer();

    void setUpstreamClient(hasaki::upstream_client *upstream_client);
    void setAdapterIpMap(const QMap<QString, int> &adapter_ip_map);
    void setUdpPacketInjector(hasaki::UdpPacketInjector *udp_packet_injector);

    uint16_t getPort() const { return port_; }
    
    // 启动代理服务器
    bool start(uint16_t port, uint16_t worker_threads = 4);

    // 停止代理服务器
    void stop();

    // 处理UDP数据包
    bool handleUdpPacket(const char *packet_data, uint packet_len, const std::string &src_ip, uint16_t src_port, const std::string &dst_ip, uint16_t dst_port,
                         bool is_ipv6, std::string& process_name);

    // 获取统计数据的接口
    TrafficStats getTrafficStats() const;
    SpeedStats getCurrentSpeed() const;
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
    void handle_udp_receive(PerIOContext *io_context, DWORD bytes_transferred);

    // 构造SOCKS5 UDP请求头
    size_t construct_socks5_udp_header(char *header, const std::string &target_addr, uint16_t target_port, MappingType mapping_type);

    // 处理UDP发送
    void handle_udp_send(PerIOContext *io_context, DWORD bytes_transferred);

    // 获取连接的目标地址和端口
    bool get_tcp_connection_target(SOCKET socket, std::string &target_addr, uint16_t &target_port, std::string &mapper_key, MappingType &mapping_type);

    bool handleDnsPacket(const char *packet_data, uint packet_len, const std::string &dst_ip, uint16_t dst_port, bool is_ipv6);
private:
    uint16_t port_;
    std::atomic<bool> is_running_;
    std::vector<std::thread> worker_threads_;
    QMap<QString, int> adapter_ip_map_;

    hasaki::upstream_client *upstream_client_ = nullptr;

    EndpointMapper *endpoint_mapper_ = nullptr;
    hasaki::UdpPacketInjector *udp_packet_injector_ = nullptr;
    hasaki::UdpSessionManager *udp_session_manager_ = nullptr;
    hasaki::TcpSessionManager *tcp_session_manager_ = nullptr;

    SOCKET tcp_listen_socket_ = INVALID_SOCKET;
    HANDLE iocp_handle_ = nullptr;
    LPFN_ACCEPTEX lpfn_acceptex_ = nullptr;

    SpeedStats current_speed_;

    // 内部原子统计结构
    struct AtomicTrafficStats {
        std::atomic<uint64_t> total_bytes_sent{0};
        std::atomic<uint64_t> total_bytes_received{0};
        std::atomic<uint64_t> tcp_bytes_sent{0};
        std::atomic<uint64_t> tcp_bytes_received{0};
        std::atomic<uint64_t> udp_bytes_sent{0};
        std::atomic<uint64_t> udp_bytes_received{0};
    } atomic_traffic_stats_;

     // 上一秒的流量值，用于计算速度
    uint64_t last_total_sent_ = 0;
    uint64_t last_total_received_ = 0;
    uint64_t last_tcp_sent_ = 0;
    uint64_t last_tcp_received_ = 0;
    uint64_t last_udp_sent_ = 0;
    uint64_t last_udp_received_ = 0;
    
    // 统计更新定时器
    QTimer* stats_timer_;
    
    // 统计方法
    void updateTrafficStats(uint64_t bytes, bool is_sent, bool is_tcp);
    void calculateSpeed();
    void resetTrafficStats(); // 重置流量统计
};

} // namespace hasaki