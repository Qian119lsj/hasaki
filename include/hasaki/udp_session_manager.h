#pragma once

#include <string>
#include <map>
#include <mutex>
#include <memory>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <atomic>
#include <thread>
#include "hasaki/udp_packet_injector.h"

namespace hasaki {

// UDP会话结构体
struct UdpSession {
    SOCKET local_socket;                // 本地UDP套接字
    std::string client_ip;              // 客户端IP
    uint16_t client_port;               // 客户端端口
    std::string dest_ip;                // 目标IP
    uint16_t dest_port;                 // 目标端口
    bool is_ipv6;                       // 是否为IPv6
    std::atomic<bool> is_active;        // 会话是否活跃
    std::thread recv_thread;            // 接收线程
    int interface_index;                // 网络接口索引

    UdpSession() : local_socket(INVALID_SOCKET), client_port(0), dest_port(0), 
                  is_ipv6(false), is_active(false), interface_index(0) {}
};

// UDP会话管理器类
class UdpSessionManager {
public:
    UdpSessionManager();
    ~UdpSessionManager();

    // 初始化会话管理器
    bool initialize();
    
    // 关闭会话管理器
    void shutdown();
    
    // 设置SOCKS5 UDP中继地址和端口
    void setSocks5UdpRelay(const std::string &addr, uint16_t port);
    
    // 处理UDP数据包
    bool handleUdpPacket(const char* packet_data, size_t packet_len, 
                         const std::string& src_ip, uint16_t src_port,
                         const std::string& dst_ip, uint16_t dst_port,
                         bool is_ipv6, int interface_index);
                         
    // 设置网络接口映射表
    using InterfaceMap = std::map<std::string, int>;
    void setInterfaceMap(const InterfaceMap& interface_map);

private:
    // 获取或创建UDP会话
    std::shared_ptr<UdpSession> getOrCreateSession(const std::string& client_ip, uint16_t client_port, 
                                                  const std::string& dest_ip, uint16_t dest_port,
                                                  bool is_ipv6, int interface_index);
                                                  
    // 会话接收线程函数
    void sessionRecvThread(std::shared_ptr<UdpSession> session);
    
    // 构造SOCKS5 UDP请求头
    size_t constructSocks5UdpHeader(char* header, const std::string& target_addr, 
                                   uint16_t target_port, bool is_ipv6);
                                   
    // 发送数据到SOCKS5服务器
    bool sendToSocks5Server(const std::shared_ptr<UdpSession>& session, 
                           const char* data, size_t data_len);
                           
    // 处理来自SOCKS5服务器的响应
    void handleSocks5Response(std::shared_ptr<UdpSession> session, 
                             const char* data, size_t data_len);
    
    // 创建会话键
    std::string createSessionKey(const std::string& client_ip, uint16_t client_port);

private:
    // 会话映射表 (client_ip:client_port -> UdpSession)
    std::map<std::string, std::shared_ptr<UdpSession>> sessions_;
    std::mutex sessions_mutex_;
    
    // SOCKS5 UDP中继地址和端口
    std::string socks5_udp_relay_addr_;
    uint16_t socks5_udp_relay_port_;
    
    // 网络接口映射表
    InterfaceMap interface_map_;
    
    // UDP包注入器
    UdpPacketInjector packet_injector_;
    
    // 运行状态
    std::atomic<bool> is_running_;
};

} // namespace hasaki 