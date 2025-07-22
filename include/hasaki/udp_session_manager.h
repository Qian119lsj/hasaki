#pragma once

#include <string>
#include <map>
#include <mutex>
#include <memory>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <atomic>
#include "hasaki/proxy_server.h"

namespace hasaki {

// UDP会话结构体
struct UdpSession {
    SOCKET local_socket;         // 本地UDP套接字
    std::string client_ip;       // 客户端IP
    uint16_t client_port;        // 客户端端口
    std::string dest_ip;         // 目标IP
    uint16_t dest_port;          // 目标端口
    bool is_ipv6;                // 是否为IPv6
    std::chrono::steady_clock::time_point last_activity_time; // 记录上次活动时间
    
    // UdpSession也拥有其I/O操作的上下文
    std::unique_ptr<PerIOContext> io_context; 

    UdpSession() : local_socket(INVALID_SOCKET), client_port(0), dest_port(0), is_ipv6(false) {
        last_activity_time = std::chrono::steady_clock::now();
        io_context = std::make_unique<PerIOContext>();
    }
    ~UdpSession() {
        if (local_socket != INVALID_SOCKET) {
            closesocket(local_socket);
            local_socket = INVALID_SOCKET;
        }
    }
    void update_activity_time() {
        last_activity_time = std::chrono::steady_clock::now();
    }
};

// UDP会话管理器类 (单例模式)
class UdpSessionManager {
public:
    // 获取单例实例
    static UdpSessionManager* getInstance();
    
    // 禁止复制和移动
    UdpSessionManager(const UdpSessionManager&) = delete;
    UdpSessionManager& operator=(const UdpSessionManager&) = delete;
    UdpSessionManager(UdpSessionManager&&) = delete;
    UdpSessionManager& operator=(UdpSessionManager&&) = delete;
    
    ~UdpSessionManager();

    void start();
    // 关闭会话管理器
    void shutdown();
    // 获取或创建UDP会话
    std::shared_ptr<UdpSession> getOrCreateSession(const std::string &client_ip, uint16_t client_port, const std::string &dest_ip, uint16_t dest_port,
                                                   bool is_ipv6, bool *is_new_session);
    
    // 获取所有会话的副本，用于UI显示
    std::map<std::string, std::shared_ptr<UdpSession>> getSessions() {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        return sessions_;
    }

private:
    // 私有构造函数，防止外部创建实例
    UdpSessionManager();
    
    // 创建会话键
    std::string createSessionKey(const std::string &client_ip, uint16_t client_port);

    void cleanup_task();
    
private:
    // 会话映射表 (client_ip:client_port -> UdpSession)
    std::map<std::string, std::shared_ptr<UdpSession>> sessions_;
    std::mutex sessions_mutex_;

    // 单例实例
    static UdpSessionManager* instance_;
    static std::mutex instance_mutex_;

    std::thread cleanup_thread_;
    std::atomic<bool> running_;
};

} // namespace hasaki