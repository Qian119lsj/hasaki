#pragma once

#include <string>
#include <map>
#include <mutex>
#include <memory>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <atomic>
#include "hasaki/proxy_server.h"

class PortProcessMonitor;

namespace hasaki {

// UDP会话结构体
struct UdpSession {
    std::string process_name;
    SOCKET local_socket = INVALID_SOCKET;         // 本地UDP套接字
    std::mutex mutex;
    std::string client_ip;       // 客户端IP
    uint16_t client_port;        // 客户端端口
    std::string mapper_key_;
    bool is_ipv6;                // 是否为IPv6
    std::chrono::steady_clock::time_point last_activity_time = std::chrono::steady_clock::now(); // 记录上次活动时间
    UdpSession() : client_port(0), is_ipv6(false) {}
    ~UdpSession() {
        closeLocalSocket();
    }
    void closeLocalSocket() {
        std::lock_guard<std::mutex> lock(mutex);
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

    void setPortProcessMonitor(PortProcessMonitor *monitor);

    void start();
    // 关闭会话管理器
    void shutdown();
    // 获取或创建UDP会话
    std::shared_ptr<UdpSession> getOrCreateSession(const std::string &session_key, const std::string &client_ip, uint16_t client_port, const std::string &dest_ip, uint16_t dest_port,
                                                   bool is_ipv6,std::string process_name, bool *is_new_session);
    
    // 获取所有会话的副本，用于UI显示
    std::map<std::string, std::shared_ptr<UdpSession>> getSessions() {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        return sessions_;
    }

    void addSession(const std::string &session_key, std::shared_ptr<UdpSession> session) {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        sessions_[session_key] = session;
    }
    void removeSession(const std::string &session_key) {
        std::shared_ptr<UdpSession> session_ptr;

        {
            // 1️⃣ 只锁一次容器，取出会话的 shared_ptr
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            auto it = sessions_.find(session_key);
            if (it == sessions_.end())
                return;                 // 没有对应会话，直接返回
            session_ptr = it->second;   // 拿到会话对象的引用计数
            sessions_.erase(it);        // 从容器中移除（此时容器不再持有对象）
        }   // 2️⃣ 这里解锁 sessions_mutex_

            // 3️⃣ 依然持有 session_ptr（引用计数至少为 1），可以安全调用成员函数
        if (session_ptr)
            session_ptr->closeLocalSocket();   // 内部会自行加锁
        // 离开作用域，session_ptr 被销毁，若没有其他持有者，UdpSession 会被析构
    }


    // 创建会话键
    static std::string createSessionKey(const std::string &client_ip, uint16_t client_port);

private:
    // 私有构造函数，防止外部创建实例
    UdpSessionManager();
    
    void cleanup_task();
    
private:
    // 会话映射表 ("client_ip:client_port" -> UdpSession)
    std::map<std::string, std::shared_ptr<UdpSession>> sessions_;
    std::mutex sessions_mutex_;

    // 单例实例
    static UdpSessionManager* instance_;
    static std::mutex instance_mutex_;

    std::thread cleanup_thread_;
    std::atomic<bool> running_;

    // 端口进程监视器
    PortProcessMonitor* portProcessMonitor_ = nullptr;
};

} // namespace hasaki