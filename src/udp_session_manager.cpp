#include "hasaki/udp_session_manager.h"
#include "hasaki/portprocessmonitor.h"
#include <QDebug>
#include <sstream>

namespace hasaki {

// 初始化静态成员
UdpSessionManager* UdpSessionManager::instance_ = nullptr;
std::mutex UdpSessionManager::instance_mutex_;

UdpSessionManager* UdpSessionManager::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (instance_ == nullptr) {
        instance_ = new UdpSessionManager();
    }
    return instance_;
}

UdpSessionManager::UdpSessionManager() {
    running_ = false;
}

UdpSessionManager::~UdpSessionManager() { shutdown(); }

void UdpSessionManager::setPortProcessMonitor(PortProcessMonitor *monitor) { portProcessMonitor_ = monitor; }

void UdpSessionManager::start() {
    if (running_) {
        return;
    }
    cleanup_thread_ = std::thread(&UdpSessionManager::cleanup_task, this);
    running_ = true;
    qDebug() << "UDP会话管理器已启动";
}

void UdpSessionManager::shutdown() {
    running_ = false;
    if (cleanup_thread_.joinable()) {
        cleanup_thread_.join();
    }
    // 关闭所有会话
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    for (auto &pair : sessions_) {
        auto &session = pair.second;
        if (session->local_socket != INVALID_SOCKET) {
            closesocket(session->local_socket);
            session->local_socket = INVALID_SOCKET;
        }
    }

    sessions_.clear();
}

std::string UdpSessionManager::createSessionKey(const std::string &client_ip, uint16_t client_port) {
    std::stringstream ss;
    ss << client_ip << ":" << client_port;
    return ss.str();
}

std::shared_ptr<UdpSession> UdpSessionManager::getOrCreateSession(const std::string &client_ip, uint16_t client_port, const std::string &dest_ip,
                                                                  uint16_t dest_port, bool is_ipv6, bool *is_new_session) {

    // 创建会话键
    std::string session_key = createSessionKey(client_ip, client_port);

    // 查找现有会话
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = sessions_.find(session_key);
        if (it != sessions_.end()) {
            it->second->update_activity_time();
            *is_new_session = false;
            return it->second;
        }
    }

    // 创建新会话
    auto session = std::make_shared<UdpSession>();
    session->client_ip = client_ip;
    session->client_port = client_port;
    session->is_ipv6 = is_ipv6;

    // 创建本地UDP套接字
    SOCKET sock = socket(is_ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        qDebug() << "创建UDP套接字失败: " << WSAGetLastError();
        return nullptr;
    }

    // 绑定到任意地址和端口
    if (!is_ipv6) {
        sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = 0; // 让系统分配端口

        if (bind(sock, (sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
            qDebug() << "绑定UDP套接字失败: " << WSAGetLastError();
            closesocket(sock);
            return nullptr;
        }
    } else {
        sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_any;
        addr.sin6_port = 0; // 让系统分配端口

        if (bind(sock, (sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
            qDebug() << "绑定UDP套接字失败: " << WSAGetLastError();
            closesocket(sock);
            return nullptr;
        }
    }

    session->local_socket = sock;

    // 添加到会话映射表
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        sessions_[session_key] = session;
    }

    // qDebug() << "创建UDP会话: " << session_key << " remote_ip: " << dest_ip << " remote_port: " << dest_port << " is_ipv6: " << is_ipv6;
    *is_new_session = true;
    return session;
}

void UdpSessionManager::cleanup_task() {
    using namespace std::chrono_literals;
    while (running_) {
        std::this_thread::sleep_for(2s);

        std::vector<std::string> keys_to_remove;
        std::vector<std::shared_ptr<UdpSession>> sockets_to_close;

        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            auto now = std::chrono::steady_clock::now();
            for (auto const &[key, session] : sessions_) {
                if (now - session->last_activity_time > 300s) {
                    // 检查端口是否在portProcessMonitor_的映射中
                    bool should_remove = true;
                    if (portProcessMonitor_) {
                        // 只有当端口不在portProcessMonitor_的映射中时才加入清理列表
                        if (portProcessMonitor_->isPortInTargetProcess(session->client_port)) {
                            should_remove = false;
                        }
                    }
                    
                    if (should_remove) {
                        keys_to_remove.push_back(key);
                        sockets_to_close.push_back(session);
                    }
                }
            }
        }

        for (auto &session : sockets_to_close) {
            if (session->local_socket != INVALID_SOCKET) {
                closesocket(session->local_socket);
                session->local_socket = INVALID_SOCKET;
            }
        }

        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            for (auto &key : keys_to_remove) {
                sessions_.erase(key);
            }
        }
        // qDebug() << "清理UDP会话: " << keys_to_remove.size() << "个会话, 当前会话数: " << sessions_.size();
    }
}

} // namespace hasaki