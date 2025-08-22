#include "hasaki/udp_session_manager.h"
#include "hasaki/port_process_monitor.h"
#include <QDebug>
#include <sstream>

namespace hasaki {

// 初始化静态成员
UdpSessionManager *UdpSessionManager::instance_ = nullptr;
std::mutex UdpSessionManager::instance_mutex_;

UdpSessionManager *UdpSessionManager::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (instance_ == nullptr) {
        instance_ = new UdpSessionManager();
    }
    return instance_;
}

UdpSessionManager::UdpSessionManager() { running_ = false; }

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

std::shared_ptr<UdpSession> UdpSessionManager::getOrCreateSession(const std::string &session_key, const std::string &client_ip, uint16_t client_port,
                                                                  const std::string &dest_ip, uint16_t dest_port, bool is_ipv6, bool *is_new_session) {

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
    session->mapper_key_ = session_key;
    session->is_ipv6 = is_ipv6;

    // qDebug() << "创建UDP会话: " << session_key << " remote_ip: " << dest_ip << " remote_port: " << dest_port << " is_ipv6: " << is_ipv6;
    *is_new_session = true;
    return session;
}

void UdpSessionManager::cleanup_task() {
    using namespace std::chrono_literals;
    while (running_) {
        std::this_thread::sleep_for(5s);
        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            std::vector<std::string> keys_to_remove;
            auto now = std::chrono::steady_clock::now();
            for (auto const &[key, session] : sessions_) {
                if (now - session->last_activity_time > 300s) {
                    // 检查端口是否在portProcessMonitor_的映射中
                    if (portProcessMonitor_) {
                        // 只有当端口不在portProcessMonitor_的映射中时才加入清理列表
                        if (!portProcessMonitor_->isPortInTargetProcess(session->client_port)) {
                            keys_to_remove.push_back(key);
                        }
                    }
                }
            }
            for (auto &key : keys_to_remove) {
                sessions_[key]->closeLocalSocket();
                sessions_.erase(key);
            }
        }
    }
}

} // namespace hasaki