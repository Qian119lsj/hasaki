#include "hasaki/tcp_session_manager.h"
#include "hasaki/delayed_delete_manager.h"
#include "hasaki/utils.h"
#include <QDebug>

namespace hasaki {

TcpSessionManager *TcpSessionManager::instance_ = nullptr;
std::mutex TcpSessionManager::instance_mutex_;

TcpSessionManager *TcpSessionManager::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (instance_ == nullptr) {
        instance_ = new TcpSessionManager();
    }
    return instance_;
}

TcpSessionManager::TcpSessionManager() {}

TcpSessionManager::~TcpSessionManager() {}

std::shared_ptr<TcpSession> TcpSessionManager::createSession(SOCKET client_socket, SOCKET target_socket, const std::string &key, MappingType mapping_type) {
    auto session = std::make_shared<TcpSession>(client_socket, target_socket, key, mapping_type);

    std::lock_guard<std::mutex> lock(sessions_mutex_);
    if (sessions_.count(client_socket)) {
        qWarning() << "TCP session for socket" << client_socket << "already exists.";
        return nullptr;
    }
    sessions_[client_socket] = session;
    return session;
}

void TcpSessionManager::closeSession(SOCKET client_socket) {
    
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto it = sessions_.find(client_socket);
    if (it != sessions_.end()) {

        if (it->second->client_socket != INVALID_SOCKET) {
            closesocket(it->second->client_socket);
            it->second->client_socket = INVALID_SOCKET;
        }
        if (it->second->target_socket != INVALID_SOCKET) {
            closesocket(it->second->target_socket);
            it->second->target_socket = INVALID_SOCKET;
        }
        DelayedDeleteManager::getInstance()->addTask(it->second->mapper_key_, it->second->mapping_type_);
        qDebug() << "remove session map key:" << it->second->mapper_key_;
        sessions_.erase(it); // 从map中移除
    }
}

size_t TcpSessionManager::getSessionCount() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(sessions_mutex_));
    return sessions_.size();
}


void TcpSessionManager::clearAllSessions() {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    for (auto &session : sessions_) {
        if (session.second->client_socket != INVALID_SOCKET) {
            closesocket(session.second->client_socket);
        }
        if (session.second->target_socket != INVALID_SOCKET) {
            closesocket(session.second->target_socket);
        }
    }
    sessions_.clear();
}

} // namespace hasaki