#include "hasaki/tcp_session_manager.h"
#include "hasaki/delayed_delete_manager.h"
#include "hasaki/utils.h"
#include <QDebug>
#include <algorithm>

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

std::shared_ptr<TcpSession> TcpSessionManager::createSession(SOCKET client_socket, SOCKET target_socket, const std::string &mapper_key_, MappingType mapping_type) {
    auto session = std::make_shared<TcpSession>(client_socket, target_socket, mapper_key_, mapping_type);

    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    sessions_.push_back(session);
    return session;
}

void TcpSessionManager::removeSession(const std::string& mapper_key) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto it = std::find_if(sessions_.begin(), sessions_.end(), [&mapper_key](const std::shared_ptr<TcpSession>& session) {
        return session->mapper_key_ == mapper_key;
    });

    if (it != sessions_.end()) {
        auto& session = *it;
        DelayedDeleteManager::getInstance()->addTask(session->mapper_key_, session->mapping_type_);
        session->closeClientSocket();
        session->closeTargetSocket();
        sessions_.erase(it);
    }
}

size_t TcpSessionManager::getSessionCount() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(sessions_mutex_));
    return sessions_.size();
}


void TcpSessionManager::clearAllSessions() {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    for(auto& session : sessions_) {
        session->closeClientSocket();
        session->closeTargetSocket();
    }
    sessions_.clear();
}

} // namespace hasaki