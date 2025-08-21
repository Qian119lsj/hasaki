#pragma once

#include "utils.h"

#include <WinSock2.h>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <mutex>
#include <memory>

namespace hasaki {

struct TcpSession {
    std::string mapper_key_;
    MappingType mapping_type_;
    SOCKET client_socket; // 客户端套接字
    SOCKET target_socket; // 目标服务器套接字
    std::mutex client_socket_mutex_;
    std::mutex target_socket_mutex_;
    TcpSession(SOCKET client_socket, SOCKET target_socket, const std::string &key, MappingType mapping_type)
        : client_socket(client_socket), target_socket(target_socket), mapper_key_(key), mapping_type_(mapping_type) {}

    void closeClientSocket() {
        std::lock_guard<std::mutex> lock(client_socket_mutex_);
        if (client_socket != INVALID_SOCKET) {
            closesocket(client_socket);
            client_socket = INVALID_SOCKET;
        }
    }
    void closeTargetSocket() {
        std::lock_guard<std::mutex> lock(target_socket_mutex_);
        if (target_socket != INVALID_SOCKET) {
            closesocket(target_socket);
            target_socket = INVALID_SOCKET;
        }
    }
};


class TcpSessionManager {
public:
    // 禁止复制和移动
    TcpSessionManager(const TcpSessionManager &) = delete;
    TcpSessionManager &operator=(const TcpSessionManager &) = delete;
    TcpSessionManager(TcpSessionManager &&) = delete;
    TcpSessionManager &operator=(TcpSessionManager &&) = delete;

    ~TcpSessionManager();

    // 获取单例实例
    static TcpSessionManager *getInstance();
    std::shared_ptr<TcpSession> createSession(SOCKET client_socket, SOCKET target_socket, const std::string &mapper_key_, MappingType mapping_type);
    void removeSession(const std::string& mapper_key);
    void clearAllSessions();

    // 获取当前TCP会话数
    size_t getSessionCount() const;

private:
    TcpSessionManager();

private:
    std::mutex sessions_mutex_;
    std::vector<std::shared_ptr<TcpSession>> sessions_;
    // 单例实例
    static TcpSessionManager *instance_;
    static std::mutex instance_mutex_;
};
} // namespace hasaki