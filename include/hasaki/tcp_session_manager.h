#pragma once

#include "utils.h"

#include <WinSock2.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <map>
#include <mutex>
#include <memory>

namespace hasaki {

struct TcpSession {
    std::string mapper_key_;
    MappingType mapping_type_;
    SOCKET client_socket; // 客户端套接字
    SOCKET target_socket; // 目标服务器套接字
    TcpSession(SOCKET client_socket, SOCKET target_socket, const std::string &key, MappingType mapping_type)
        : client_socket(client_socket), target_socket(target_socket), mapper_key_(key), mapping_type_(mapping_type) {}
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
    std::shared_ptr<TcpSession> createSession(SOCKET client_socket, SOCKET target_socket, const std::string &key, MappingType mapping_type);
    void closeSession(SOCKET client_socket);
    void clearAllSessions();
private:
    TcpSessionManager();
    void createDelayedRemover(const std::string &key, MappingType type);

private:
    std::mutex sessions_mutex_;
    std::map<SOCKET, std::shared_ptr<TcpSession>> sessions_;

    // 单例实例
    static TcpSessionManager *instance_;
    static std::mutex instance_mutex_;
};
} // namespace hasaki