#include "hasaki/proxy_server.h"
#include "hasaki/delayed_delete_manager.h"

#include <QDebug>
#include <QApplication>
#include <QMetaObject>
#include <QThread>

ProxySession::ProxySession(SOCKET client_socket, SOCKET target_socket, const std::string &mapper_key, MappingType mapping_type)
    : mapper_key_(mapper_key), mapping_type_(mapping_type), client_socket(client_socket), target_socket(target_socket) {}

ProxySession::~ProxySession() { close(); }

void ProxySession::createDelayedRemover(const std::string& key, MappingType type) {
    // 使用延迟删除管理器添加任务
    DelayedDeleteManager::getInstance()->addTask(key, type);
}

void ProxySession::close() {
    // 延迟删除映射
    if (!mapper_key_.empty()) {
        qDebug() << "延迟删除映射:" << QString::fromStdString(mapper_key_);
        
        // 添加延迟删除任务
        createDelayedRemover(mapper_key_, mapping_type_);
        mapper_key_.clear();
    }

    client_per_socket_data->TryToCloseSocketData(client_per_socket_data);
    target_per_socket_data->TryToCloseSocketData(target_per_socket_data);
}