#pragma once

#include <QObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QString>

class SingleInstanceManager : public QObject {
    Q_OBJECT

public:
    explicit SingleInstanceManager(const QString &appName, QObject *parent = nullptr);
    ~SingleInstanceManager();

    // 检查是否已有实例在运行
    bool isAnotherInstanceRunning();

    // 启动本地服务器监听新实例
    bool startServer();

    // 向已存在的实例发送显示窗口消息
    void activateExistingInstance();

signals:
    // 当收到激活请求时发出信号
    void activationRequested();

private slots:
    void onNewConnection();
    void onClientDisconnected();

private:
    QString serverName_;
    QLocalServer *localServer_;
    QString lockFilePath_;

    // 清理可能存在的僵尸服务器
    void cleanupStaleServer();
};
