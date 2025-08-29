#include "hasaki/single_instance_manager.h"

#include <QCoreApplication>
#include <QDir>
#include <QStandardPaths>
#include <QDebug>
#include <QDataStream>
#include <QFile>
#include <QFileInfo>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

SingleInstanceManager::SingleInstanceManager(const QString &appName, QObject *parent)
    : QObject(parent), localServer_(nullptr) {
    serverName_ = QString("hasaki_%1").arg(appName);
    
    // 使用临时目录作为锁文件位置
    QString tempDir = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
    lockFilePath_ = QDir(tempDir).filePath(serverName_ + ".lock");
}

SingleInstanceManager::~SingleInstanceManager() {
    if (localServer_) {
        localServer_->close();
        localServer_->deleteLater();
    }
    
    // 清理锁文件
    QFile::remove(lockFilePath_);
}

bool SingleInstanceManager::isAnotherInstanceRunning() {
    // 首先尝试连接到已存在的实例
    QLocalSocket socket;
    socket.connectToServer(serverName_);
    
    if (socket.waitForConnected(1000)) {
        // 连接成功，说明已有实例在运行
        socket.disconnectFromServer();
        return true;
    }
    
    // 检查锁文件是否存在
    QFileInfo lockFileInfo(lockFilePath_);
    if (lockFileInfo.exists()) {
        // 锁文件存在，但无法连接到服务器，可能是僵尸进程
        // 尝试清理
        cleanupStaleServer();
    }
    
    return false;
}

bool SingleInstanceManager::startServer() {
    if (localServer_) {
        return true;
    }
    
    // 清理可能存在的僵尸服务器
    cleanupStaleServer();
    
    localServer_ = new QLocalServer(this);
    
    // 监听新连接
    connect(localServer_, &QLocalServer::newConnection, 
            this, &SingleInstanceManager::onNewConnection);
    
    if (!localServer_->listen(serverName_)) {
        qDebug() << "无法启动本地服务器:" << localServer_->errorString();
        return false;
    }
    
    // 创建锁文件
    QFile lockFile(lockFilePath_);
    if (lockFile.open(QIODevice::WriteOnly)) {
        QDataStream out(&lockFile);
        out << QCoreApplication::applicationPid();
        lockFile.close();
    }
    
    qDebug() << "单实例服务器启动成功，监听:" << serverName_;
    return true;
}

void SingleInstanceManager::activateExistingInstance() {
    QLocalSocket socket;
    socket.connectToServer(serverName_);
    
    if (socket.waitForConnected(1000)) {
        // 发送激活消息
        QByteArray data = "ACTIVATE";
        socket.write(data);
        socket.waitForBytesWritten(1000);
        socket.disconnectFromServer();
        qDebug() << "向已存在的实例发送激活消息";
    } else {
        qDebug() << "无法连接到已存在的实例:" << socket.errorString();
    }
}

void SingleInstanceManager::onNewConnection() {
    QLocalSocket *clientSocket = localServer_->nextPendingConnection();
    if (!clientSocket) {
        return;
    }
    
    connect(clientSocket, &QLocalSocket::disconnected,
            this, &SingleInstanceManager::onClientDisconnected);
    
    connect(clientSocket, &QLocalSocket::readyRead, [this, clientSocket]() {
        QByteArray data = clientSocket->readAll();
        QString message = QString::fromUtf8(data);
        
        if (message == "ACTIVATE") {
            qDebug() << "收到激活请求";
            emit activationRequested();
        }
        
        clientSocket->disconnectFromServer();
    });
}

void SingleInstanceManager::onClientDisconnected() {
    QLocalSocket *socket = qobject_cast<QLocalSocket*>(sender());
    if (socket) {
        socket->deleteLater();
    }
}

void SingleInstanceManager::cleanupStaleServer() {
    // 移除可能存在的服务器实例
    QLocalServer::removeServer(serverName_);
    
    // 检查锁文件
    QFileInfo lockFileInfo(lockFilePath_);
    if (lockFileInfo.exists()) {
        QFile lockFile(lockFilePath_);
        if (lockFile.open(QIODevice::ReadOnly)) {
            QDataStream in(&lockFile);
            qint64 pid;
            in >> pid;
            lockFile.close();
            
#ifdef Q_OS_WIN
            // 在Windows上检查进程是否还存在
            HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, static_cast<DWORD>(pid));
            if (process == NULL) {
                // 进程不存在，删除锁文件
                QFile::remove(lockFilePath_);
                qDebug() << "清理僵尸锁文件:" << lockFilePath_;
            } else {
                CloseHandle(process);
            }
#else
            // 其他平台的实现可以在这里添加
            QFile::remove(lockFilePath_);
#endif
        } else {
            // 无法读取锁文件，直接删除
            QFile::remove(lockFilePath_);
        }
    }
}
