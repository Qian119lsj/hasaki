#include "hasaki/app_settings.h"

#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QStandardPaths>

AppSettings::AppSettings(QObject* parent) : QObject(parent) {
    m_configFilePath = getConfigFilePath();
    ensureConfigFileExists();
}

AppSettings::~AppSettings() {}

QString AppSettings::getConfigFilePath() const {
    QString dataPath = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (dataPath.isEmpty()) {
        dataPath = QCoreApplication::applicationDirPath();
        qWarning() << "Could not find AppDataLocation, using application directory.";
    }
    QDir dir(dataPath);
    if (!dir.exists()) {
        dir.mkpath(".");
    }
    return dataPath + "/config.json";
}

void AppSettings::ensureConfigFileExists() const {
    if (!QFile::exists(m_configFilePath)) {
        QJsonObject root;
        root["TargetProcesses"] = QJsonArray();
        root["ProxyServerPort"] = 998;
        
        // 初始化SOCKS5服务器列表
        QJsonArray socks5Servers;
        QJsonObject defaultServer;
        defaultServer["name"] = "默认";
        defaultServer["address"] = "127.0.0.1";
        defaultServer["port"] = 1087;
        socks5Servers.append(defaultServer);
        root["Socks5Servers"] = socks5Servers;
        root["CurrentSocks5Server"] = "默认";
        
        // 默认启用IPv6
        root["EnableIpv6"] = true;
        
        writeJsonObject(root);
    }
}

QJsonObject AppSettings::readJsonObject() const {
    QFile file(m_configFilePath);
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "Could not open config file for reading:" << m_configFilePath;
        return QJsonObject();
    }
    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();
    return doc.object();
}

void AppSettings::writeJsonObject(const QJsonObject& json) const {
    QFile file(m_configFilePath);
    if (!file.open(QIODevice::WriteOnly)) {
        qWarning() << "Could not open config file for writing:" << m_configFilePath;
        return;
    }
    file.write(QJsonDocument(json).toJson(QJsonDocument::Indented));
    file.close();
}


QSet<QString> AppSettings::getTargetProcessNames() const {
    QSet<QString> processNames;
    QJsonObject   root  = readJsonObject();
    if (root.contains("TargetProcesses") && root["TargetProcesses"].isArray()) {
        QJsonArray array = root["TargetProcesses"].toArray();
        for (const auto& value : array) {
            processNames.insert(value.toString());
        }
    }
    return processNames;
}

void AppSettings::setTargetProcessNames(const QSet<QString>& processNames) {
    QJsonObject root = readJsonObject();
    QJsonArray  array;
    for (const QString& name : processNames) {
        array.append(name);
    }
    root["TargetProcesses"] = array;
    writeJsonObject(root);
}

bool AppSettings::isBlacklistEnabled() const
{
    return readJsonObject().value("BlacklistEnabled").toBool(false);
}

void AppSettings::setBlacklistEnabled(bool enabled)
{
    QJsonObject root = readJsonObject();
    root["BlacklistEnabled"] = enabled;
    writeJsonObject(root);
}

QSet<QString> AppSettings::getBlacklistProcessNames() const
{
    QSet<QString> processNames;
    QJsonObject   root  = readJsonObject();
    if (root.contains("BlacklistProcessNames") && root["BlacklistProcessNames"].isArray()) {
        QJsonArray array = root["BlacklistProcessNames"].toArray();
        for (const auto& value : array) {
            processNames.insert(value.toString());
        }
    }
    return processNames;
}

void AppSettings::setBlacklistProcessNames(const QSet<QString>& processNames)
{
    QJsonObject root = readJsonObject();
    QJsonArray  array;
    for (const QString& name : processNames) {
        array.append(name);
    }
    root["BlacklistProcessNames"] = array;
    writeJsonObject(root);
}

int AppSettings::getProxyServerPort() const {
    return readJsonObject().value("ProxyServerPort").toInt(998);
}

void AppSettings::setProxyServerPort(int port) {
    QJsonObject root = readJsonObject();
    root["ProxyServerPort"] = port;
    writeJsonObject(root);
}

QList<Socks5Server> AppSettings::getSocks5Servers() const {
    QList<Socks5Server> servers;
    QJsonObject root = readJsonObject();
    
    if (root.contains("Socks5Servers") && root["Socks5Servers"].isArray()) {
        QJsonArray array = root["Socks5Servers"].toArray();
        for (const auto& value : array) {
            if (value.isObject()) {
                QJsonObject serverObj = value.toObject();
                Socks5Server server;
                server.name = serverObj["name"].toString();
                server.address = serverObj["address"].toString();
                server.port = serverObj["port"].toInt();
                servers.append(server);
            }
        }
    }
    
    // 如果没有服务器，添加默认服务器
    if (servers.isEmpty()) {
        Socks5Server defaultServer;
        defaultServer.name = "默认";
        defaultServer.address = "127.0.0.1";
        defaultServer.port = 1087;
        servers.append(defaultServer);
        
        // 保存默认服务器，使用非const对象调用
        const_cast<AppSettings*>(this)->addSocks5Server(defaultServer.name, defaultServer.address, defaultServer.port);
    }
    
    return servers;
}

void AppSettings::addSocks5Server(const QString& name, const QString& address, int port) {
    QJsonObject root = readJsonObject();
    QJsonArray serversArray;
    
    // 读取现有服务器
    if (root.contains("Socks5Servers") && root["Socks5Servers"].isArray()) {
        serversArray = root["Socks5Servers"].toArray();
    }
    
    // 检查是否已存在同名服务器，如果存在则更新
    bool found = false;
    for (int i = 0; i < serversArray.size(); ++i) {
        QJsonObject serverObj = serversArray[i].toObject();
        if (serverObj["name"].toString() == name) {
            serverObj["address"] = address;
            serverObj["port"] = port;
            serversArray[i] = serverObj;
            found = true;
            break;
        }
    }
    
    // 如果不存在，添加新服务器
    if (!found) {
        QJsonObject newServer;
        newServer["name"] = name;
        newServer["address"] = address;
        newServer["port"] = port;
        serversArray.append(newServer);
    }
    
    root["Socks5Servers"] = serversArray;
    writeJsonObject(root);
}

void AppSettings::removeSocks5Server(const QString& name) {
    QJsonObject root = readJsonObject();
    
    if (root.contains("Socks5Servers") && root["Socks5Servers"].isArray()) {
        QJsonArray serversArray = root["Socks5Servers"].toArray();
        QJsonArray newArray;
        
        // 复制除了要删除的服务器外的所有服务器
        for (int i = 0; i < serversArray.size(); ++i) {
            QJsonObject serverObj = serversArray[i].toObject();
            if (serverObj["name"].toString() != name) {
                newArray.append(serverObj);
            }
        }
        
        // 如果删除后没有服务器，添加默认服务器
        if (newArray.isEmpty()) {
            QJsonObject defaultServer;
            defaultServer["name"] = "默认";
            defaultServer["address"] = "127.0.0.1";
            defaultServer["port"] = 1087;
            newArray.append(defaultServer);
        }
        
        // 如果删除的是当前选中的服务器，更新当前服务器
        if (getCurrentSocks5Server() == name) {
            root["CurrentSocks5Server"] = newArray[0].toObject()["name"].toString();
        }
        
        root["Socks5Servers"] = newArray;
        writeJsonObject(root);
    }
}

QString AppSettings::getCurrentSocks5Server() const {
    QJsonObject root = readJsonObject();
    QString currentServer = root.value("CurrentSocks5Server").toString();
    
    // 如果当前服务器为空，返回第一个服务器的名称
    if (currentServer.isEmpty()) {
        QList<Socks5Server> servers = getSocks5Servers();
        if (!servers.isEmpty()) {
            currentServer = servers.first().name;
        }
    }
    
    return currentServer;
}

void AppSettings::setCurrentSocks5Server(const QString& name) {
    QJsonObject root = readJsonObject();
    root["CurrentSocks5Server"] = name;
    writeJsonObject(root);
}

QPair<QString, int> AppSettings::getCurrentSocks5ServerInfo() const {
    QString currentServerName = getCurrentSocks5Server();
    QList<Socks5Server> servers = getSocks5Servers();
    
    for (const auto& server : servers) {
        if (server.name == currentServerName) {
            return qMakePair(server.address, server.port);
        }
    }
    
    // 如果找不到当前服务器，返回默认值
    return qMakePair(QString("127.0.0.1"), 1087);
} 

bool AppSettings::isIpv6Enabled() const {
    return readJsonObject().value("EnableIpv6").toBool(true);
}

void AppSettings::setIpv6Enabled(bool enabled) {
    QJsonObject root = readJsonObject();
    root["EnableIpv6"] = enabled;
    writeJsonObject(root);
} 