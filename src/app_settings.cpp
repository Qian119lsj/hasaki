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

QList<hasaki::upstream_data> AppSettings::getUpstreams() const {
    QList<hasaki::upstream_data> upstreams;
    QJsonObject root = readJsonObject();
    
    if (root.contains("upstreams") && root["upstreams"].isArray()) {
        QJsonArray array = root["upstreams"].toArray();
        for (const auto& value : array) {
            if (value.isObject()) {
                QJsonObject serverObj = value.toObject();
                hasaki::upstream_data upstream;
                upstream.name = serverObj["name"].toString();
                upstream.type = static_cast<hasaki::upstream_type>(serverObj["type"].toInt());
                upstream.address = serverObj["address"].toString();
                upstream.port = serverObj["port"].toInt();
                upstream.local_address = serverObj["local_address"].toString();
                upstream.local_port = serverObj["local_port"].toInt();
                upstream.username = serverObj["username"].toString();
                upstream.password = serverObj["password"].toString();
                upstream.encryption_method = serverObj["encryption_method"].toString();
                upstreams.append(upstream);
            }
        }
    }
    return upstreams;
}

void AppSettings::addOrUpdateUpstream(const hasaki::upstream_data& upstream) {
    QJsonObject root = readJsonObject();
    QJsonArray serversArray;
    
    // 读取现有服务器
    if (root.contains("upstreams") && root["upstreams"].isArray()) {
        serversArray = root["upstreams"].toArray();
    }
    
    // 检查是否已存在同名服务器，如果存在则更新
    bool found = false;
    for (int i = 0; i < serversArray.size(); ++i) {
        QJsonObject serverObj = serversArray[i].toObject();
        if (serverObj["name"].toString() == upstream.name) {
            serverObj["type"] = static_cast<int>(upstream.type);
            serverObj["address"] = upstream.address;
            serverObj["port"] = upstream.port;
            serverObj["local_address"] = upstream.local_address;
            serverObj["local_port"] = upstream.local_port;
            serverObj["username"] = upstream.username;
            serverObj["password"] = upstream.password;
            serverObj["encryption_method"] = upstream.encryption_method;
            serversArray[i] = serverObj;
            found = true;
            break;
        }
    }
    
    // 如果不存在，添加新服务器
    if (!found) {
        QJsonObject newServer;
        newServer["name"] = upstream.name;
        newServer["type"] = static_cast<int>(upstream.type);
        newServer["address"] = upstream.address;
        newServer["port"] = upstream.port;
        newServer["local_address"] = upstream.local_address;
        newServer["local_port"] = upstream.local_port;
        newServer["username"] = upstream.username;
        newServer["password"] = upstream.password;
        newServer["encryption_method"] = upstream.encryption_method;
        serversArray.append(newServer);
    }
    
    root["upstreams"] = serversArray;
    writeJsonObject(root);
}

void AppSettings::removeUpstream(const QString& name) {
    QJsonObject root = readJsonObject();
    
    if (root.contains("upstreams") && root["upstreams"].isArray()) {
        QJsonArray serversArray = root["upstreams"].toArray();
        QJsonArray newArray;
        
        // 复制除了要删除的服务器外的所有服务器
        for (int i = 0; i < serversArray.size(); ++i) {
            QJsonObject serverObj = serversArray[i].toObject();
            if (serverObj["name"].toString() != name) {
                newArray.append(serverObj);
            }
        }
        
        // 如果删除的是当前选中的服务器，更新当前服务器
        if (getCurrentUpstreamName() == name) {
            root["currentUpstream"] = newArray[0].toObject()["name"].toString();
        }
        
        root["upstreams"] = newArray;
        writeJsonObject(root);
    }
}

QString AppSettings::getCurrentUpstreamName() const {
    QJsonObject root = readJsonObject();
    QString currentServer = root.value("currentUpstream").toString();
    
    if (currentServer.isEmpty()) {
        return "";
    }
    
    return currentServer;
}

hasaki::upstream_data AppSettings::getCurrentUpstream() const {
    QString name = getCurrentUpstreamName();
    if (name.isEmpty()) {
        return hasaki::upstream_data();
    }
    
    QList<hasaki::upstream_data> servers = getUpstreams();
    for (const hasaki::upstream_data& server : servers) {
        if (server.name == name) {
            return server;
        }
    }
    
    return hasaki::upstream_data();
}


void AppSettings::setCurrentUpstream(const QString& name) {
    QJsonObject root = readJsonObject();
    root["currentUpstream"] = name;
    writeJsonObject(root);
}

bool AppSettings::isIpv6Enabled() const {
    return readJsonObject().value("EnableIpv6").toBool(true);
}

void AppSettings::setIpv6Enabled(bool enabled) {
    QJsonObject root = readJsonObject();
    root["EnableIpv6"] = enabled;
    writeJsonObject(root);
} 