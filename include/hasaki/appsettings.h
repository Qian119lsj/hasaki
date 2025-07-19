#ifndef APPSETTINGS_H
#define APPSETTINGS_H

#include <QJsonObject>
#include <QObject>
#include <QSet>
#include <QString>
#include <QList>
#include <QPair>

struct Socks5Server {
    QString name;
    QString address;
    int port;
};

class AppSettings : public QObject {
    Q_OBJECT
public:
    explicit AppSettings(QObject* parent = nullptr);
    ~AppSettings();

    QSet<QString> getTargetProcessNames() const;
    void          setTargetProcessNames(const QSet<QString>& processNames);
    int           getProxyServerPort() const;
    void          setProxyServerPort(int port);
    
    // 移除单个SOCKS5服务器设置，改为多服务器管理
    QList<Socks5Server> getSocks5Servers() const;
    void addSocks5Server(const QString& name, const QString& address, int port);
    void removeSocks5Server(const QString& name);
    QString getCurrentSocks5Server() const;
    void setCurrentSocks5Server(const QString& name);
    QPair<QString, int> getCurrentSocks5ServerInfo() const;

    bool isBlacklistEnabled() const;
    void setBlacklistEnabled(bool enabled);

    QSet<QString> getBlacklistProcessNames() const;
    void setBlacklistProcessNames(const QSet<QString>& processNames);

private:
    void        ensureConfigFileExists() const;
    QString     getConfigFilePath() const;
    QJsonObject readJsonObject() const;
    void        writeJsonObject(const QJsonObject& json) const;

    QString m_configFilePath;
};

#endif  // APPSETTINGS_H