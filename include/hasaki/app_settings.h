#ifndef APPSETTINGS_H
#define APPSETTINGS_H

#include <QJsonObject>
#include <QObject>
#include <QSet>
#include <QString>
#include <QList>
#include <QPair>
#include "hasaki/data/upstream_data.h"

class AppSettings : public QObject {
    Q_OBJECT
public:
    explicit AppSettings(QObject* parent = nullptr);
    ~AppSettings();

    QSet<QString> getTargetProcessNames() const;
    void          setTargetProcessNames(const QSet<QString>& processNames);
    int           getProxyServerPort() const;
    void          setProxyServerPort(int port);
    
    QList<hasaki::upstream_data> getUpstreams() const;
    void addUpstream(const hasaki::upstream_data& upstream);
    void removeUpstream(const QString& name);
    QString getCurrentUpstreamName() const;
    void setCurrentUpstream(const QString& name);
    hasaki::upstream_data getCurrentUpstream() const;

    bool isBlacklistEnabled() const;
    void setBlacklistEnabled(bool enabled);

    QSet<QString> getBlacklistProcessNames() const;
    void setBlacklistProcessNames(const QSet<QString>& processNames);
    
    bool isIpv6Enabled() const;
    void setIpv6Enabled(bool enabled);

private:
    void        ensureConfigFileExists() const;
    QString     getConfigFilePath() const;
    QJsonObject readJsonObject() const;
    void        writeJsonObject(const QJsonObject& json) const;

    QString m_configFilePath;
};

#endif  // APPSETTINGS_H