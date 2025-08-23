#ifndef APPSETTINGS_H
#define APPSETTINGS_H

#include <QJsonObject>
#include <QObject>
#include <QSet>
#include <QString>
#include <QList>
#include <QPair>
#include "hasaki/data/upstream_data.h"

// 进程预设数据结构
struct ProcessPreset {
    QString name;                        // 预设名称
    QSet<QString> processNames;          // 进程列表
    QSet<QString> blacklistProcessNames; // 黑名单进程列表
    // 黑名单模式默认启用
};

class AppSettings : public QObject {
    Q_OBJECT
public:
    explicit AppSettings(QObject *parent = nullptr);
    ~AppSettings();

    QSet<QString> getTargetProcessNames() const;
    void setTargetProcessNames(const QSet<QString> &processNames);
    int getProxyServerPort() const;
    void setProxyServerPort(int port);

    QList<hasaki::upstream_data> getUpstreams() const;
    void addOrUpdateUpstream(const hasaki::upstream_data &upstream);
    void removeUpstream(const QString &name);
    QString getCurrentUpstreamName() const;
    void setCurrentUpstream(const QString &name);
    hasaki::upstream_data getCurrentUpstream() const;

    bool isBlacklistEnabled() const;
    void setBlacklistEnabled(bool enabled);

    QSet<QString> getBlacklistProcessNames() const;
    void setBlacklistProcessNames(const QSet<QString> &processNames);

    bool isIpv6Enabled() const;
    void setIpv6Enabled(bool enabled);

    // 进程预设相关方法
    QList<ProcessPreset> getProcessPresets() const;
    void addOrUpdateProcessPreset(const ProcessPreset &preset);
    void removeProcessPreset(const QString &name);
    QString getCurrentProcessPresetName() const;
    void setCurrentProcessPreset(const QString &name);
    ProcessPreset getCurrentProcessPreset() const;

private:
    void ensureConfigFileExists() const;
    QString getConfigFilePath() const;
    QJsonObject readJsonObject() const;
    void writeJsonObject(const QJsonObject &json) const;
    ProcessPreset jsonToProcessPreset(const QJsonObject &json) const;
    QJsonObject processPresetToJson(const ProcessPreset &preset) const;

    QString m_configFilePath;
};

#endif // APPSETTINGS_H