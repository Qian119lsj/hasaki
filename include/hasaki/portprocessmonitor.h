#pragma once

#include <QObject>
#include <QString>
#include <QSet>
#include <QHash>
#include <QMutex>
#include <thread>
#include <optional>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "windivert.h"

struct PortProcessInfo {
    quint16 port;
    QString processName;
};

// RAII wrapper for HANDLE
class UniqueHandle {
public:
    UniqueHandle(HANDLE handle = INVALID_HANDLE_VALUE) : m_handle(handle) {}
    ~UniqueHandle() {
        if (m_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(m_handle);
        }
    }
    UniqueHandle(const UniqueHandle &) = delete;
    UniqueHandle &operator=(const UniqueHandle &) = delete;
    UniqueHandle(UniqueHandle &&other) noexcept : m_handle(other.m_handle) { other.m_handle = INVALID_HANDLE_VALUE; }
    UniqueHandle &operator=(UniqueHandle &&other) noexcept {
        if (this != &other) {
            if (m_handle != INVALID_HANDLE_VALUE) {
                CloseHandle(m_handle);
            }
            m_handle = other.m_handle;
            other.m_handle = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
    operator bool() const { return m_handle != INVALID_HANDLE_VALUE; }
    HANDLE get() const { return m_handle; }

private:
    HANDLE m_handle;
};

class PortProcessMonitor : public QObject {
    Q_OBJECT
public:
    explicit PortProcessMonitor(QObject *parent = nullptr);
    ~PortProcessMonitor();

    bool startMonitoring();
    void stopMonitoring();

    void setTargetProcessNames(const QSet<QString> &processNames);
    void setBlacklistProcessNames(const QSet<QString> &processNames);
    void setBlacklistMode(bool enabled);

    bool isPortInTargetProcess(quint16 port) const;
    QList<PortProcessInfo> getPortProcessList() const;

signals:
    void mappingsChanged();

private:
    void processEvents(std::stop_token stop_token);
    void handleSocketEvent(WINDIVERT_ADDRESS *addr);
    std::optional<std::wstring> getProcessNameByPid(DWORD pid) const;

    mutable QMutex m_mutex;
    HANDLE m_handle;
    std::jthread m_thread;

    QSet<QString> m_targetProcessNames;
    QSet<QString> m_blacklistProcessNames;
    bool m_isBlacklistMode = false;
    QHash<quint16, QString> m_portToProcessName;
    QSet<DWORD> m_blacklistedPids; // 进程ID黑名单, 用于忽略自身等
};