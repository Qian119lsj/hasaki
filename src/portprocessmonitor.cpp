#include "hasaki/portprocessmonitor.h"
#include <QDebug>
#include <QtNetwork/QHostAddress>
#include <filesystem>
#include <iostream>
#include <chrono>

PortProcessMonitor::PortProcessMonitor(QObject *parent) : QObject(parent), m_handle(INVALID_HANDLE_VALUE) {}

PortProcessMonitor::~PortProcessMonitor() { stopMonitoring(); }

bool PortProcessMonitor::startMonitoring() {
    if (m_thread.joinable()) {
        return true; // 已经在运行中
    }

    // 将本进程ID加入黑名单
    m_blacklistedPids.insert(GetCurrentProcessId());

    // 打开WinDivert句柄，监听BIND和CLOSE事件
    m_handle = WinDivertOpen("not loopback and (event == BIND or event == CLOSE)", WINDIVERT_LAYER_SOCKET, WINDIVERT_PRIORITY_HIGHEST,
                             WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);

    if (m_handle == INVALID_HANDLE_VALUE) {
        DWORD lastError = GetLastError();
        qDebug() << "打开WinDivert句柄失败: " << lastError;
        if (lastError == ERROR_ACCESS_DENIED) {
            qDebug() << ">> 提示: 此应用程序必须以管理员身份运行。";
        } else if (lastError == ERROR_FILE_NOT_FOUND) {
            qDebug() << "未找到WinDivert驱动文件(WinDivert32.sys/WinDivert64.sys)或加载失败。";
        }
        return false;
    }

    // 启动处理线程
    m_thread = std::jthread([this](std::stop_token st) { this->processEvents(st); });
    return true;
}

void PortProcessMonitor::stopMonitoring() {
    // 请求线程停止
    if (m_thread.joinable()) {
        m_thread.request_stop();
        // It's better to not join here if stopMonitoring can be called from the UI thread
        // to avoid blocking. The jthread destructor will join. Or manage lifetime carefully.
        // For now, let's keep it for simplicity.
        m_thread.join();
    }

    // 关闭WinDivert句柄
    if (m_handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(m_handle);
        m_handle = INVALID_HANDLE_VALUE;
    }
}

void PortProcessMonitor::setTargetProcessNames(const QSet<QString> &processNames) {
    QMutexLocker locker(&m_mutex);
    m_targetProcessNames = processNames;
}

void PortProcessMonitor::setBlacklistProcessNames(const QSet<QString>& processNames)
{
    QMutexLocker locker(&m_mutex);
    m_blacklistProcessNames = processNames;
}

void PortProcessMonitor::setBlacklistMode(bool enabled)
{
    QMutexLocker locker(&m_mutex);
    m_isBlacklistMode = enabled;
}

bool PortProcessMonitor::isPortInTargetProcess(quint16 port) const {
    QMutexLocker locker(&m_mutex);
    if (!m_portToProcessName.contains(port)) {
        return false;
    }

    const QString processName = m_portToProcessName.value(port);

    // 转发决策逻辑
    if (m_isBlacklistMode) {
        // 在黑名单模式下，如果在黑名单中，则一定不转发
        if (m_blacklistProcessNames.contains(processName)) {
            return false;
        }
    }
    
    // 最终是否转发，总是由TargetProcessNames决定
    return m_targetProcessNames.contains(processName);
}

QList<PortProcessInfo> PortProcessMonitor::getPortProcessList() const {
    QMutexLocker locker(&m_mutex);
    QList<PortProcessInfo> list;

    for (auto it = m_portToProcessName.constBegin(); it != m_portToProcessName.constEnd(); ++it) {
        PortProcessInfo info;
        info.port = it.key();
        info.processName = it.value();
        
        // 检查是否已过期
        if (m_portExpirationTime.contains(it.key())) {
            info.isExpired = true;
            info.expireTime = m_portExpirationTime.value(it.key());
        }
        
        list.append(info);
    }

    return list;
}

uint64_t PortProcessMonitor::getCurrentTimeMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void PortProcessMonitor::cleanupExpiredMappings() {
    QMutexLocker locker(&m_mutex);
    uint64_t now = getCurrentTimeMs();
    
    QList<quint16> portsToRemove;
    for (auto it = m_portExpirationTime.begin(); it != m_portExpirationTime.end(); ++it) {
        if (it.value() <= now) {
            portsToRemove.append(it.key());
        }
    }
    
    bool mappingsUpdated = false;
    for (quint16 port : portsToRemove) {
        m_portToProcessName.remove(port);
        m_portExpirationTime.remove(port);
        // qDebug() << "remove port:" << port;
        mappingsUpdated = true;
    }
    
    if (mappingsUpdated) {
        emit mappingsChanged();
    }
}

void PortProcessMonitor::processEvents(std::stop_token stop_token) {
    WINDIVERT_ADDRESS addr;
    
    // 上次清理过期映射的时间
    uint64_t lastCleanupTime = getCurrentTimeMs();
    
    while (!stop_token.stop_requested()) {
        // 每10秒检查一次过期映射
        uint64_t currentTime = getCurrentTimeMs();
        if (currentTime - lastCleanupTime > 10000) { // 10秒 = 10000毫秒
            cleanupExpiredMappings();
            lastCleanupTime = currentTime;
        }
        
        // 接收事件
        if (!WinDivertRecv(m_handle, NULL, 0, NULL, &addr)) {
            DWORD lastError = GetLastError();
            if (lastError != ERROR_NO_DATA && lastError != ERROR_OPERATION_ABORTED) {
                qDebug() << "Socket Warning: Failed to read socket event: " << lastError;
            } else {
                // Graceful exit
                return;
            }
            continue;
        }

        // 不处理进程id为4的进程 (System进程)
        if (addr.Socket.ProcessId == 4) {
            continue;
        }

        // 跳过黑名单中的进程ID
        if (m_blacklistedPids.contains(addr.Socket.ProcessId)) {
            continue;
        }

        // 处理事件
        handleSocketEvent(&addr);
    }
}

void PortProcessMonitor::handleSocketEvent(WINDIVERT_ADDRESS *addr) {
    WINDIVERT_DATA_SOCKET *socketData = &addr->Socket;
    quint16 localPort = socketData->LocalPort;
    bool mappingsUpdated = false;

    {
        QMutexLocker locker(&m_mutex);

        if (addr->Event == WINDIVERT_EVENT_SOCKET_BIND) {
            auto processNameOpt = getProcessNameByPid(socketData->ProcessId);
            if (processNameOpt) {
                QString processName = QString::fromStdWString(processNameOpt.value());

                // 黑名单逻辑:
                // 如果是黑名单模式，且进程在黑名单里，则不跟踪
                if (m_isBlacklistMode && m_blacklistProcessNames.contains(processName)) {
                    return; // 不跟踪此进程
                }

                m_portToProcessName.insert(localPort, processName);
                // 如果端口在过期列表中,移除它
                if (m_portExpirationTime.contains(localPort)) {
                    m_portExpirationTime.remove(localPort);
                }
                mappingsUpdated = true;

                // qDebug() << "Port BOUND:" << localPort << "by process" << processName << "(" << socketData->ProcessId << ")";
            }
        } else if (addr->Event == WINDIVERT_EVENT_SOCKET_CLOSE) {
            if (m_portToProcessName.contains(localPort)) {
                // 不立即删除,而是标记为过期,设置300秒后删除
                uint64_t expireTime = getCurrentTimeMs() + 300000;
                m_portExpirationTime.insert(localPort, expireTime);
                mappingsUpdated = true;

                // qDebug() << "Port MARKED FOR EXPIRATION:" << localPort << "will be removed in 130 seconds";
            }
        }
    }

    if (mappingsUpdated) {
        emit mappingsChanged();
    }
}

std::optional<std::wstring> PortProcessMonitor::getProcessNameByPid(DWORD pid) const {
    // 获取进程句柄
    UniqueHandle processHandle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));

    if (!processHandle) {
        return std::nullopt;
    }

    // 查询进程的可执行文件路径
    wchar_t imagePath[MAX_PATH * 2] = {0};
    DWORD bufferSize = sizeof(imagePath) / sizeof(wchar_t);

    if (QueryFullProcessImageNameW(processHandle.get(), 0, imagePath, &bufferSize)) {
        try {
            return std::filesystem::path(imagePath).filename().wstring();
        } catch (const std::filesystem::filesystem_error &e) {
            std::wcerr << L"Filesystem error: " << e.what() << std::endl;
            return std::nullopt;
        }
    }

    return std::nullopt;
}