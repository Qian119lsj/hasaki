#pragma once

#include "hasaki/app_settings.h"
#include "hasaki/packet_forwarder.h"
#include "hasaki/port_process_monitor.h"
#include "hasaki/proxy_server.h"
#include "hasaki/endpoint_mapper.h"
#include "hasaki/udp_session_manager.h"
#include "hasaki/udp_packet_injector.h"

#include <QMainWindow>
#include <QSystemTrayIcon>
#include <QCloseEvent>
#include <QComboBox>
#include <QMap>
#include <QPair>
#include <QTimer>
#include <QTableWidgetItem>
#include <QStatusBar>
#include <QLabel>
#include <qaction.h>
#include <qsystemtrayicon.h>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class AppSettings;
class PortProcessMonitor;
class EndpointMapper;
class PacketForwarder;
class ProxyServer;
class SettingsDialog;
class ProcessPresetDialog;

// 为实现自定义排序，创建一个QTableWidgetItem的子类
class TimeWidgetItem : public QTableWidgetItem {
public:
    TimeWidgetItem(const QString &text) : QTableWidgetItem(text) {}

    bool operator<(const QTableWidgetItem &other) const override {
        // 比较存储在UserRole中的数值
        return data(Qt::UserRole).toLongLong() < other.data(Qt::UserRole).toLongLong();
    }
};

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    // 获取IP地址到网络适配器索引的映射
    const QMap<QString, int> &getAdapterIpMap() const { return adapterIpMap_; }

protected:
    void closeEvent(QCloseEvent *event) override;
private slots:
    void onTrayIconActivated(QSystemTrayIcon::ActivationReason reason);
    void on_actionSettings_triggered();
    void on_actionAddUpstream_triggered();
    void on_actionUdpTest_triggered();
    void on_actionConsoleWindow_triggered();
    void applySettings();
    void updateUdpSessionView();   // 新增：更新UDP会话表格
    void updateSessionStatusBar(); // 新增：更新状态栏会话数
    void on_startButton_clicked();
    void on_stopButton_clicked();
    void on_upstreamComboBox_currentIndexChanged(int index);
    void on_editUpstreamButton_clicked();
    void on_deleteUpstreamButton_clicked();

    // 进程预设相关槽函数
    void on_processPresetComboBox_currentIndexChanged(int index);
    void on_addProcessPresetButton_clicked();
    void on_editProcessPresetButton_clicked();
    void on_deleteProcessPresetButton_clicked();
    void on_copyProcessPresetButton_clicked();

private:
    void createTrayIcon();
    void startForwarding();
    void stopForwarding();
    void applySettingsFromDialog(SettingsDialog *dialog);
    void updateUpstreamComboBox();
    void initializeAdapterIpMap();

    // 进程预设相关方法
    void updateProcessPresetComboBox();
    void applyProcessPreset(const ProcessPreset &preset);

    Ui::MainWindow *ui = nullptr;
    QSystemTrayIcon *trayIcon_ = nullptr;
    QMenu *trayIconMenu_ = nullptr;
    QAction *showAction_ = nullptr;
    QAction *quitAction_ = nullptr;

    AppSettings *appSettings_ = nullptr;
    PortProcessMonitor *portProcessMonitor_ = nullptr;
    PacketForwarder *packetForwarder_ = nullptr;
    hasaki::upstream_client *upstream_client_ = nullptr;
    ProxyServer *proxyServer_ = nullptr;
    EndpointMapper *endpointMapper_ = nullptr;
    hasaki::UdpSessionManager *udpSessionManager_ = nullptr; // 使用单例，但仍保留指针
    hasaki::UdpPacketInjector *udpPacketInjector_ = nullptr;
    QComboBox *upstreamComboBox_ = nullptr;
    QComboBox *processPresetComboBox_ = nullptr; // 进程预设下拉框
    bool is_running_ = false;

    // 存储IP地址到网络适配器索引的映射
    QMap<QString, int> adapterIpMap_;

    // 定时器，用于定期更新UDP会话表格
    QTimer *udpSessionUpdateTimer_ = nullptr;

    // 定时器，用于定期更新状态栏会话数
    QTimer *sessionCountUpdateTimer_ = nullptr;

    // 状态栏标签
    QLabel *sessionStatusLabel_ = nullptr;
};
