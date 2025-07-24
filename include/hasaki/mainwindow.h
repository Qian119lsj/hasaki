#pragma once

#include "hasaki/appsettings.h"
#include "hasaki/packet_forwarder.h"
#include "hasaki/portprocessmonitor.h"
#include "hasaki/proxy_server.h"
#include "hasaki/endpoint_mapper.h"
#include "hasaki/udp_session_manager.h"
#include "hasaki/udp_packet_injector.h"
#include "hasaki/tcp_session_manager.h"

#include <QMainWindow>
#include <QComboBox>
#include <QMap>
#include <QPair>
#include <QTimer>
#include <QTableWidgetItem>
#include <QStatusBar>
#include <QLabel>

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
    MainWindow(QWidget* parent = nullptr);
    ~MainWindow();
    
    // 获取IP地址到网络适配器索引的映射
    const QMap<QString, int>& getAdapterIpMap() const { return adapterIpMap_; }

private slots:
    void on_actionSettings_triggered();
    void on_actionAddSocks5Server_triggered();
    void on_actionUdpTest_triggered();
    void applySettings();
    void updateMappingsView();
    void updateUdpSessionView(); // 新增：更新UDP会话表格
    void updateSessionStatusBar(); // 新增：更新状态栏会话数
    void on_startButton_clicked();
    void on_stopButton_clicked();
    void on_socks5ServerComboBox_currentIndexChanged(int index);
    void on_editServerButton_clicked();
    void on_deleteServerButton_clicked();

private:
    void startForwarding();
    void stopForwarding();
    void applySettingsFromDialog(SettingsDialog* dialog);
    void updateSocks5ServerComboBox();
    void initializeAdapterIpMap();

    Ui::MainWindow* ui;
    AppSettings* appSettings_;
    PortProcessMonitor* portProcessMonitor_;
    PacketForwarder* packetForwarder_;
    ProxyServer* proxyServer_;
    EndpointMapper* endpointMapper_;
    hasaki::UdpSessionManager* udpSessionManager_; // 使用单例，但仍保留指针
    hasaki::UdpPacketInjector* udpPacketInjector_;
    QComboBox* socks5ServerComboBox_;
    bool is_running_ = false;
    
    // 存储IP地址到网络适配器索引的映射
    QMap<QString, int> adapterIpMap_;
    
    // 定时器，用于定期更新UDP会话表格
    QTimer* udpSessionUpdateTimer_;
    
    // 定时器，用于定期更新状态栏会话数
    QTimer* sessionCountUpdateTimer_;
    
    // 状态栏标签
    QLabel* sessionStatusLabel_;
};
