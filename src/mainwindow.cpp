#include "hasaki/mainwindow.h"

#include "hasaki/settingsdialog.h"
#include "hasaki/socks5serverdialog.h"
#include "hasaki/udptestdialog.h"
#include "hasaki/delayed_delete_manager.h"
#include "ui_mainwindow.h"

#include <QHeaderView>
#include <QMessageBox>
#include <QNetworkInterface>
#include <QHostAddress>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    // 初始化网络适配器IP映射
    initializeAdapterIpMap();

    // 设置UDP会话表格
    ui->mappingsTableWidget->setColumnCount(5);
    ui->mappingsTableWidget->setHorizontalHeaderLabels({"客户端IP", "客户端端口", "目标IP", "目标端口", "最后活动时间"});
    ui->mappingsTableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    // 初始化组件
    appSettings_ = new AppSettings(this);
    portProcessMonitor_ = new PortProcessMonitor(this);
    endpointMapper_ = EndpointMapper::getInstance();
    packetForwarder_ = new PacketForwarder();
    proxyServer_ = new ProxyServer(endpointMapper_);
    // 使用UdpSessionManager单例
    udpSessionManager_ = hasaki::UdpSessionManager::getInstance();

    // 设置组件关系
    packetForwarder_->setPortProcessMonitor(portProcessMonitor_);
    proxyServer_->setAdapterIpMap(adapterIpMap_);
    udpPacketInjector_ = new hasaki::UdpPacketInjector();
    proxyServer_->setUdpPacketInjector(udpPacketInjector_);

    // 不再使用端口映射更新信号
    // connect(portProcessMonitor_, &PortProcessMonitor::mappingsChanged, this, &MainWindow::updateMappingsView);

    // 设置初始状态
    portProcessMonitor_->setTargetProcessNames(appSettings_->getTargetProcessNames());
    portProcessMonitor_->setBlacklistProcessNames(appSettings_->getBlacklistProcessNames());
    portProcessMonitor_->setBlacklistMode(appSettings_->isBlacklistEnabled());
    portProcessMonitor_->startMonitoring();

    // 初始化SOCKS5服务器下拉框
    socks5ServerComboBox_ = ui->socks5ServerComboBox;
    updateSocks5ServerComboBox();
    connect(ui->socks5ServerComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &MainWindow::on_socks5ServerComboBox_currentIndexChanged);

    // 初始化UDP会话更新定时器
    udpSessionUpdateTimer_ = new QTimer(this);
    connect(udpSessionUpdateTimer_, &QTimer::timeout, this, &MainWindow::updateUdpSessionView);
    udpSessionUpdateTimer_->start(2000); // 每2秒更新一次

    ui->startButton->setEnabled(true);
    ui->stopButton->setEnabled(false);
    
    // 初始更新一次UDP会话表格
    updateUdpSessionView();
}

MainWindow::~MainWindow() {
    stopForwarding();
    portProcessMonitor_->stopMonitoring();
    
    // 关闭延迟删除管理器
    DelayedDeleteManager::getInstance()->stop();
    
    // 停止定时器
    udpSessionUpdateTimer_->stop();
    
    delete packetForwarder_;
    delete proxyServer_;
    // 不需要删除单例对象
    // delete udpSessionManager_;
    delete ui;
}

void MainWindow::on_actionSettings_triggered() {
    SettingsDialog dialog(this);
    dialog.setProcessNames(appSettings_->getTargetProcessNames());
    dialog.setBlacklistEnabled(appSettings_->isBlacklistEnabled());
    dialog.setBlacklistProcessNames(appSettings_->getBlacklistProcessNames());
    dialog.setProxyPort(appSettings_->getProxyServerPort());
    dialog.setEnableIpv6(appSettings_->isIpv6Enabled());

    // 连接应用设置信号
    connect(&dialog, &SettingsDialog::applySettings, this, &MainWindow::applySettings);

    int result = dialog.exec();
    if (result == QDialog::Accepted) {
        // "保存" 按钮被点击
        applySettingsFromDialog(&dialog);
    }
}

void MainWindow::on_actionAddSocks5Server_triggered() {
    Socks5ServerDialog dialog(this);

    if (dialog.exec() == QDialog::Accepted) {
        QString name = dialog.getServerName();
        QString address = dialog.getServerAddress();
        int port = dialog.getServerPort();

        if (!name.isEmpty() && !address.isEmpty() && port > 0) {
            appSettings_->addSocks5Server(name, address, port);
            appSettings_->setCurrentSocks5Server(name);
            updateSocks5ServerComboBox();
        }
    }
}

void MainWindow::updateSocks5ServerComboBox() {
    ui->socks5ServerComboBox->clear();
    
    QList<Socks5Server> servers = appSettings_->getSocks5Servers();
    QString currentServer = appSettings_->getCurrentSocks5Server();
    int currentIndex = 0;
    
    for (int i = 0; i < servers.size(); ++i) {
        ui->socks5ServerComboBox->addItem(servers[i].name);
        if (servers[i].name == currentServer) {
            currentIndex = i;
        }
    }
    
    if (ui->socks5ServerComboBox->count() > 0) {
        ui->socks5ServerComboBox->setCurrentIndex(currentIndex);
    }
    
    // 如果正在运行，禁用下拉框
    ui->socks5ServerComboBox->setEnabled(!is_running_);
    ui->editServerButton->setEnabled(!is_running_);
    ui->deleteServerButton->setEnabled(!is_running_);
}

void MainWindow::on_socks5ServerComboBox_currentIndexChanged(int index) {
    if (index >= 0) {
        QString serverName = socks5ServerComboBox_->itemText(index);
        appSettings_->setCurrentSocks5Server(serverName);
    }
}

void MainWindow::applySettingsFromDialog(SettingsDialog *dialog) {
    if (!dialog)
        return;

    // 保存所有设置
    appSettings_->setTargetProcessNames(dialog->getProcessNames());
    appSettings_->setBlacklistEnabled(dialog->isBlacklistEnabled());
    appSettings_->setBlacklistProcessNames(dialog->getBlacklistProcessNames());
    appSettings_->setProxyServerPort(dialog->getProxyPort());
    appSettings_->setIpv6Enabled(dialog->isIpv6Enabled());

    // 应用到监控器
    portProcessMonitor_->setTargetProcessNames(dialog->getProcessNames());
    portProcessMonitor_->setBlacklistProcessNames(dialog->getBlacklistProcessNames());
    portProcessMonitor_->setBlacklistMode(dialog->isBlacklistEnabled());
    
    // 应用IPv6设置到PacketForwarder
    packetForwarder_->setEnableIpv6(dialog->isIpv6Enabled());

    // 如果正在运行，可能需要重启服务以应用新设置
    if (is_running_) {
        ui->statusbar->showMessage("设置已应用，部分设置可能需要重启服务生效", 5000);
    } else {
        ui->statusbar->showMessage("设置已应用", 3000);
    }
}

void MainWindow::applySettings() {
    SettingsDialog *dialog = qobject_cast<SettingsDialog *>(sender());
    if (dialog) {
        applySettingsFromDialog(dialog);
    }
}

void MainWindow::updateMappingsView() {
    // 此方法保留但不再使用，改为使用updateUdpSessionView
}

void MainWindow::updateUdpSessionView() {
    ui->mappingsTableWidget->setRowCount(0); // 清空表格
    
    // 获取UDP会话数据
    auto sessions = udpSessionManager_->getSessions();
    
    ui->mappingsTableWidget->setSortingEnabled(false); // 更新时禁用排序
    
    int row = 0;
    for (const auto &session_pair : sessions) {
        auto &session = session_pair.second;
        
        ui->mappingsTableWidget->insertRow(row);
        
        // 客户端IP
        ui->mappingsTableWidget->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(session->client_ip)));
        
        // 客户端端口
        QTableWidgetItem *clientPortItem = new QTableWidgetItem();
        clientPortItem->setData(Qt::DisplayRole, session->client_port);
        ui->mappingsTableWidget->setItem(row, 1, clientPortItem);
        
        // 目标IP
        ui->mappingsTableWidget->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(session->dest_ip)));
        
        // 目标端口
        QTableWidgetItem *destPortItem = new QTableWidgetItem();
        destPortItem->setData(Qt::DisplayRole, session->dest_port);
        ui->mappingsTableWidget->setItem(row, 3, destPortItem);
        
        // 最后活动时间
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - session->last_activity_time).count();
        QString timeStr = QString("%1秒前").arg(elapsed);
        ui->mappingsTableWidget->setItem(row, 4, new QTableWidgetItem(timeStr));
        
        row++;
    }
    
    ui->mappingsTableWidget->setSortingEnabled(true); // 重新启用排序
    if (ui->mappingsTableWidget->rowCount() > 0) {
        ui->mappingsTableWidget->sortItems(0, Qt::AscendingOrder);
    }
    
    // 更新状态栏显示会话数
    ui->statusbar->showMessage(QString("当前UDP会话数: %1").arg(sessions.size()), 2000);
}

void MainWindow::startForwarding() {
    if (is_running_) {
        return;
    }

    QSet<QString> targetProcesses = appSettings_->getTargetProcessNames();
    if (targetProcesses.isEmpty()) {
        ui->statusbar->showMessage("错误: 未配置目标进程", 5000);
        return;
    }

    // 启动时确保监控器状态与设置一致
    portProcessMonitor_->setTargetProcessNames(targetProcesses);
    portProcessMonitor_->setBlacklistProcessNames(appSettings_->getBlacklistProcessNames());
    portProcessMonitor_->setBlacklistMode(appSettings_->isBlacklistEnabled());
    
    // 设置IPv6状态
    packetForwarder_->setEnableIpv6(appSettings_->isIpv6Enabled());

    int proxyPort = appSettings_->getProxyServerPort();

    // 获取当前选中的SOCKS5服务器信息
    QPair<QString, int> socks5Info = appSettings_->getCurrentSocks5ServerInfo();
    QString socks5Address = socks5Info.first;
    int socks5Port = socks5Info.second;
    proxyServer_->setSocks5Server(socks5Address.toStdString(), static_cast<uint16_t>(socks5Port));
    if (!proxyServer_->start(proxyPort, 14)) {
        ui->statusbar->showMessage("错误: 启动代理服务器失败", 5000);
        packetForwarder_->stop();
        return;
    }

    udpPacketInjector_->initialize();
    packetForwarder_->setProxyServer(proxyServer_);
    if (!packetForwarder_->start()) {
        ui->statusbar->showMessage("错误: 启动包转发器失败", 5000);
        return;
    }

    is_running_ = true;
    ui->startButton->setEnabled(false);
    ui->stopButton->setEnabled(true);
    ui->socks5ServerComboBox->setEnabled(false); // 启动后禁用SOCKS5服务器选择
    ui->editServerButton->setEnabled(false); // 启动后禁用编辑按钮
    ui->deleteServerButton->setEnabled(false); // 启动后禁用删除按钮
    ui->statusbar->showMessage("服务运行中...", 0);
    
    // 启动后立即更新一次UDP会话表格
    updateUdpSessionView();
}

void MainWindow::stopForwarding() {
    if (!is_running_) {
        return;
    }
    proxyServer_->stop();
    packetForwarder_->stop();

    is_running_ = false;
    ui->startButton->setEnabled(true);
    ui->stopButton->setEnabled(false);
    ui->socks5ServerComboBox->setEnabled(true); // 停止后启用SOCKS5服务器选择
    ui->editServerButton->setEnabled(true); // 停止后启用编辑按钮
    ui->deleteServerButton->setEnabled(true); // 停止后启用删除按钮
    ui->statusbar->showMessage("服务已停止", 5000);
    
    // 停止后立即更新一次UDP会话表格，清空表格
    updateUdpSessionView();
}

void MainWindow::on_startButton_clicked() { startForwarding(); }

void MainWindow::on_stopButton_clicked() { stopForwarding(); }

void MainWindow::on_editServerButton_clicked() {
    if (ui->socks5ServerComboBox->count() == 0) {
        return;
    }
    
    QString currentServerName = ui->socks5ServerComboBox->currentText();
    QList<Socks5Server> servers = appSettings_->getSocks5Servers();
    
    // 查找当前选中的服务器
    Socks5Server currentServer;
    bool found = false;
    for (const auto& server : servers) {
        if (server.name == currentServerName) {
            currentServer = server;
            found = true;
            break;
        }
    }
    
    if (!found) {
        return;
    }
    
    // 创建编辑对话框
    Socks5ServerDialog dialog(this);
    dialog.setWindowTitle("编辑SOCKS5服务器");
    dialog.setServerName(currentServer.name);
    dialog.setServerAddress(currentServer.address);
    dialog.setServerPort(currentServer.port);
    
    if (dialog.exec() == QDialog::Accepted) {
        QString newName = dialog.getServerName();
        QString address = dialog.getServerAddress();
        int port = dialog.getServerPort();
        
        if (!newName.isEmpty() && !address.isEmpty() && port > 0) {
            // 如果名称改变了，需要先删除旧的服务器
            if (newName != currentServerName) {
                appSettings_->removeSocks5Server(currentServerName);
            }
            
            // 添加或更新服务器
            appSettings_->addSocks5Server(newName, address, port);
            appSettings_->setCurrentSocks5Server(newName);
            updateSocks5ServerComboBox();
        }
    }
}

void MainWindow::on_actionUdpTest_triggered() {
    UdpTestDialog dialog(this);
    dialog.exec();
}

void MainWindow::on_deleteServerButton_clicked() {
    if (ui->socks5ServerComboBox->count() <= 1) {
        QMessageBox::warning(this, "警告", "至少需要保留一个SOCKS5服务器");
        return;
    }
    
    QString currentServerName = ui->socks5ServerComboBox->currentText();
    
    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, "确认删除", 
                                 QString("确定要删除服务器 '%1' 吗?").arg(currentServerName),
                                 QMessageBox::Yes|QMessageBox::No);
                                 
    if (reply == QMessageBox::Yes) {
        appSettings_->removeSocks5Server(currentServerName);
        updateSocks5ServerComboBox();
    }
}

void MainWindow::initializeAdapterIpMap() {
    adapterIpMap_.clear();
    
    // 获取所有网络接口
    QList<QNetworkInterface> interfaces = QNetworkInterface::allInterfaces();
    
    for (const QNetworkInterface &interface : interfaces) {
        // 跳过回环接口和不活动的接口
        if (interface.flags().testFlag(QNetworkInterface::IsLoopBack) || 
            !interface.flags().testFlag(QNetworkInterface::IsUp) ||
            !interface.flags().testFlag(QNetworkInterface::IsRunning)) {
            continue;
        }
        
        // 获取接口的IPv4和IPv6地址
        QList<QNetworkAddressEntry> entries = interface.addressEntries();
        for (const QNetworkAddressEntry &entry : entries) {
            QHostAddress addr = entry.ip();
            if (addr.protocol() == QAbstractSocket::IPv4Protocol || 
                addr.protocol() == QAbstractSocket::IPv6Protocol) {
                // 获取接口索引和IP地址
                int ifIdx = interface.index();
                QString addrStr = addr.toString();
                
                // 如果是IPv6地址，可能需要处理范围ID
                if (addr.protocol() == QAbstractSocket::IPv6Protocol) {
                    // 移除IPv6地址中的范围ID部分（如果存在）
                    int scopeIdPos = addrStr.indexOf('%');
                    if (scopeIdPos != -1) {
                        addrStr = addrStr.left(scopeIdPos);
                    }
                }
                
                // 存储映射（如果已存在相同IP地址，优先保留IPv4的映射）
                if (!adapterIpMap_.contains(addrStr) || 
                    addr.protocol() == QAbstractSocket::IPv4Protocol) {
                    adapterIpMap_[addrStr] = ifIdx;
                }
                
                qDebug() << "找到网络适配器:" << interface.name() 
                         << "索引:" << ifIdx 
                         << "IP:" << addrStr
                         << "类型:" << (addr.protocol() == QAbstractSocket::IPv4Protocol ? "IPv4" : "IPv6");
            }
        }
    }
}
