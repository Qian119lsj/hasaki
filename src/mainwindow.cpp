#include "hasaki/mainwindow.h"

#include "hasaki/settingsdialog.h"
#include "hasaki/upstreamdialog.h"
#include "hasaki/udptestdialog.h"
#include "hasaki/process_preset_dialog.h"
#include "hasaki/delayed_delete_manager.h"
#include "hasaki/tcp_session_manager.h"
#include "hasaki/console_manager.h"
#include "ui_mainwindow.h"

#include <QApplication>
#include <QHeaderView>
#include <QMessageBox>
#include <QNetworkInterface>
#include <QHostAddress>
#include <QDebug>
#include <qapplication.h>
#include <qdebug.h>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);
    createTrayIcon();

    // 初始化网络适配器IP映射
    initializeAdapterIpMap();

    // 设置UDP会话表格
    ui->mappingsTableWidget->setColumnCount(3);
    ui->mappingsTableWidget->setHorizontalHeaderLabels({"客户端IP", "客户端端口", "最后活动时间"});
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
    udpSessionManager_->setPortProcessMonitor(portProcessMonitor_);
    packetForwarder_->setPortProcessMonitor(portProcessMonitor_);
    udpPacketInjector_ = new hasaki::UdpPacketInjector();
    proxyServer_->setUdpPacketInjector(udpPacketInjector_);

    // 设置初始状态
    ProcessPreset currentPreset = appSettings_->getCurrentProcessPreset();
    portProcessMonitor_->setTargetProcessNames(currentPreset.processNames);
    portProcessMonitor_->setBlacklistProcessNames(currentPreset.blacklistProcessNames);
    portProcessMonitor_->setBlacklistMode(true); // 默认启用黑名单模式
    portProcessMonitor_->startMonitoring();

    // 初始化上游服务器下拉框
    upstreamComboBox_ = ui->upstreamComboBox;
    updateUpstreamComboBox();
    connect(ui->upstreamComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &MainWindow::on_upstreamComboBox_currentIndexChanged);

    // 初始化进程预设下拉框
    processPresetComboBox_ = ui->processPresetComboBox;
    updateProcessPresetComboBox();
    connect(ui->processPresetComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &MainWindow::on_processPresetComboBox_currentIndexChanged);

    // 初始化UDP会话更新定时器
    udpSessionUpdateTimer_ = new QTimer(this);
    connect(udpSessionUpdateTimer_, &QTimer::timeout, this, &MainWindow::updateUdpSessionView);
    udpSessionUpdateTimer_->start(2000); // 每2秒更新一次

    // 初始化会话状态更新定时器
    sessionCountUpdateTimer_ = new QTimer(this);
    connect(sessionCountUpdateTimer_, &QTimer::timeout, this, &MainWindow::updateSessionStatusBar);
    sessionCountUpdateTimer_->start(1000); // 每秒更新一次

    // 创建状态栏标签
    sessionStatusLabel_ = new QLabel(this);
    sessionStatusLabel_->setAlignment(Qt::AlignRight);
    sessionStatusLabel_->setMinimumWidth(200);
    ui->statusbar->addPermanentWidget(sessionStatusLabel_);

    // 初始更新一次状态栏
    updateSessionStatusBar();

    ui->startButton->setEnabled(true);
    ui->stopButton->setEnabled(false);

    // 初始更新一次UDP会话表格
    updateUdpSessionView();
}

MainWindow::~MainWindow() {
    stopForwarding();
    portProcessMonitor_->stopMonitoring();

    // 停止定时器
    udpSessionUpdateTimer_->stop();
    sessionCountUpdateTimer_->stop();

    delete packetForwarder_;
    delete proxyServer_;
    delete ui;
}

void MainWindow::createTrayIcon() {
    trayIcon_ = new QSystemTrayIcon(this);
    trayIcon_->setIcon(QIcon(":/icons/app.ico"));
    trayIcon_->setToolTip("Hasaki");
    trayIconMenu_ = new QMenu(this);
    showAction_ = new QAction("显示主窗口", this);
    quitAction_ = new QAction("退出", this);
    trayIconMenu_->addAction(showAction_);
    trayIconMenu_->addSeparator();
    trayIconMenu_->addAction(quitAction_);
    trayIcon_->setContextMenu(trayIconMenu_);

    connect(showAction_, &QAction::triggered, this, &QWidget::show);
    connect(quitAction_, &QAction::triggered, this, &QApplication::quit);

    connect(trayIcon_, &QSystemTrayIcon::activated, this, &MainWindow::onTrayIconActivated);
    trayIcon_->show();
    trayIcon_->showMessage("Hasaki", "Hasaki已启动并在托盘运行", QSystemTrayIcon::Information, 3000);
}

void MainWindow::onTrayIconActivated(QSystemTrayIcon::ActivationReason reason) {
    switch (reason) {
    case QSystemTrayIcon::Trigger:
    case QSystemTrayIcon::DoubleClick:
        this->showNormal();
        this->raise();
        this->activateWindow();
        break;
    default:
        break;
    }
}

void MainWindow::closeEvent(QCloseEvent *event) {
    if (trayIcon_->isVisible()) {
        this->hide();
        event->ignore();
    } else {
        event->accept();
    }
}

void MainWindow::on_actionSettings_triggered() {
    SettingsDialog dialog(this);
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

void MainWindow::on_actionAddUpstream_triggered() {
    UpstreamDialog dialog(this);

    if (dialog.exec() == QDialog::Accepted) {
        hasaki::upstream_data upstream;
        upstream.name = dialog.getName();
        upstream.type = dialog.getType();
        upstream.address = dialog.getAddress();
        upstream.port = dialog.getPort();
        upstream.local_address = dialog.getLocalAddress();
        upstream.local_port = dialog.getLocalPort();
        upstream.username = dialog.getUserName();
        upstream.password = dialog.getPassword();
        upstream.encryption_method = dialog.getEncryptionMethod();
        appSettings_->addOrUpdateUpstream(upstream);
        appSettings_->setCurrentUpstream(dialog.getName());
        updateUpstreamComboBox();
    }
}

void MainWindow::updateUpstreamComboBox() {
    ui->upstreamComboBox->clear();

    QList<hasaki::upstream_data> servers = appSettings_->getUpstreams();
    QString currentServer = appSettings_->getCurrentUpstreamName();
    int currentIndex = 0;

    for (int i = 0; i < servers.size(); ++i) {
        ui->upstreamComboBox->addItem(servers[i].name);
        if (servers[i].name == currentServer) {
            currentIndex = i;
        }
    }

    if (ui->upstreamComboBox->count() > 0) {
        ui->upstreamComboBox->setCurrentIndex(currentIndex);
    }

    // 如果正在运行，禁用下拉框
    ui->upstreamComboBox->setEnabled(!is_running_);
    ui->editUpstreamButton->setEnabled(!is_running_);
    ui->deleteUpstreamButton->setEnabled(!is_running_);
}

void MainWindow::updateProcessPresetComboBox() {
    ui->processPresetComboBox->clear();

    QList<ProcessPreset> presets = appSettings_->getProcessPresets();
    QString currentPreset = appSettings_->getCurrentProcessPresetName();
    int currentIndex = 0;

    for (int i = 0; i < presets.size(); ++i) {
        ui->processPresetComboBox->addItem(presets[i].name);
        if (presets[i].name == currentPreset) {
            currentIndex = i;
        }
    }

    if (ui->processPresetComboBox->count() > 0) {
        ui->processPresetComboBox->setCurrentIndex(currentIndex);
    }

    // 如果正在运行，禁用相关按钮
    ui->addProcessPresetButton->setEnabled(!is_running_);
    ui->editProcessPresetButton->setEnabled(!is_running_);
    ui->deleteProcessPresetButton->setEnabled(!is_running_);
    ui->copyProcessPresetButton->setEnabled(!is_running_);
}

void MainWindow::applyProcessPreset(const ProcessPreset &preset) {
    // 应用预设到监控器
    portProcessMonitor_->setTargetProcessNames(preset.processNames);
    portProcessMonitor_->setBlacklistProcessNames(preset.blacklistProcessNames);
    portProcessMonitor_->setBlacklistMode(true); // 默认启用黑名单模式
}

void MainWindow::on_upstreamComboBox_currentIndexChanged(int index) {
    if (index >= 0) {
        QString serverName = upstreamComboBox_->itemText(index);
        appSettings_->setCurrentUpstream(serverName);
    }
}

void MainWindow::applySettingsFromDialog(SettingsDialog *dialog) {
    if (!dialog)
        return;

    // 保存设置
    appSettings_->setProxyServerPort(dialog->getProxyPort());
    appSettings_->setIpv6Enabled(dialog->isIpv6Enabled());

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

void MainWindow::updateSessionStatusBar() {
    // 获取当前TCP和UDP会话数
    size_t tcpSessions = hasaki::TcpSessionManager::getInstance()->getSessionCount();
    size_t udpSessions = udpSessionManager_->getSessions().size();

    // 更新状态栏标签
    sessionStatusLabel_->setText(QString("TCP会话: %1 | UDP会话: %2").arg(tcpSessions).arg(udpSessions));
}

void MainWindow::updateUdpSessionView() {
    // 保存当前排序状态
    int currentSortColumn = ui->mappingsTableWidget->horizontalHeader()->sortIndicatorSection();
    Qt::SortOrder currentSortOrder = ui->mappingsTableWidget->horizontalHeader()->sortIndicatorOrder();

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
        ui->mappingsTableWidget->setItem(row, 1, clientPortItem); // 客户端端口

        // 最后活动时间
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - session->last_activity_time).count();
        QString timeStr = QString("%1秒前").arg(elapsed);

        TimeWidgetItem *timeItem = new TimeWidgetItem(timeStr);
        // 使用UserRole存储原始时间戳（秒数）用于排序
        timeItem->setData(Qt::UserRole, static_cast<qint64>(elapsed));
        ui->mappingsTableWidget->setItem(row, 2, timeItem);

        row++;
    }

    ui->mappingsTableWidget->setSortingEnabled(true); // 重新启用排序

    // 恢复之前的排序状态
    if (ui->mappingsTableWidget->rowCount() > 0) {
        ui->mappingsTableWidget->sortItems(currentSortColumn, currentSortOrder);
    }
}

void MainWindow::startForwarding() {
    if (is_running_) {
        return;
    }

    ProcessPreset currentPreset = appSettings_->getCurrentProcessPreset();
    // 黑名单模式默认启用，不需要检查processNames是否为空

    // 启动时确保监控器状态与预设一致
    applyProcessPreset(currentPreset);

    // 设置IPv6状态
    packetForwarder_->setEnableIpv6(appSettings_->isIpv6Enabled());

    int proxyPort = appSettings_->getProxyServerPort();

    // 获取当前选中的SOCKS5服务器信息
    hasaki::upstream_data upstreamInfo = appSettings_->getCurrentUpstream();
    upstream_client_ = new hasaki::upstream_client();
    upstream_client_->type = upstreamInfo.type;
    upstream_client_->address = upstreamInfo.address.toStdString();
    upstream_client_->port = upstreamInfo.port;
    upstream_client_->local_address = upstreamInfo.local_address.toStdString();
    upstream_client_->local_port = upstreamInfo.local_port;
    upstream_client_->username = upstreamInfo.username.toStdString();
    upstream_client_->password = upstreamInfo.password.toStdString();
    upstream_client_->encryption_method = upstreamInfo.encryption_method.toStdString();
    if (!upstream_client_->init()) {
        ui->statusbar->showMessage("错误: 初始化SOCKS5客户端失败", 5000);
        return;
    }
    proxyServer_->setUpstreamClient(upstream_client_);
    if (!proxyServer_->start(proxyPort, 8)) {
        ui->statusbar->showMessage("错误: 启动代理服务器失败", 5000);
        packetForwarder_->stop();
        return;
    }

    udpPacketInjector_->initialize();
    packetForwarder_->setProxyServer(proxyServer_);
    initializeAdapterIpMap();
    proxyServer_->setAdapterIpMap(adapterIpMap_);
    if (!packetForwarder_->start()) {
        ui->statusbar->showMessage("错误: 启动包转发器失败", 5000);
        return;
    }

    is_running_ = true;
    ui->startButton->setEnabled(false);
    ui->stopButton->setEnabled(true);
    ui->upstreamComboBox->setEnabled(false);     // 启动后禁用服务器选择
    ui->editUpstreamButton->setEnabled(false);   // 启动后禁用编辑按钮
    ui->deleteUpstreamButton->setEnabled(false); // 启动后禁用删除按钮
    // 禁用预设相关按钮
    ui->processPresetComboBox->setEnabled(false);
    ui->addProcessPresetButton->setEnabled(false);
    ui->editProcessPresetButton->setEnabled(false);
    ui->deleteProcessPresetButton->setEnabled(false);
    ui->copyProcessPresetButton->setEnabled(false);
    ui->statusbar->showMessage("服务运行中");

    // 启动后立即更新一次UDP会话表格和状态栏
    updateUdpSessionView();
    updateSessionStatusBar();
}

void MainWindow::stopForwarding() {
    if (!is_running_) {
        return;
    }
    proxyServer_->stop();
    packetForwarder_->stop();
    DelayedDeleteManager::getInstance()->clearAllTasks();
    endpointMapper_->clearAllMappings();

    is_running_ = false;
    ui->startButton->setEnabled(true);
    ui->stopButton->setEnabled(false);
    ui->upstreamComboBox->setEnabled(true);     // 停止后启用服务器选择
    ui->editUpstreamButton->setEnabled(true);   // 停止后启用编辑按钮
    ui->deleteUpstreamButton->setEnabled(true); // 停止后启用删除按钮
    // 启用预设相关按钮
    ui->processPresetComboBox->setEnabled(true);
    ui->addProcessPresetButton->setEnabled(true);
    ui->editProcessPresetButton->setEnabled(true);
    ui->deleteProcessPresetButton->setEnabled(true);
    ui->copyProcessPresetButton->setEnabled(true);
    ui->statusbar->showMessage("服务已停止");

    // 停止后更新状态栏
    updateSessionStatusBar();
}

void MainWindow::on_startButton_clicked() { startForwarding(); }

void MainWindow::on_stopButton_clicked() { stopForwarding(); }

void MainWindow::on_editUpstreamButton_clicked() {
    if (ui->upstreamComboBox->count() == 0) {
        return;
    }

    hasaki::upstream_data currentServer = appSettings_->getCurrentUpstream();
    qDebug() << "当前服务器信息: " << currentServer.name << currentServer.type << currentServer.address << currentServer.port << currentServer.local_address
             << currentServer.local_port << currentServer.username << currentServer.password << currentServer.encryption_method;

    // 创建编辑对话框
    UpstreamDialog dialog(this);
    dialog.setWindowTitle("编辑上游服务器");
    dialog.setName(currentServer.name);
    dialog.setType(currentServer.type);
    dialog.setAddress(currentServer.address);
    dialog.setPort(currentServer.port);
    dialog.setLocalAddress(currentServer.local_address);
    dialog.setLocalPort(currentServer.local_port);
    dialog.setUserName(currentServer.username);
    dialog.setPassword(currentServer.password);
    dialog.setEncryptionMethod(currentServer.encryption_method);

    if (dialog.exec() == QDialog::Accepted) {
        QString newName = dialog.getName();
        QString address = dialog.getAddress();
        int port = dialog.getPort();

        if (!newName.isEmpty() && !address.isEmpty() && port > 0) {
            // 如果名称改变了，需要先删除旧的服务器
            if (newName != currentServer.name) {
                appSettings_->removeUpstream(currentServer.name);
            }

            // 添加或更新服务器
            hasaki::upstream_data upstream{.name = newName,
                                           .type = dialog.getType(),
                                           .address = address,
                                           .port = port,
                                           .local_address = dialog.getLocalAddress(),
                                           .local_port = dialog.getLocalPort(),
                                           .username = dialog.getUserName(),
                                           .password = dialog.getPassword(),
                                           .encryption_method = dialog.getEncryptionMethod()};
            appSettings_->addOrUpdateUpstream(upstream);
            appSettings_->setCurrentUpstream(newName);
            updateUpstreamComboBox();
        }
    }
}

void MainWindow::on_deleteUpstreamButton_clicked() {
    if (ui->upstreamComboBox->count() <= 1) {
        QMessageBox::warning(this, "警告", "至少需要保留一个上游服务器");
        return;
    }

    QString currentServerName = ui->upstreamComboBox->currentText();

    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, "确认删除", QString("确定要删除服务器 '%1' 吗?").arg(currentServerName), QMessageBox::Yes | QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        appSettings_->removeUpstream(currentServerName);
        appSettings_->setCurrentUpstream(appSettings_->getUpstreams().first().name);
        updateUpstreamComboBox();
    }
}

void MainWindow::on_actionUdpTest_triggered() {
    UdpTestDialog dialog(this);
    dialog.exec();
}

void MainWindow::on_actionConsoleWindow_triggered() {
    console_manager::toggle();
    qDebug() << "Toggle Console button clicked. Current console window handle:" << GetConsoleWindow();
}

void MainWindow::initializeAdapterIpMap() {
    adapterIpMap_.clear();

    // 获取所有网络接口
    QList<QNetworkInterface> interfaces = QNetworkInterface::allInterfaces();

    for (const QNetworkInterface &interface : interfaces) {
        // 跳过回环接口和不活动的接口
        if (interface.flags().testFlag(QNetworkInterface::IsLoopBack) || !interface.flags().testFlag(QNetworkInterface::IsUp) ||
            !interface.flags().testFlag(QNetworkInterface::IsRunning)) {
            continue;
        }

        // 获取接口的IPv4和IPv6地址
        QList<QNetworkAddressEntry> entries = interface.addressEntries();
        for (const QNetworkAddressEntry &entry : entries) {
            QHostAddress addr = entry.ip();
            if (addr.protocol() == QAbstractSocket::IPv4Protocol || addr.protocol() == QAbstractSocket::IPv6Protocol) {
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
                if (!adapterIpMap_.contains(addrStr) || addr.protocol() == QAbstractSocket::IPv4Protocol) {
                    adapterIpMap_[addrStr] = ifIdx;
                }

                qDebug() << "找到网络适配器:" << interface.name() << "索引:" << ifIdx << "IP:" << addrStr
                         << "类型:" << (addr.protocol() == QAbstractSocket::IPv4Protocol ? "IPv4" : "IPv6");
            }
        }
    }
}

void MainWindow::on_processPresetComboBox_currentIndexChanged(int index) {
    if (index >= 0) {
        QString presetName = processPresetComboBox_->itemText(index);
        appSettings_->setCurrentProcessPreset(presetName);

        // 应用选中的预设
        ProcessPreset preset = appSettings_->getCurrentProcessPreset();
        applyProcessPreset(preset);
    }
}

void MainWindow::on_addProcessPresetButton_clicked() {
    ProcessPresetDialog dialog(this);
    dialog.setEditMode(false);

    if (dialog.exec() == QDialog::Accepted) {
        ProcessPreset preset = dialog.getPreset();

        // 检查名称是否已存在
        QList<ProcessPreset> existingPresets = appSettings_->getProcessPresets();
        for (const ProcessPreset &existing : existingPresets) {
            if (existing.name == preset.name) {
                QMessageBox::warning(this, "警告", "预设名称已存在，请使用不同的名称");
                return;
            }
        }

        appSettings_->addOrUpdateProcessPreset(preset);
        appSettings_->setCurrentProcessPreset(preset.name);
        updateProcessPresetComboBox();

        // 应用新预设
        applyProcessPreset(preset);
    }
}

void MainWindow::on_editProcessPresetButton_clicked() {
    if (ui->processPresetComboBox->count() == 0) {
        return;
    }

    ProcessPreset currentPreset = appSettings_->getCurrentProcessPreset();

    ProcessPresetDialog dialog(this);
    dialog.setEditMode(true);
    dialog.setPreset(currentPreset);

    if (dialog.exec() == QDialog::Accepted) {
        ProcessPreset updatedPreset = dialog.getPreset();
        appSettings_->addOrUpdateProcessPreset(updatedPreset);
        updateProcessPresetComboBox();

        // 应用更新后的预设
        applyProcessPreset(updatedPreset);
    }
}

void MainWindow::on_deleteProcessPresetButton_clicked() {
    if (ui->processPresetComboBox->count() <= 1) {
        QMessageBox::warning(this, "警告", "至少需要保留一个进程预设");
        return;
    }

    QString currentPresetName = ui->processPresetComboBox->currentText();

    QMessageBox::StandardButton reply =
        QMessageBox::question(this, "确认删除", QString("是否确认删除预设 '%1'?").arg(currentPresetName), QMessageBox::Yes | QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        appSettings_->removeProcessPreset(currentPresetName);
        updateProcessPresetComboBox();

        // 应用新的当前预设
        ProcessPreset newCurrentPreset = appSettings_->getCurrentProcessPreset();
        applyProcessPreset(newCurrentPreset);
    }
}

void MainWindow::on_copyProcessPresetButton_clicked() {
    if (ui->processPresetComboBox->count() == 0) {
        return;
    }

    ProcessPreset currentPreset = appSettings_->getCurrentProcessPreset();

    ProcessPresetDialog dialog(this);
    dialog.setEditMode(false); // 新增模式
    dialog.setWindowTitle("复制进程预设");

    // 填充除了预设名称外的当前设置
    ProcessPreset copyPreset = currentPreset;
    copyPreset.name = ""; // 清空名称，让用户输入新名称
    dialog.setPreset(copyPreset);

    if (dialog.exec() == QDialog::Accepted) {
        ProcessPreset newPreset = dialog.getPreset();

        // 检查名称是否已存在
        QList<ProcessPreset> existingPresets = appSettings_->getProcessPresets();
        for (const ProcessPreset &existing : existingPresets) {
            if (existing.name == newPreset.name) {
                QMessageBox::warning(this, "警告", "预设名称已存在，请使用不同的名称");
                return;
            }
        }

        appSettings_->addOrUpdateProcessPreset(newPreset);
        appSettings_->setCurrentProcessPreset(newPreset.name);
        updateProcessPresetComboBox();

        // 应用新预设
        applyProcessPreset(newPreset);
    }
}