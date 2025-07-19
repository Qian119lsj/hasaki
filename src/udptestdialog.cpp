#include "hasaki/udptestdialog.h"
#include "ui_udptestdialog.h"
#include "hasaki/mainwindow.h"

#include <QMessageBox>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QDebug>
#include <QHostAddress>

UdpTestDialog::UdpTestDialog(QWidget *parent)
    : QDialog(parent), ui(new Ui::UdpTestDialog) {
    ui->setupUi(this);

    // 不再使用正则表达式验证器，改为在发送时验证IP地址
    // 这样可以同时支持IPv4和IPv6地址

    // 从父窗口获取适配器IP映射
    MainWindow *mainWindow = qobject_cast<MainWindow*>(parent);
    if (mainWindow) {
        adapterIpMap_ = mainWindow->getAdapterIpMap();
    }

    // 初始化适配器下拉框
    initializeAdapterComboBoxes();

    // 连接信号槽
    connect(ui->sourceAdapterComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), 
            this, &UdpTestDialog::on_sourceAdapterComboBox_currentIndexChanged);
    connect(ui->destAdapterComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), 
            this, &UdpTestDialog::on_destAdapterComboBox_currentIndexChanged);

    // 初始化UDP包注入器
    if (!injector_.initialize()) {
        QMessageBox::warning(this, "警告", "无法初始化UDP包注入器。请确保以管理员权限运行此应用程序。");
        ui->sendButton->setEnabled(false);
        ui->statusLabel->setText("初始化失败 - 请以管理员权限运行");
    }
}

UdpTestDialog::~UdpTestDialog() {
    // 自动清理由unique_ptr管理
}

void UdpTestDialog::initializeAdapterComboBoxes() {
    ui->sourceAdapterComboBox->clear();
    ui->destAdapterComboBox->clear();
    
    // 添加一个"手动输入"选项
    ui->sourceAdapterComboBox->addItem("手动输入", -1);
    ui->destAdapterComboBox->addItem("手动输入", -1);
    
    // 添加所有适配器
    QMapIterator<QString, int> i(adapterIpMap_);
    while (i.hasNext()) {
        i.next();
        QString ipAddress = i.key();
        int ifIdx = i.value();
        
        // 根据IP地址类型添加前缀标识
        QString prefix;
        if (ipAddress.contains(':')) {
            prefix = "[IPv6] ";
        } else {
            prefix = "[IPv4] ";
        }
        
        QString displayText = QString("%1适配器 %2: %3").arg(prefix).arg(ifIdx).arg(ipAddress);
        
        ui->sourceAdapterComboBox->addItem(displayText, ifIdx);
        ui->destAdapterComboBox->addItem(displayText, ifIdx);
    }
    
    // 默认选择第一个有效适配器(如果有的话)
    if (ui->sourceAdapterComboBox->count() > 1) {
        ui->sourceAdapterComboBox->setCurrentIndex(1);
    }
    if (ui->destAdapterComboBox->count() > 1) {
        ui->destAdapterComboBox->setCurrentIndex(1);
    }
}

void UdpTestDialog::on_sourceAdapterComboBox_currentIndexChanged(int index) {
    if (index < 0) return;
    
    int ifIdx = ui->sourceAdapterComboBox->itemData(index).toInt();
    currentSourceIfIdx_ = ifIdx;
    
    if (ifIdx >= 0) {
        // 查找对应的IP地址
        QString ipAddress;
        QMapIterator<QString, int> i(adapterIpMap_);
        while (i.hasNext()) {
            i.next();
            if (i.value() == ifIdx) {
                ipAddress = i.key();
                break;
            }
        }
        
        if (!ipAddress.isEmpty()) {
            ui->sourceIpEdit->setText(ipAddress);
            ui->sourceIpEdit->setEnabled(false);
        } else {
            ui->sourceIpEdit->setEnabled(true);
        }
    } else {
        ui->sourceIpEdit->setEnabled(true);
    }
}

void UdpTestDialog::on_destAdapterComboBox_currentIndexChanged(int index) {
    if (index < 0) return;
    
    int ifIdx = ui->destAdapterComboBox->itemData(index).toInt();
    
    if (ifIdx >= 0) {
        // 查找对应的IP地址
        QString ipAddress;
        QMapIterator<QString, int> i(adapterIpMap_);
        while (i.hasNext()) {
            i.next();
            if (i.value() == ifIdx) {
                ipAddress = i.key();
                break;
            }
        }
        
        if (!ipAddress.isEmpty()) {
            ui->destIpEdit->setText(ipAddress);
            ui->destIpEdit->setEnabled(false);
        } else {
            ui->destIpEdit->setEnabled(true);
        }
    } else {
        ui->destIpEdit->setEnabled(true);
    }
}

void UdpTestDialog::on_sendButton_clicked() {
    QString sourceIp = ui->sourceIpEdit->text();
    int sourcePort = ui->sourcePortSpinBox->value();
    QString destIp = ui->destIpEdit->text();
    int destPort = ui->destPortSpinBox->value();
    
    // 验证IP地址格式
    QHostAddress sourceAddr;
    if (!sourceAddr.setAddress(sourceIp)) {
        QMessageBox::warning(this, "错误", "源IP地址格式无效");
        return;
    }
    
    QHostAddress destAddr;
    if (!destAddr.setAddress(destIp)) {
        QMessageBox::warning(this, "错误", "目标IP地址格式无效");
        return;
    }
    
    // 获取payload
    QByteArray payload;
    if (ui->hexModeCheckBox->isChecked()) {
        // 十六进制模式
        QString hexText = ui->payloadEdit->toPlainText().simplified();
        hexText.remove(' '); // 移除所有空格
        
        // 检查是否是有效的十六进制字符串
        QRegularExpression hexRegex("^[0-9A-Fa-f]*$");
        if (!hexRegex.match(hexText).hasMatch() || hexText.length() % 2 != 0) {
            QMessageBox::warning(this, "错误", "无效的十六进制格式。请确保每个字节由两个十六进制字符组成。");
            return;
        }
        
        // 转换为二进制数据
        for (int i = 0; i < hexText.length(); i += 2) {
            QString byteStr = hexText.mid(i, 2);
            bool ok;
            char byte = static_cast<char>(byteStr.toInt(&ok, 16));
            if (ok) {
                payload.append(byte);
            }
        }
    } else {
        // 文本模式
        payload = ui->payloadEdit->toPlainText().toUtf8();
    }
    
    if (payload.isEmpty()) {
        QMessageBox::warning(this, "警告", "发送内容不能为空。");
        return;
    }
    
    qDebug() << "使用适配器索引:" << currentSourceIfIdx_ << "发送UDP包";
    
    // 发送UDP包
    bool success = injector_.sendSpoofedPacket(
        sourceIp.toStdString(),
        static_cast<uint16_t>(sourcePort),
        destIp.toStdString(),
        static_cast<uint16_t>(destPort),
        payload.data(),
        static_cast<size_t>(payload.size()),
        currentSourceIfIdx_
    );
    
    if (success) {
        ui->statusLabel->setText("发送成功");
    } else {
        ui->statusLabel->setText("发送失败");
        QMessageBox::critical(this, "错误", "发送UDP包失败。请检查网络设置和权限。");
    }
} 