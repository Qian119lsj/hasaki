#pragma once

#include "hasaki/udp_packet_injector.h"

#include <QDialog>
#include <QLineEdit>
#include <QTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QSpinBox>
#include <QComboBox>
#include <QMap>
#include <memory>

namespace Ui {
class UdpTestDialog;
}

class UdpTestDialog : public QDialog {
    Q_OBJECT

public:
    explicit UdpTestDialog(QWidget *parent = nullptr);
    ~UdpTestDialog();

private slots:
    void on_sendButton_clicked();
    void on_sourceAdapterComboBox_currentIndexChanged(int index);
    void on_destAdapterComboBox_currentIndexChanged(int index);

private:
    void initializeAdapterComboBoxes();

    std::unique_ptr<Ui::UdpTestDialog> ui;
    hasaki::UdpPacketInjector injector_;
    QMap<QString, int> adapterIpMap_; // 存储IP地址到网络适配器索引的映射
    int currentSourceIfIdx_ = 0; // 当前选中的源适配器索引
}; 