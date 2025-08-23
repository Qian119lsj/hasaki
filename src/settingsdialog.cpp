#include "hasaki/settingsdialog.h"
#include "ui_settingsdialog.h"
#include <QListWidgetItem>
#include <QString>
#include <QDialogButtonBox>

SettingsDialog::SettingsDialog(QWidget *parent) : QDialog(parent), ui(new Ui::SettingsDialog) {
    ui->setupUi(this);

    // 连接按钮信号
    connect(ui->buttonBox, &QDialogButtonBox::clicked, this, &SettingsDialog::onButtonClicked);
}

SettingsDialog::~SettingsDialog() { delete ui; }

void SettingsDialog::setProxyPort(int port) { ui->proxyPortLineEdit->setText(QString::number(port)); }

int SettingsDialog::getProxyPort() const { return ui->proxyPortLineEdit->text().toInt(); }

void SettingsDialog::setEnableIpv6(bool enable) { ui->enableIpv6CheckBox->setChecked(enable); }

bool SettingsDialog::isIpv6Enabled() const { return ui->enableIpv6CheckBox->isChecked(); }

void SettingsDialog::onButtonClicked(QAbstractButton *button) {
    QDialogButtonBox::StandardButton standardButton = ui->buttonBox->standardButton(button);

    switch (standardButton) {
    case QDialogButtonBox::Apply:
        applyCurrentSettings();
        break;
    case QDialogButtonBox::Save:
        saveSettings();
        accept(); // 保存并关闭对话框
        break;
    case QDialogButtonBox::Cancel:
        reject(); // 取消并关闭对话框
        break;
    default:
        break;
    }
}

void SettingsDialog::saveSettings() {
    // 保存设置
    applyCurrentSettings();
}

void SettingsDialog::applyCurrentSettings() {
    // 应用当前设置但不关闭对话框
    emit applySettings();
}