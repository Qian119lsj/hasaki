#include "hasaki/settingsdialog.h"
#include "ui_settingsdialog.h"
#include <QListWidgetItem>
#include <QString>
#include <QDialogButtonBox>

SettingsDialog::SettingsDialog(QWidget *parent) : QDialog(parent), ui(new Ui::SettingsDialog) { ui->setupUi(this); }

SettingsDialog::~SettingsDialog() { delete ui; }

void SettingsDialog::setProcessNames(const QSet<QString> &processNames) {
    ui->listWidget->clear();
    for (const QString &name : processNames) {
        ui->listWidget->addItem(name);
    }
}

QSet<QString> SettingsDialog::getProcessNames() const {
    QSet<QString> names;
    for (int i = 0; i < ui->listWidget->count(); ++i) {
        names.insert(ui->listWidget->item(i)->text());
    }
    return names;
}

void SettingsDialog::setBlacklistEnabled(bool enabled)
{
    ui->blacklistEnabledCheckBox->setChecked(enabled);
}

bool SettingsDialog::isBlacklistEnabled() const
{
    return ui->blacklistEnabledCheckBox->isChecked();
}

void SettingsDialog::setBlacklistProcessNames(const QSet<QString> &processNames)
{
    ui->blacklistWidget->clear();
    for (const QString &name : processNames) {
        ui->blacklistWidget->addItem(name);
    }
}

QSet<QString> SettingsDialog::getBlacklistProcessNames() const
{
    QSet<QString> names;
    for (int i = 0; i < ui->blacklistWidget->count(); ++i) {
        names.insert(ui->blacklistWidget->item(i)->text());
    }
    return names;
}

void SettingsDialog::setProxyPort(int port)
{
    ui->proxyPortLineEdit->setText(QString::number(port));
}

int SettingsDialog::getProxyPort() const { return ui->proxyPortLineEdit->text().toInt(); }

void SettingsDialog::on_addButton_clicked() {
    const QString newProcess = ui->lineEdit->text().trimmed();
    if (!newProcess.isEmpty()) {
        if (ui->listWidget->findItems(newProcess, Qt::MatchExactly).isEmpty()) {
            ui->listWidget->addItem(newProcess);
        }
        ui->lineEdit->clear();
    }
}

void SettingsDialog::on_removeButton_clicked()
{
    qDeleteAll(ui->listWidget->selectedItems());
}

void SettingsDialog::on_blacklistAddButton_clicked()
{
    const QString newProcess = ui->blacklistLineEdit->text().trimmed();
    if (!newProcess.isEmpty()) {
        if (ui->blacklistWidget->findItems(newProcess, Qt::MatchExactly).isEmpty()) {
            ui->blacklistWidget->addItem(newProcess);
        }
        ui->blacklistLineEdit->clear();
    }
}

void SettingsDialog::on_blacklistRemoveButton_clicked()
{
    qDeleteAll(ui->blacklistWidget->selectedItems());
}

void SettingsDialog::onButtonClicked(QAbstractButton* button)
{
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