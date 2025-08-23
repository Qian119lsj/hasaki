#include "hasaki/process_preset_dialog.h"
#include "ui_process_preset_dialog.h"
#include <QListWidgetItem>
#include <QString>
#include <QDialogButtonBox>
#include <QMessageBox>

ProcessPresetDialog::ProcessPresetDialog(QWidget *parent) : QDialog(parent), ui(new Ui::ProcessPresetDialog) {
    ui->setupUi(this);

    // 连接按钮信号
    connect(ui->buttonBox, &QDialogButtonBox::clicked, this, &ProcessPresetDialog::onButtonClicked);
}

ProcessPresetDialog::~ProcessPresetDialog() { delete ui; }

void ProcessPresetDialog::setPreset(const ProcessPreset &preset) {
    // 设置预设名称
    ui->presetNameLineEdit->setText(preset.name);

    // 设置白名单进程列表
    ui->processListWidget->clear();
    for (const QString &name : preset.processNames) {
        ui->processListWidget->addItem(name);
    }

    // 设置黑名单进程列表
    ui->blacklistWidget->clear();
    for (const QString &name : preset.blacklistProcessNames) {
        ui->blacklistWidget->addItem(name);
    }
}

ProcessPreset ProcessPresetDialog::getPreset() const {
    ProcessPreset preset;
    preset.name = ui->presetNameLineEdit->text().trimmed();

    // 获取白名单进程列表
    for (int i = 0; i < ui->processListWidget->count(); ++i) {
        preset.processNames.insert(ui->processListWidget->item(i)->text());
    }

    // 获取黑名单进程列表
    for (int i = 0; i < ui->blacklistWidget->count(); ++i) {
        preset.blacklistProcessNames.insert(ui->blacklistWidget->item(i)->text());
    }

    return preset;
}

void ProcessPresetDialog::setEditMode(bool editMode) {
    m_editMode = editMode;

    if (editMode) {
        setWindowTitle("编辑进程预设");
        // 编辑模式下不允许修改预设名称
        ui->presetNameLineEdit->setEnabled(false);
    } else {
        setWindowTitle("新建进程预设");
        ui->presetNameLineEdit->setEnabled(true);
    }
}

void ProcessPresetDialog::on_addButton_clicked() {
    const QString newProcess = ui->processLineEdit->text().trimmed();
    if (!newProcess.isEmpty()) {
        if (ui->processListWidget->findItems(newProcess, Qt::MatchExactly).isEmpty()) {
            ui->processListWidget->addItem(newProcess);
        }
        ui->processLineEdit->clear();
    }
}

void ProcessPresetDialog::on_removeButton_clicked() { qDeleteAll(ui->processListWidget->selectedItems()); }

void ProcessPresetDialog::on_blacklistAddButton_clicked() {
    const QString newProcess = ui->blacklistLineEdit->text().trimmed();
    if (!newProcess.isEmpty()) {
        if (ui->blacklistWidget->findItems(newProcess, Qt::MatchExactly).isEmpty()) {
            ui->blacklistWidget->addItem(newProcess);
        }
        ui->blacklistLineEdit->clear();
    }
}

void ProcessPresetDialog::on_blacklistRemoveButton_clicked() { qDeleteAll(ui->blacklistWidget->selectedItems()); }

void ProcessPresetDialog::onButtonClicked(QAbstractButton *button) {
    QDialogButtonBox::StandardButton standardButton = ui->buttonBox->standardButton(button);

    switch (standardButton) {
    case QDialogButtonBox::Ok:
        if (validateInput()) {
            accept();
        }
        break;
    case QDialogButtonBox::Cancel:
        reject();
        break;
    default:
        break;
    }
}

bool ProcessPresetDialog::validateInput() {
    QString presetName = ui->presetNameLineEdit->text().trimmed();

    if (presetName.isEmpty()) {
        QMessageBox::warning(this, "警告", "预设名称不能为空");
        return false;
    }

    // 这里可以添加更多验证逻辑
    return true;
}