#ifndef PROCESS_PRESET_DIALOG_H
#define PROCESS_PRESET_DIALOG_H

#include <QDialog>
#include <QSet>
#include <QString>
#include <QAbstractButton>
#include "hasaki/app_settings.h"

namespace Ui {
class ProcessPresetDialog;
}

class ProcessPresetDialog : public QDialog {
    Q_OBJECT

public:
    explicit ProcessPresetDialog(QWidget *parent = nullptr);
    ~ProcessPresetDialog();

    // 设置和获取预设数据
    void setPreset(const ProcessPreset &preset);
    ProcessPreset getPreset() const;

    // 设置是否为编辑模式
    void setEditMode(bool editMode);

private slots:
    void on_addButton_clicked();
    void on_removeButton_clicked();
    void on_blacklistAddButton_clicked();
    void on_blacklistRemoveButton_clicked();
    void onButtonClicked(QAbstractButton *button);

private:
    Ui::ProcessPresetDialog *ui;
    bool m_editMode = false; // 是否为编辑模式
    bool validateInput();    // 验证输入
};

#endif // PROCESS_PRESET_DIALOG_H