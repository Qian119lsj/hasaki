#ifndef SETTINGSDIALOG_H
#define SETTINGSDIALOG_H

#include <QDialog>
#include <QSet>
#include <QString>
#include <QAbstractButton>

namespace Ui {
class SettingsDialog;
}

class SettingsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SettingsDialog(QWidget *parent = nullptr);
    ~SettingsDialog();

    void setProcessNames(const QSet<QString> &processNames);
    QSet<QString> getProcessNames() const;

    void setBlacklistEnabled(bool enabled);
    bool isBlacklistEnabled() const;

    void setBlacklistProcessNames(const QSet<QString> &processNames);
    QSet<QString> getBlacklistProcessNames() const;

    void setProxyPort(int port);
    int getProxyPort() const;

signals:
    void applySettings(); // 应用设置信号

private slots:
    void on_addButton_clicked();
    void on_removeButton_clicked();
    void onButtonClicked(QAbstractButton* button); // 处理按钮点击
    void on_blacklistAddButton_clicked();
    void on_blacklistRemoveButton_clicked();

private:
    Ui::SettingsDialog *ui;
    void saveSettings(); // 保存设置
    void applyCurrentSettings(); // 应用当前设置
};

#endif // SETTINGSDIALOG_H 