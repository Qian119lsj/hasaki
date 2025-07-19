#ifndef SOCKS5SERVERDIALOG_H
#define SOCKS5SERVERDIALOG_H

#include <QDialog>
#include <QString>

namespace Ui {
class Socks5ServerDialog;
}

class Socks5ServerDialog : public QDialog
{
    Q_OBJECT

public:
    explicit Socks5ServerDialog(QWidget *parent = nullptr);
    ~Socks5ServerDialog();

    void setServerName(const QString &name);
    QString getServerName() const;

    void setServerAddress(const QString &address);
    QString getServerAddress() const;

    void setServerPort(int port);
    int getServerPort() const;

private:
    Ui::Socks5ServerDialog *ui;
};

#endif // SOCKS5SERVERDIALOG_H 