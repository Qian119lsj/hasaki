#ifndef UPSTREAMDIALOG_H
#define UPSTREAMDIALOG_H

#include <QDialog>
#include <QString>
#include <hasaki/data/upstream_data.h>

namespace Ui {
class UpstreamDialog;
}

class UpstreamDialog : public QDialog {
    Q_OBJECT

public:
    explicit UpstreamDialog(QWidget *parent = nullptr);
    ~UpstreamDialog();

    void setName(const QString &name);
    QString getName() const;
    hasaki::upstream_type getType() const;
    void setType(hasaki::upstream_type type);

    void setAddress(const QString &address);
    QString getAddress() const;

    void setPort(int port);
    int getPort() const;

    void setLocalAddress(const QString &address);
    QString getLocalAddress() const;

    void setLocalPort(int port);
    int getLocalPort() const;

    QString getUserName() const;
    void setUserName(const QString &name);
    QString getPassword() const;
    void setPassword(const QString &password);
    // Shadowsocks 2022 specific methods
    QString getEncryptionMethod() const;
    void setEncryptionMethod(const QString &method);

private slots:
    void onTypeChanged(int index);

private:
    Ui::UpstreamDialog *ui;
};

#endif // UPSTREAMDIALOG_H