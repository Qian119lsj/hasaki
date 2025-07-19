#include "hasaki/socks5serverdialog.h"
#include "ui_socks5serverdialog.h"

Socks5ServerDialog::Socks5ServerDialog(QWidget *parent) : QDialog(parent), ui(new Ui::Socks5ServerDialog) { ui->setupUi(this); }

Socks5ServerDialog::~Socks5ServerDialog() { delete ui; }

void Socks5ServerDialog::setServerName(const QString &name) { ui->serverNameLineEdit->setText(name); }

QString Socks5ServerDialog::getServerName() const { return ui->serverNameLineEdit->text(); }

void Socks5ServerDialog::setServerAddress(const QString &address) { ui->serverAddressLineEdit->setText(address); }

QString Socks5ServerDialog::getServerAddress() const { return ui->serverAddressLineEdit->text(); }

void Socks5ServerDialog::setServerPort(int port) { ui->serverPortLineEdit->setText(QString::number(port)); }

int Socks5ServerDialog::getServerPort() const { return ui->serverPortLineEdit->text().toInt(); }