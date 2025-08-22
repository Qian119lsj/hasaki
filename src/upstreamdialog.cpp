#include "hasaki/upstreamdialog.h"
#include "ui_upstreamdialog.h"
#include <QComboBox>

UpstreamDialog::UpstreamDialog(QWidget *parent) : QDialog(parent), ui(new Ui::UpstreamDialog) {
    ui->setupUi(this);

    // Set up type combo box
    ui->typeComboBox->addItem("SOCKS5", QVariant::fromValue(hasaki::upstream_type::SOCKS5));
    ui->typeComboBox->addItem("Shadowsocks 2022", QVariant::fromValue(hasaki::upstream_type::SHADOWSOCKS_2022));

    // Set up encryption method combo box
    ui->encryptionMethodComboBox->addItem("2022-blake3-aes-128-gcm");
    ui->encryptionMethodComboBox->addItem("2022-blake3-aes-256-gcm");

    // Connect signals
    connect(ui->typeComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &UpstreamDialog::onTypeChanged);

    ui->localAddressLineEdit->setText("0.0.0.0");

    // Initialize UI state
    onTypeChanged(0);
}

UpstreamDialog::~UpstreamDialog() { delete ui; }

void UpstreamDialog::setName(const QString &name) { ui->nameLineEdit->setText(name); }

QString UpstreamDialog::getName() const { return ui->nameLineEdit->text(); }

void UpstreamDialog::setAddress(const QString &address) { ui->addressLineEdit->setText(address); }

QString UpstreamDialog::getAddress() const { return ui->addressLineEdit->text(); }

void UpstreamDialog::setPort(int port) { ui->portSpinBox->setValue(port); }

int UpstreamDialog::getPort() const { return ui->portSpinBox->value(); }

void UpstreamDialog::setLocalAddress(const QString &address) { ui->localAddressLineEdit->setText(address); }

QString UpstreamDialog::getLocalAddress() const { return ui->localAddressLineEdit->text(); }

void UpstreamDialog::setLocalPort(int port) { ui->localPortSpinBox->setValue(port); }

int UpstreamDialog::getLocalPort() const { return ui->localPortSpinBox->value(); }

QString UpstreamDialog::getUserName() const { return ui->userNameLineEdit->text(); }

void UpstreamDialog::setUserName(const QString &userName) { ui->userNameLineEdit->setText(userName); }

QString UpstreamDialog::getPassword() const { return ui->passwordLineEdit->text(); }

void UpstreamDialog::setPassword(const QString &password) { ui->passwordLineEdit->setText(password); }

QString UpstreamDialog::getEncryptionMethod() const { return ui->encryptionMethodComboBox->currentText(); }

void UpstreamDialog::setEncryptionMethod(const QString &method) {
    int index = ui->encryptionMethodComboBox->findText(method);
    if (index >= 0) {
        ui->encryptionMethodComboBox->setCurrentIndex(index);
    }
}

hasaki::upstream_type UpstreamDialog::getType() const { return static_cast<hasaki::upstream_type>(ui->typeComboBox->currentData().toInt()); }

void UpstreamDialog::setType(hasaki::upstream_type type) {
    int index = ui->typeComboBox->findData(QVariant::fromValue(type));
    if (index >= 0) {
        ui->typeComboBox->setCurrentIndex(index);
    }
}

void UpstreamDialog::onTypeChanged(int index) {
    Q_UNUSED(index);
    bool isShadowsocks = (getType() == hasaki::upstream_type::SHADOWSOCKS_2022);

    // Show/hide Shadowsocks specific widgets
    ui->userNameLabel->setVisible(!isShadowsocks);
    ui->userNameLineEdit->setVisible(!isShadowsocks);
    ui->encryptionMethodLabel->setVisible(isShadowsocks);
    ui->encryptionMethodComboBox->setVisible(isShadowsocks);
    // Adjust dialog size
    adjustSize();
}