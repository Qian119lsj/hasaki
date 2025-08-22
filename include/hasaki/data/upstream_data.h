#pragma once

#include <QString>

namespace hasaki {
enum upstream_type { SOCKS5=1, SHADOWSOCKS_2022=2 };
struct upstream_data {
    QString name;
    upstream_type type;
    QString address;
    int port;
    QString local_address;
    int local_port;
    QString username;
    QString password;
    QString encryption_method;
};  
}