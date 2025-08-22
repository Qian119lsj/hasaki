#pragma once

#include "hasaki/data/upstream_data.h"
#include "hasaki/socks5_client.h"
#include <QDebug>
#include <qlogging.h>
#include <string>

namespace hasaki {

struct upstream_client {
    upstream_type type;
    std::string address;
    uint16_t port;
    std::string local_address;
    uint16_t local_port;
    std::string username;
    std::string password;
    std::string encryption_method;
    Socks5Client *socks5_client;

    bool init() {
        if (type == SOCKS5) {
            try {
                socks5_client = new Socks5Client("", 0, address, port);
                return true;
            } catch (const std::exception &e) {
                qDebug() << e.what();
                return false;
            }
        }
        return false;
    };
    bool connect_to_remote(SOCKET &remote_socket, const std::string &target_addr, uint16_t target_port) {
        if (type == SOCKS5) {
            return socks5_client->connect_to_remote(remote_socket, target_addr, target_port);
        }
        return false;
    };
    bool sendToRemote(SOCKET &socket, const char *data, size_t data_len, const std::string &dst_ip, uint16_t dst_port, bool is_ipv6) {
        if (type == SOCKS5) {
            return socks5_client->sendToRemote(socket, data, data_len, dst_ip, dst_port, is_ipv6);
        }
        return false;
    };
    bool receiveFromRemote(const char *data, size_t data_len, std::vector<char> &response, std::string &orig_dst_addr, uint16_t &orig_dst_port) {
        if (type == SOCKS5) {
            return socks5_client->receiveFromRemote(data, data_len, response, orig_dst_addr, orig_dst_port);
        }
        return false;
    };
};

} // namespace hasaki
