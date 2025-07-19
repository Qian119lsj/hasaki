#pragma once

#include <WinSock2.h>
#include <Windows.h>
#include <cstdint>
#include <string>


class Socks5Client {
public:
    Socks5Client();
    ~Socks5Client();

    // 连接到SOCKS5服务器并请求连接到目标地址
    SOCKET connectTarget(const std::string& socks5_addr, uint16_t socks5_port, const std::string& target_addr, uint16_t target_port);

    // 请求UDP关联
    SOCKET associateUdp(const std::string &socks5_addr, uint16_t socks5_port, const std::string &client_addr, uint16_t client_port, std::string &udp_addr,
                        uint16_t &udp_port);

private:
    // SOCKS5握手和认证
    bool performHandshake(SOCKET sock);

    // 发送SOCKS5连接请求
    bool sendConnectRequest(SOCKET sock, const std::string& target_addr, uint16_t target_port);

    // 接收SOCKS5连接响应
    bool receiveConnectResponse(SOCKET sock);
};