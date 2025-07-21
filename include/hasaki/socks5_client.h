#pragma once

#include <WinSock2.h>
#include <Windows.h>
#include <cstdint>
#include <string>


class Socks5Client {
public:
    Socks5Client()= delete;
    ~Socks5Client()= delete;

    // 连接到SOCKS5服务器并请求连接到目标地址
    static SOCKET connectTarget(const std::string& socks5_addr, uint16_t socks5_port, const std::string& target_addr, uint16_t target_port);

    // 请求UDP关联
    static SOCKET associateUdp(const std::string &socks5_addr, uint16_t socks5_port, const std::string &client_addr, uint16_t client_port, std::string &udp_addr,
                        uint16_t &udp_port);
    // 构造SOCKS5 UDP请求头
    static size_t constructSocks5UdpHeader(char* header, const std::string& target_addr, 
        uint16_t target_port, bool is_ipv6);
private:
    // SOCKS5握手和认证
    static bool performHandshake(SOCKET sock);

    // 发送SOCKS5连接请求
    static bool sendConnectRequest(SOCKET sock, const std::string& target_addr, uint16_t target_port);

    // 接收SOCKS5连接响应
    static bool receiveConnectResponse(SOCKET sock);
};