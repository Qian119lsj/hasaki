#pragma once

#include <WinSock2.h>
#include <Windows.h>
#include <cstdint>
#include <string>

class Socks5Client {
public:
    Socks5Client(const std::string &local_address, uint16_t local_port, const std::string &server_address, uint16_t server_port);
    ~Socks5Client();
    Socks5Client(const Socks5Client &other) = delete;
    Socks5Client &operator=(const Socks5Client &other) = delete;

    bool connect_to_remote(SOCKET &remote_socket, const std::string &socks5_addr, uint16_t socks5_port);

    bool sendToRemote(SOCKET &socket, const char *data, size_t data_len, const std::string &dst_ip, uint16_t dst_port, bool is_ipv6);

private:
    std::string local_address;
    uint16_t local_port;
    std::string server_address;
    uint16_t server_port;

    SOCKET socks5_control_socket_;

    std::string socks5_udp_relay_addr_;
    uint16_t socks5_udp_relay_port_;

    // 请求UDP关联
    bool associateUdp();

    // SOCKS5握手和认证
    static bool performHandshake(SOCKET sock);

    // 发送SOCKS5连接请求
    static bool sendConnectRequest(SOCKET sock, const std::string &target_addr, uint16_t target_port);

    // 接收SOCKS5连接响应
    static bool receiveConnectResponse(SOCKET sock);
    
    // 构造SOCKS5 UDP请求头
    static size_t constructSocks5UdpHeader(char *header, const std::string &target_addr, uint16_t target_port, bool is_ipv6);
};