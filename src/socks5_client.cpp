#include "hasaki/socks5_client.h"

#include <QDebug>
#include <rpcndr.h>
#include <ws2tcpip.h>

Socks5Client::Socks5Client(const std::string &local_address, uint16_t local_port, const std::string &server_address, uint16_t server_port) {
    this->local_address = local_address;
    this->local_port = local_port;
    this->server_address = server_address;
    this->server_port = server_port;

    // 建立udp关联
    if (!associateUdp()) {
        throw std::runtime_error("建立UDP关联失败");
    }
}

Socks5Client::~Socks5Client() {
    if (socks5_control_socket_ != INVALID_SOCKET) {
        closesocket(socks5_control_socket_);
    }
}

bool Socks5Client::connect_to_remote(SOCKET &remote_socket, const std::string &target_addr, uint16_t target_port) {
    // 创建套接字
    remote_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (remote_socket == INVALID_SOCKET) {
        qDebug() << "创建SOCKS5客户端套接字失败: " << WSAGetLastError();
        return false;
    }

    if (!local_address.empty() && local_port > 0) {
        sockaddr_in local_addr;
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_port = htons(local_port);
        if (inet_pton(AF_INET, local_address.c_str(), &local_addr.sin_addr) != 1) {
            qDebug() << "无效的本地地址: " << QString::fromStdString(local_address);
            closesocket(remote_socket);
            remote_socket = INVALID_SOCKET;
            return false;
        }
        if (bind(remote_socket, (sockaddr *)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
            qDebug() << "绑定SOCKS5客户端套接字失败: " << WSAGetLastError();
            closesocket(remote_socket);
            remote_socket = INVALID_SOCKET;
            return false;
        }
    }

    // 连接到SOCKS5服务器
    sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);

    if (inet_pton(AF_INET, server_address.c_str(), &server_addr.sin_addr) != 1) {
        qDebug() << "无效的SOCKS5服务器地址: " << QString::fromStdString(server_address);
        closesocket(remote_socket);
        remote_socket = INVALID_SOCKET;
        return false;
    }

    if (connect(remote_socket, (sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        qDebug() << "连接SOCKS5服务器失败: " << WSAGetLastError();
        closesocket(remote_socket);
        remote_socket = INVALID_SOCKET;
        return false;
    }

    // 执行SOCKS5握手
    if (!performHandshake(remote_socket)) {
        qDebug() << "SOCKS5握手失败";
        closesocket(remote_socket);
        remote_socket = INVALID_SOCKET;
        return false;
    }

    // 发送连接请求
    if (!sendConnectRequest(remote_socket, target_addr, target_port)) {
        qDebug() << "发送SOCKS5连接请求失败";
        closesocket(remote_socket);
        remote_socket = INVALID_SOCKET;
        return false;
    }

    // 接收连接响应
    if (!receiveConnectResponse(remote_socket)) {
        qDebug() << "接收SOCKS5连接响应失败";
        closesocket(remote_socket);
        remote_socket = INVALID_SOCKET;
        return false;
    }

    return true;
}

bool Socks5Client::sendToRemote(SOCKET &socket, const char *data, size_t data_len, const std::string &dst_ip, uint16_t dst_port, bool is_ipv6) {

    // 构造SOCKS5 UDP请求头
    char header[512];
    size_t header_len = Socks5Client::constructSocks5UdpHeader(header, dst_ip, dst_port, is_ipv6);
    if (header_len == 0) {
        qDebug() << "构造SOCKS5 UDP请求头失败";
        return false;
    }

    // 创建完整数据包
    char *send_buffer = new char[header_len + data_len];
    memcpy(send_buffer, header, header_len);

    // 只有当packet_data不为空且packet_len大于0时才复制数据
    if (data != nullptr && data_len > 0) {
        memcpy(send_buffer + header_len, data, data_len);
    } else {
        qDebug() << "收到空的UDP数据包";
    }

    // 创建目标地址
    sockaddr_storage to_addr;
    int to_addr_len = 0;

    if (socks5_udp_relay_addr_.find(':') != std::string::npos) {
        // IPv6地址
        sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        inet_pton(AF_INET6, socks5_udp_relay_addr_.c_str(), &addr.sin6_addr);
        addr.sin6_port = htons(socks5_udp_relay_port_);

        memcpy(&to_addr, &addr, sizeof(addr));
        to_addr_len = sizeof(addr);
    } else {
        // IPv4地址
        sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        inet_pton(AF_INET, socks5_udp_relay_addr_.c_str(), &addr.sin_addr);
        addr.sin_port = htons(socks5_udp_relay_port_);

        memcpy(&to_addr, &addr, sizeof(addr));
        to_addr_len = sizeof(addr);
    }

    // 发送数据
    int bytes_sent = sendto(socket, send_buffer, header_len + data_len, 0, (sockaddr *)&to_addr, to_addr_len);
    delete[] send_buffer;
    if (bytes_sent == SOCKET_ERROR) {
        return false;
    }

    return true;
}

bool Socks5Client::receiveFromRemote(const char *data, size_t data_len, std::vector<char> &response, std::string &orig_dst_addr, uint16_t &orig_dst_port) {

    if (data_len < 4) {
        return false;
    }
    // 处理来自SOCKS5服务器的返回流量
    char atyp = data[3];
    size_t header_len = 0;
    if (atyp == 0x01) { // IPv4
        if (data_len < 10)
            return false;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &data[4], ip_str, INET_ADDRSTRLEN);
        orig_dst_addr = ip_str;

        uint16_t net_port;
        memcpy(&net_port, data + 8, sizeof(net_port));
        orig_dst_port = ntohs(net_port);
        header_len = 10;
    } else if (atyp == 0x04) { // IPv6
        if (data_len < 22)
            return false;
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &data[4], ip_str, INET6_ADDRSTRLEN);
        orig_dst_addr = ip_str;

        uint16_t net_port;
        memcpy(&net_port, data + 20, sizeof(net_port));
        orig_dst_port = ntohs(net_port);
        header_len = 22;
    } else {
        // 不支持的地址类型
        qDebug() << "不支持的地址类型: " << static_cast<int>(atyp);
        return false;
    }
    
    response.assign(data + header_len, data + data_len);

    return true;
}

bool Socks5Client::performHandshake(SOCKET sock) {
    // SOCKS5握手请求 (无认证)
    unsigned char handshake[3] = {0x05, 0x01, 0x00}; // SOCKS5, 1种认证方法, 无认证(0x00)

    if (send(sock, (char *)handshake, sizeof(handshake), 0) != sizeof(handshake)) {
        qDebug() << "发送SOCKS5握手请求失败: " << WSAGetLastError();
        return false;
    }

    // 接收服务器响应
    unsigned char response[2];
    if (recv(sock, (char *)response, sizeof(response), 0) != sizeof(response)) {
        qDebug() << "接收SOCKS5握手响应失败: " << WSAGetLastError();
        return false;
    }

    // 检查响应是否有效
    if (response[0] != 0x05 || response[1] != 0x00) {
        qDebug() << "SOCKS5服务器不支持无认证方式";
        return false;
    }

    return true;
}

bool Socks5Client::sendConnectRequest(SOCKET sock, const std::string &target_addr, uint16_t target_port) {
    // 构建连接请求
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  |   1   |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+

    // 检查地址类型 (IPv4, IPv6, 或域名)
    struct sockaddr_storage ss;
    int ss_len = sizeof(ss);
    memset(&ss, 0, sizeof(ss));

    // 尝试解析为IPv4地址
    if (inet_pton(AF_INET, target_addr.c_str(), &((struct sockaddr_in *)&ss)->sin_addr) == 1) {
        // IPv4地址
        unsigned char request[10]; // 4字节IPv4地址 + 基本头(4) + 端口(2)
        memset(request, 0, sizeof(request));

        request[0] = 0x05; // VER: SOCKS5
        request[1] = 0x01; // CMD: CONNECT
        request[2] = 0x00; // RSV: 保留字段
        request[3] = 0x01; // ATYP: IPv4

        // 复制IPv4地址 (已经是网络字节序)
        inet_pton(AF_INET, target_addr.c_str(), &request[4]);

        // 设置端口 (网络字节序)
        uint16_t net_port = htons(target_port);
        memcpy(&request[8], &net_port, 2);

        if (send(sock, (char *)request, sizeof(request), 0) != sizeof(request)) {
            qDebug() << "发送IPv4 SOCKS5连接请求失败: " << WSAGetLastError();
            return false;
        }
    }
    // 尝试解析为IPv6地址
    else if (inet_pton(AF_INET6, target_addr.c_str(), &((struct sockaddr_in6 *)&ss)->sin6_addr) == 1) {
        // IPv6地址
        unsigned char request[22]; // 16字节IPv6地址 + 基本头(4) + 端口(2)
        memset(request, 0, sizeof(request));

        request[0] = 0x05; // VER: SOCKS5
        request[1] = 0x01; // CMD: CONNECT
        request[2] = 0x00; // RSV: 保留字段
        request[3] = 0x04; // ATYP: IPv6

        // 复制IPv6地址 (已经是网络字节序)
        inet_pton(AF_INET6, target_addr.c_str(), &request[4]);

        // 设置端口 (网络字节序)
        uint16_t net_port = htons(target_port);
        memcpy(&request[20], &net_port, 2);

        if (send(sock, (char *)request, sizeof(request), 0) != sizeof(request)) {
            qDebug() << "发送IPv6 SOCKS5连接请求失败: " << WSAGetLastError();
            return false;
        }
    }
    // 假设是域名
    else {
        // 域名地址
        size_t addr_len = target_addr.length();
        if (addr_len > 255) {
            qDebug() << "域名太长: " << QString::fromStdString(target_addr);
            return false;
        }

        unsigned char *request = new unsigned char[7 + addr_len]; // 基本头(4) + 域名长度(1) + 域名 + 端口(2)
        memset(request, 0, 7 + addr_len);

        request[0] = 0x05; // VER: SOCKS5
        request[1] = 0x01; // CMD: CONNECT
        request[2] = 0x00; // RSV: 保留字段
        request[3] = 0x03; // ATYP: 域名

        // 设置域名长度和域名
        request[4] = (unsigned char)addr_len;
        memcpy(&request[5], target_addr.c_str(), addr_len);

        // 设置端口 (网络字节序)
        uint16_t net_port = htons(target_port);
        memcpy(&request[5 + addr_len], &net_port, 2);

        int req_size = 7 + addr_len;
        int sent = send(sock, (char *)request, req_size, 0);
        delete[] request;

        if (sent != req_size) {
            qDebug() << "发送域名 SOCKS5连接请求失败: " << WSAGetLastError();
            return false;
        }
    }

    return true;
}

bool Socks5Client::receiveConnectResponse(SOCKET sock) {
    // 接收连接响应的前5个字节，确定地址类型和后续数据长度
    unsigned char response_header[5];
    if (recv(sock, (char *)response_header, sizeof(response_header), 0) != sizeof(response_header)) {
        qDebug() << "接收SOCKS5连接响应头部失败: " << WSAGetLastError();
        return false;
    }

    // 检查响应是否成功
    if (response_header[0] != 0x05) {
        qDebug() << "非SOCKS5协议响应";
        return false;
    }

    if (response_header[1] != 0x00) {
        // 错误码含义
        const char *error_messages[] = {"请求成功",   "服务器故障", "连接不允许", "网络不可达",    "主机不可达",
                                        "连接被拒绝", "TTL过期",    "命令不支持", "地址类型不支持"};

        int error_code = response_header[1];
        if (error_code >= 0 && error_code <= 8) {
            qDebug() << "SOCKS5连接请求被拒绝: " << error_messages[error_code];
        } else {
            qDebug() << "SOCKS5连接请求被拒绝，未知错误码: " << error_code;
        }
        return false;
    }

    // 根据地址类型读取剩余数据
    int remaining_bytes = 0;
    switch (response_header[3]) {    // ATYP
    case 0x01:                       // IPv4
        remaining_bytes = 4 + 2 - 1; // 4字节IPv4地址 + 2字节端口 - 已读的1字节
        break;
    case 0x03:                                    // 域名
        remaining_bytes = response_header[4] + 2; // 域名长度 + 2字节端口
        break;
    case 0x04:                        // IPv6
        remaining_bytes = 16 + 2 - 1; // 16字节IPv6地址 + 2字节端口 - 已读的1字节
        break;
    default:
        qDebug() << "未知的地址类型: " << (int)response_header[3];
        return false;
    }

    // 读取剩余数据
    if (remaining_bytes > 0) {
        char *remaining_data = new char[remaining_bytes];
        int received = recv(sock, remaining_data, remaining_bytes, 0);
        delete[] remaining_data;

        if (received != remaining_bytes) {
            qDebug() << "接收SOCKS5连接响应剩余数据失败: " << WSAGetLastError();
            return false;
        }
    }

    return true;
}

bool Socks5Client::associateUdp() {
    socks5_control_socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socks5_control_socket_ == INVALID_SOCKET) {
        qDebug() << "创建SOCKS5客户端套接字失败: " << WSAGetLastError();
        return false;
    }

    if (!local_address.empty() && local_port > 0) {
        sockaddr_in client_addr;
        client_addr.sin_family = AF_INET;
        client_addr.sin_port = htons(local_port);
        if (inet_pton(AF_INET, local_address.c_str(), &client_addr.sin_addr) != 1) {
            qDebug() << "无效的本地地址: " << QString::fromStdString(local_address);
            closesocket(socks5_control_socket_);
            socks5_control_socket_ = INVALID_SOCKET;
            return false;
        }

        if (bind(socks5_control_socket_, (SOCKADDR *)&client_addr, sizeof(client_addr)) == SOCKET_ERROR) {
            qDebug() << "绑定SOCKS5客户端套接字失败: " << WSAGetLastError();
            closesocket(socks5_control_socket_);
            socks5_control_socket_ = INVALID_SOCKET;
            return false;
        }
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_address.c_str(), &server_addr.sin_addr) != 1) {
        qDebug() << "无效的SOCKS5服务器地址: " << QString::fromStdString(server_address);
        closesocket(socks5_control_socket_);
        socks5_control_socket_ = INVALID_SOCKET;
        return false;
    }

    if (connect(socks5_control_socket_, (SOCKADDR *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        qDebug() << "连接SOCKS5服务器失败: " << WSAGetLastError();
        closesocket(socks5_control_socket_);
        socks5_control_socket_ = INVALID_SOCKET;
        return false;
    }

    if (!performHandshake(socks5_control_socket_)) {
        qDebug() << "SOCKS5握手失败";
        closesocket(socks5_control_socket_);
        socks5_control_socket_ = INVALID_SOCKET;
        return false;
    }

    // 发送UDP关联请求
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  |   1   |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    char request[10];
    request[0] = 0x05; // SOCKS version 5
    request[1] = 0x03; // UDP ASSOCIATE command
    request[2] = 0x00; // Reserved
    request[3] = 0x01; // Address type: IPv4. 客户端希望SOCKS5服务器用于向客户端发送UDP数据报的地址。
                       // 通常客户端会请求 0.0.0.0:0，让服务器自己决定。
    inet_pton(AF_INET, "0.0.0.0", &request[4]);
    *(uint16_t *)&request[8] = htons(0);

    if (send(socks5_control_socket_, request, sizeof(request), 0) == SOCKET_ERROR) {
        qDebug() << "发送SOCKS5 UDP关联请求失败: " << WSAGetLastError();
        closesocket(socks5_control_socket_);
        socks5_control_socket_ = INVALID_SOCKET;
        return false;
    }

    // 接收UDP关联响应
    char response[256];
    int len = recv(socks5_control_socket_, response, sizeof(response), 0);

    // 响应的最小长度是10 (IPv4)
    if (len < 10) {
        qDebug() << "接收SOCKS5 UDP关联响应失败, 响应过短: " << len;
        closesocket(socks5_control_socket_);
        socks5_control_socket_ = INVALID_SOCKET;
        return false;
    }

    if (response[1] != 0x00) { // 检查是否成功
        qDebug() << "SOCKS5 UDP关联请求被拒绝，状态码: " << (int)response[1];
        closesocket(socks5_control_socket_);
        socks5_control_socket_ = INVALID_SOCKET;
        return false;
    }

    // 提取UDP中继地址和端口
    char atyp = response[3];
    if (atyp == 0x01) { // IPv4
        if (len < 10) {
            qDebug() << "IPv4响应长度不足";
            closesocket(socks5_control_socket_);
            socks5_control_socket_ = INVALID_SOCKET;
            return false;
        }
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &response[4], ip_str, INET_ADDRSTRLEN);
        socks5_udp_relay_addr_ = ip_str;
        socks5_udp_relay_port_ = ntohs(*(uint16_t *)&response[8]);
    } else if (atyp == 0x04) { // IPv6
        if (len < 22) {
            qDebug() << "IPv6响应长度不足";
            closesocket(socks5_control_socket_);
            socks5_control_socket_ = INVALID_SOCKET;
            return false;
        }
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &response[4], ip_str, INET6_ADDRSTRLEN);
        socks5_udp_relay_addr_ = ip_str;
        socks5_udp_relay_port_ = ntohs(*(uint16_t *)&response[20]);
    } else if (atyp == 0x03) { // 域名
        unsigned char domain_len = response[4];
        if (len < 5 + domain_len + 2) {
            qDebug() << "域名响应长度不足";
            closesocket(socks5_control_socket_);
            socks5_control_socket_ = INVALID_SOCKET;
            return false;
        }
        socks5_udp_relay_addr_ = std::string(&response[5], domain_len);
        socks5_udp_relay_port_ = ntohs(*(uint16_t *)&response[5 + domain_len]);
    } else {
        qDebug() << "未知的地址类型: " << (int)atyp;
        closesocket(socks5_control_socket_);
        socks5_control_socket_ = INVALID_SOCKET;
        return false;
    }
    return true;
}

size_t Socks5Client::constructSocks5UdpHeader(char *header, const std::string &target_addr, uint16_t target_port, bool is_ipv6) {
    size_t header_len = 0;
    header[0] = 0x00; // RSV
    header[1] = 0x00; // RSV
    header[2] = 0x00; // FRAG

    if (!is_ipv6) {
        header[3] = 0x01; // ATYP: IPv4
        inet_pton(AF_INET, target_addr.c_str(), &header[4]);
        *(uint16_t *)&header[8] = htons(target_port);
        header_len = 10;
    } else {
        header[3] = 0x04; // ATYP: IPv6
        inet_pton(AF_INET6, target_addr.c_str(), &header[4]);
        *(uint16_t *)&header[20] = htons(target_port);
        header_len = 22;
    }

    return header_len;
}
