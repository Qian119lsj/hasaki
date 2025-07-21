#include "hasaki/utils.h"
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdint>
#include <string>
#include "windivert.h"

#define INET_ADDRSTRLEN 22
#define INET6_ADDRSTRLEN 65

// 网络序IPV4地址转字符串
std::string Utils::FormatIpv4Address(const UINT32 addr_uint32) {
    UINT32 addr = WinDivertHelperNtohl(addr_uint32);
    char buffer[INET_ADDRSTRLEN];
    WinDivertHelperFormatIPv4Address(addr, buffer, sizeof(buffer));
    return buffer;
}
std::string Utils::FormatIpv4Address(const UINT32 *addr_uint32) {
    UINT32 addr = WinDivertHelperNtohl(addr_uint32[3]);
    char buffer[INET_ADDRSTRLEN];
    WinDivertHelperFormatIPv4Address(addr, buffer, sizeof(buffer));
    return buffer;
}

// 网络序IPV6地址转字符串
std::string Utils::FormatIpv6Address(const UINT32 *addr_uint32) {
    UINT32 addr[8];
    WinDivertHelperNtohIpv6Address(addr_uint32, addr);
    char buffer[INET6_ADDRSTRLEN];
    WinDivertHelperFormatIPv6Address(addr, buffer, sizeof(buffer));
    return buffer;
}

std::string Utils::getConnectionString(const WINDIVERT_DATA_FLOW *flow, UINT32 ipv6) {
    std::string connectionString;
    if (ipv6 == 1) {
        char buffer[INET6_ADDRSTRLEN];
        WinDivertHelperFormatIPv6Address(flow->LocalAddr, buffer, INET6_ADDRSTRLEN);
        char buffer2[INET6_ADDRSTRLEN];
        WinDivertHelperFormatIPv6Address(flow->RemoteAddr, buffer2, INET6_ADDRSTRLEN);

        connectionString = std::string(buffer) + ":" + std::to_string(flow->LocalPort) + "->" + std::string(buffer2) + ":" + std::to_string(flow->RemotePort);
    } else {
        char buffer[INET_ADDRSTRLEN];
        WinDivertHelperFormatIPv4Address(flow->LocalAddr[0], buffer, INET_ADDRSTRLEN);
        char buffer2[INET_ADDRSTRLEN];
        WinDivertHelperFormatIPv4Address(flow->RemoteAddr[0], buffer2, INET_ADDRSTRLEN);

        connectionString = std::string(buffer) + ":" + std::to_string(flow->LocalPort) + "->" + std::string(buffer2) + ":" + std::to_string(flow->RemotePort);
    }

    return connectionString;
}
// 辅助函数：从sockaddr_storage中提取IP字符串和端口号
void Utils::extractIpAndPort(const sockaddr_storage &addr, std::string &ip_str, uint16_t &port) {
    char ip_buf[INET6_ADDRSTRLEN] = {0};
    if (addr.ss_family == AF_INET) {
        // IPv4
        const sockaddr_in *addr_in = reinterpret_cast<const sockaddr_in *>(&addr);
        inet_ntop(AF_INET, &addr_in->sin_addr, ip_buf, sizeof(ip_buf));
        port = ntohs(addr_in->sin_port);
    } else if (addr.ss_family == AF_INET6) {
        // IPv6
        const sockaddr_in6 *addr_in6 = reinterpret_cast<const sockaddr_in6 *>(&addr);
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip_buf, sizeof(ip_buf));
        port = ntohs(addr_in6->sin6_port);
    } else {
        ip_buf[0] = '\0';
        port = 0;
    }
    ip_str = ip_buf;
}