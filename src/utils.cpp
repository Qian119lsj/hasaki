#include "hasaki/utils.h"

#include "windivert.h"


#define INET_ADDRSTRLEN 22
#define INET6_ADDRSTRLEN 65

// 网络序IPV4地址转字符串
std::string FormatIpv4Address(const UINT32 addr_uint32) {
    UINT32 addr = WinDivertHelperNtohl(addr_uint32);
    char   buffer[INET_ADDRSTRLEN];
    WinDivertHelperFormatIPv4Address(addr, buffer, sizeof(buffer));
    return buffer;
}
std::string FormatIpv4Address(const UINT32* addr_uint32) {
    UINT32 addr = WinDivertHelperNtohl(addr_uint32[3]);
    char   buffer[INET_ADDRSTRLEN];
    WinDivertHelperFormatIPv4Address(addr, buffer, sizeof(buffer));
    return buffer;
}

// 网络序IPV6地址转字符串
std::string FormatIpv6Address(const UINT32* addr_uint32) {
    UINT32 addr[8];
    WinDivertHelperNtohIpv6Address(addr_uint32, addr);
    char buffer[INET6_ADDRSTRLEN];
    WinDivertHelperFormatIPv6Address(addr, buffer, sizeof(buffer));
    return buffer;
}

std::string getConnectionString(const WINDIVERT_DATA_FLOW* flow, UINT32 ipv6) {
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