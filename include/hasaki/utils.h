#pragma once
#define WIN32_LEAN_AND_MEAN
#include "windivert.h"

#include <string>
#include <WinSock2.h>
#include <QDebug>
#include <QThread>
#include <QFileInfo>

// 映射类型枚举
enum class MappingType { IPV4_TCP, IPV6_TCP, IPV4_UDP, IPV6_UDP, UNKNOWN };

// 延迟删除任务结构体
struct DelayedDeleteTask {
    std::string key;     // 映射键
    MappingType type;    // 映射类型
    uint64_t deleteTime; // 删除时间点（毫秒时间戳）

    DelayedDeleteTask(const std::string &k, MappingType t, uint64_t dt) : key(k), type(t), deleteTime(dt) {}
};

struct Ipv4EndpointPair {
    UINT32 srcAddr;
    USHORT srcPort;
    UINT32 dstAddr;
    USHORT dstPort;
};

struct Ipv6EndpointPair {
    UINT8 srcAddr[16];
    UINT16 srcPort;
    UINT8 dstAddr[16];
    UINT16 dstPort;
};

struct ProcessInfo {
    std::string processPath;
};

class Utils {
public:
    // 网络序IPV4地址转字符串
    static std::string FormatIpv4Address(UINT32 addr_uint32);
    static std::string FormatIpv4Address(const UINT32 *addr_uint32);

    // 网络序IPV6地址转字符串
    static std::string FormatIpv6Address(const UINT32 *addr_uint32);

    static std::string getConnectionString(const WINDIVERT_DATA_FLOW *flow, UINT32 ipv6);
    static void extractIpAndPort(const sockaddr_storage &addr, std::string &ip_str, uint16_t &port);
};