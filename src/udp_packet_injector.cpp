#include "hasaki/udp_packet_injector.h"

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include "windivert.h"

#include <QDebug>
#include <vector>
#include <cstring>

#pragma comment(lib, "Ws2_32.lib")

namespace hasaki {

UdpPacketInjector::UdpPacketInjector() = default;

UdpPacketInjector::~UdpPacketInjector() { shutdown(); }

bool UdpPacketInjector::initialize() {
    // We open a handle with a filter "false" because we only need it for injection, not for capturing.
    // This is an efficient way to get a handle just for sending packets.
    divertHandle_ = WinDivertOpen("false", WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SEND_ONLY);
    if (divertHandle_ == INVALID_HANDLE_VALUE) {
        DWORD lastError = GetLastError();
        qDebug() << "UdpPacketInjector: Failed to open WinDivert handle: " << lastError;
        if (lastError == ERROR_ACCESS_DENIED) {
            qDebug() << ">> Hint: This application must be run as an administrator.";
        }
        divertHandle_ = nullptr; // Ensure handle is null on failure
        return false;
    }
    qDebug() << "UdpPacketInjector initialized successfully.";
    return true;
}

void UdpPacketInjector::shutdown() {
    if (divertHandle_ != nullptr) {
        WinDivertClose(static_cast<HANDLE>(divertHandle_));
        divertHandle_ = nullptr;
        qDebug() << "UdpPacketInjector shut down.";
    }
}

bool UdpPacketInjector::isIPv6Address(const std::string &ipAddress) {
    // 检查IP地址是否包含冒号，简单判断是否为IPv6
    return ipAddress.find(':') != std::string::npos;
}

bool UdpPacketInjector::sendSpoofedPacket(const std::string &spoofedIp, uint16_t spoofedPort, const std::string &destIp, uint16_t destPort, const char *payload,
                                          size_t payloadLen, int ifIdx) {
    if (divertHandle_ == nullptr) {
        qDebug() << "UdpPacketInjector is not initialized.";
        return false;
    }

    // 判断源地址和目标地址是否为IPv6
    bool isSourceIPv6 = isIPv6Address(spoofedIp);
    bool isDestIPv6 = isIPv6Address(destIp);

    // 源地址和目标地址必须是相同的IP版本
    if (isSourceIPv6 != isDestIPv6) {
        qDebug() << "源地址和目标地址必须是相同的IP版本 (IPv4 或 IPv6)";
        return false;
    }

    // 根据IP版本调用相应的发送函数
    if (isSourceIPv6) {
        return sendSpoofedIPv6Packet(spoofedIp, spoofedPort, destIp, destPort, payload, payloadLen, ifIdx);
    } else {
        return sendSpoofedIPv4Packet(spoofedIp, spoofedPort, destIp, destPort, payload, payloadLen, ifIdx);
    }
}

bool UdpPacketInjector::sendSpoofedIPv4Packet(const std::string &spoofedIp, uint16_t spoofedPort, const std::string &destIp, uint16_t destPort, const char *payload,
                                             size_t payloadLen, int ifIdx) {
    // 1. 构造数据包缓冲区
    size_t packetLen = sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR) + payloadLen;
    std::vector<char> packet(packetLen);

    // 获取指向头部和负载的指针
    auto *ipHeader = reinterpret_cast<PWINDIVERT_IPHDR>(packet.data());
    auto *udpHeader = reinterpret_cast<PWINDIVERT_UDPHDR>(packet.data() + sizeof(WINDIVERT_IPHDR));
    char *udpPayload = packet.data() + sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_UDPHDR);

    // 2. 填充IP头部
    ipHeader->Version = 4;
    ipHeader->HdrLength = sizeof(WINDIVERT_IPHDR) / 4;
    ipHeader->TOS = 0;
    ipHeader->Length = htons(static_cast<uint16_t>(packetLen));
    ipHeader->Id = htons(0xDEAD); // 可以是随机值
    WINDIVERT_IPHDR_SET_FRAGOFF(ipHeader, 0);
    WINDIVERT_IPHDR_SET_DF(ipHeader, 1);
    ipHeader->TTL = 64;
    ipHeader->Protocol = IPPROTO_UDP;
    ipHeader->Checksum = 0; // 将由WinDivertHelperCalcChecksums计算
    inet_pton(AF_INET, spoofedIp.c_str(), &ipHeader->SrcAddr);
    inet_pton(AF_INET, destIp.c_str(), &ipHeader->DstAddr);

    // 3. 填充UDP头部
    udpHeader->SrcPort = htons(spoofedPort);
    udpHeader->DstPort = htons(destPort);
    udpHeader->Length = htons(sizeof(WINDIVERT_UDPHDR) + payloadLen);
    udpHeader->Checksum = 0; // 将由WinDivertHelperCalcChecksums计算

    // 4. 复制负载
    if (payload != nullptr && payloadLen > 0) {
        memcpy(udpPayload, payload, payloadLen);
    }

    // 5. 计算校验和
    WINDIVERT_ADDRESS addr;
    RtlZeroMemory(&addr, sizeof(addr));
    addr.Outbound = 0; // 标记为入站数据包
    addr.Network.IfIdx = ifIdx > 0 ? ifIdx : 0; // 使用传入的网络适配器索引,如果未指定则使用默认值
    addr.Impostor = 1;

    if (!WinDivertHelperCalcChecksums(packet.data(), packet.size(), &addr, WINDIVERT_HELPER_NO_ICMP_CHECKSUM | WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM |WINDIVERT_HELPER_NO_TCP_CHECKSUM)) {
        qDebug() << "计算校验和失败: " << GetLastError();
        return false;
    }

    // 6. 注入数据包
    if (!WinDivertSend(static_cast<HANDLE>(divertHandle_), packet.data(), packet.size(), nullptr, &addr)) {
        qDebug() << "WinDivertSend失败: " << GetLastError();
        return false;
    }

    return true;
}

bool UdpPacketInjector::sendSpoofedIPv6Packet(const std::string &spoofedIp, uint16_t spoofedPort, const std::string &destIp, uint16_t destPort, const char *payload,
                                             size_t payloadLen, int ifIdx) {
    // 1. 构造数据包缓冲区
    size_t packetLen = sizeof(WINDIVERT_IPV6HDR) + sizeof(WINDIVERT_UDPHDR) + payloadLen;
    std::vector<char> packet(packetLen);

    // 获取指向头部和负载的指针
    auto *ipv6Header = reinterpret_cast<PWINDIVERT_IPV6HDR>(packet.data());
    auto *udpHeader = reinterpret_cast<PWINDIVERT_UDPHDR>(packet.data() + sizeof(WINDIVERT_IPV6HDR));
    char *udpPayload = packet.data() + sizeof(WINDIVERT_IPV6HDR) + sizeof(WINDIVERT_UDPHDR);

    // 2. 填充IPv6头部
    ipv6Header->Version = 6;
    WINDIVERT_IPV6HDR_SET_TRAFFICCLASS(ipv6Header, 0);
    WINDIVERT_IPV6HDR_SET_FLOWLABEL(ipv6Header, 0);
    ipv6Header->Length = htons(static_cast<uint16_t>(sizeof(WINDIVERT_UDPHDR) + payloadLen));
    ipv6Header->NextHdr = IPPROTO_UDP;
    ipv6Header->HopLimit = 64;
    
    // 转换IPv6地址
    inet_pton(AF_INET6, spoofedIp.c_str(), ipv6Header->SrcAddr);
    inet_pton(AF_INET6, destIp.c_str(), ipv6Header->DstAddr);

    // 3. 填充UDP头部
    udpHeader->SrcPort = htons(spoofedPort);
    udpHeader->DstPort = htons(destPort);
    udpHeader->Length = htons(static_cast<uint16_t>(sizeof(WINDIVERT_UDPHDR) + payloadLen));
    udpHeader->Checksum = 0; // 将由WinDivertHelperCalcChecksums计算

    // 4. 复制负载
    if (payload != nullptr && payloadLen > 0) {
        memcpy(udpPayload, payload, payloadLen);
    }

    // 5. 计算校验和
    WINDIVERT_ADDRESS addr;
    RtlZeroMemory(&addr, sizeof(addr));
    addr.Outbound = 0; // 标记为入站数据包
    addr.Network.IfIdx = ifIdx > 0 ? ifIdx : 0; // 使用传入的网络适配器索引
    addr.Impostor = 1;

    if (!WinDivertHelperCalcChecksums(packet.data(), packet.size(), &addr, WINDIVERT_HELPER_NO_ICMP_CHECKSUM | WINDIVERT_HELPER_NO_ICMPV6_CHECKSUM | WINDIVERT_HELPER_NO_TCP_CHECKSUM)) {
        qDebug() << "计算校验和失败: " << GetLastError();
        return false;
    }

    // 6. 注入数据包
    if (!WinDivertSend(static_cast<HANDLE>(divertHandle_), packet.data(), packet.size(), nullptr, &addr)) {
        qDebug() << "WinDivertSend失败: " << GetLastError();
        return false;
    }

    return true;
}

} // namespace hasaki