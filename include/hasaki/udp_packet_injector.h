#pragma once

#include <string>
#include <cstdint>

namespace hasaki {

/**
 * @brief The UdpPacketInjector class provides functionality to create and inject spoofed UDP packets.
 *
 * This class uses the WinDivert library to send UDP packets with a specified source IP and port.
 * It is useful for scenarios where you need to simulate responses from a server or redirect traffic
 * in a network application. The class must be run with administrator privileges to open the
 * WinDivert handle.
 * 
 * Supports both IPv4 and IPv6 packets.
 */
class UdpPacketInjector {
public:
    UdpPacketInjector();
    ~UdpPacketInjector();

    // Disable copy and move semantics
    UdpPacketInjector(const UdpPacketInjector &) = delete;
    UdpPacketInjector &operator=(const UdpPacketInjector &) = delete;
    UdpPacketInjector(UdpPacketInjector &&) = delete;
    UdpPacketInjector &operator=(UdpPacketInjector &&) = delete;

    bool initialize();
    void shutdown();
    bool sendSpoofedPacket(const std::string &spoofedIp, uint16_t spoofedPort, const std::string &destIp, uint16_t destPort, const char *payload,
                           size_t payloadLen, int ifIdx = 0);

private:
    bool sendSpoofedIPv4Packet(const std::string &spoofedIp, uint16_t spoofedPort, const std::string &destIp, uint16_t destPort, const char *payload,
                               size_t payloadLen, int ifIdx);
    bool sendSpoofedIPv6Packet(const std::string &spoofedIp, uint16_t spoofedPort, const std::string &destIp, uint16_t destPort, const char *payload,
                               size_t payloadLen, int ifIdx);
    bool isIPv6Address(const std::string &ipAddress);
    void *divertHandle_ = nullptr;
};

} // namespace hasaki
