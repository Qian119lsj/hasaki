#include "hasaki/packet_forwarder.h"

#include "hasaki/utils.h"
#include "hasaki/mainwindow.h"

#include <QDebug>
#include <string>

#define BATCH_SIZE 64
#define PACKET_BUFFER_SIZE (BATCH_SIZE * 1500)

using namespace hasaki;
PacketForwarder::PacketForwarder() {
    endpointMapper_ = EndpointMapper::getInstance();
    enable_ipv6_ = true;
}

PacketForwarder::~PacketForwarder() { stop(); }

void PacketForwarder::setProxyServer(ProxyServer *proxyServer) { proxyServer_ = proxyServer; }
void PacketForwarder::setPortProcessMonitor(PortProcessMonitor *monitor) { portProcessMonitor_ = monitor; }

void PacketForwarder::setEnableIpv6(bool enable) {
    enable_ipv6_ = enable;
    qDebug() << "IPv6支持已" << (enable ? "启用" : "禁用");
}

bool PacketForwarder::start() {
    //  and !impostor
    net_handle_ = WinDivertOpen("outbound and (tcp or udp) and remotePort!=5353 and remotePort!=1900 and remotePort!=5355 and remotePort!=3702 and "
                                "remotePort!=137 and remotePort!=138 and remotePort!=67 and remotePort!=547 and (ip.DstAddr!=127.0.0.1 or ipv6.DstAddr!=::1)",
                                WINDIVERT_LAYER_NETWORK, 0, 0);
    if (net_handle_ == INVALID_HANDLE_VALUE) {
        DWORD lastError = GetLastError();
        qDebug() << "打开WinDivert句柄失败: " << lastError;
        if (lastError == ERROR_ACCESS_DENIED) {
            qDebug() << ">> 提示: 此应用程序必须以管理员身份运行。";
        } else if (lastError == ERROR_FILE_NOT_FOUND) {
            qDebug() << "未找到WinDivert驱动文件(WinDivert32.sys/WinDivert64.sys)或加载失败。";
        }
        return false;
    }

    net_thread_ = std::jthread([this](std::stop_token st) { this->net_thread_func(st); });
    qDebug() << "PacketForwarder started.";
    return true;
}

void PacketForwarder::stop() {
    if (net_thread_.joinable()) {
        net_thread_.request_stop();
        if (net_handle_ != INVALID_HANDLE_VALUE) {
            WinDivertClose(net_handle_);
            net_handle_ = INVALID_HANDLE_VALUE;
        }
        net_thread_.join();
    }
}

void PacketForwarder::net_thread_func(std::stop_token st) {
    uint16_t proxy_port = proxyServer_->getPort();
    UINT8 packetBuffer[PACKET_BUFFER_SIZE];
    UINT packetLen;
    WINDIVERT_ADDRESS addrBuffer[BATCH_SIZE];

    while (!st.stop_requested()) {
        UINT addrLen = sizeof(addrBuffer);
        if (!WinDivertRecvEx(net_handle_, packetBuffer, sizeof(packetBuffer), &packetLen, 0, addrBuffer, &addrLen, NULL)) {
            if (st.stop_requested()) {
                break;
            }
            DWORD error = GetLastError();
            if (error == ERROR_NO_DATA) {
                qDebug() << "Handle shutdown, no more data.";
                break; // 句柄被关闭且队列为空
            }
            if (error == ERROR_INSUFFICIENT_BUFFER) {
                qDebug() << "Warning: Insufficient buffer (" << packetLen << " bytes received). Processing what we got.";
            } else {
                qDebug() << "Error receiving packet batch: " << error;
                break;
            }
        }
        UINT8 protocol = 0; // 协议类型

        // WinDivertSendEx 需要的缓冲区和地址数组
        unsigned char send_packet_batch_buffer[PACKET_BUFFER_SIZE];
        WINDIVERT_ADDRESS send_addr_array[BATCH_SIZE];

        UINT length_of_packets_to_be_sent = 0;
        UINT num_of_packets_to_be_sent = 0;

        PVOID packet_addr = packetBuffer;
        UINT remaining_packets_length = packetLen;

        UINT8 num_of_total_packets = addrLen / sizeof(WINDIVERT_ADDRESS);
        UINT index = 0; // 当前处理的数据包索引
        while (true) {

            // 解析数据包
            PWINDIVERT_IPHDR ipHdr = nullptr;
            PWINDIVERT_IPV6HDR ipv6Hdr = nullptr;
            PWINDIVERT_TCPHDR tcpHdr = nullptr;
            PWINDIVERT_UDPHDR udpHdr = nullptr;

            char *packet_data = nullptr; // udp有效载荷
            UINT packet_data_len = 0;    // udp有效载荷长度

            if (remaining_packets_length == 0) {
                break;
            }
            PVOID pStartOfCurrentPacket = packet_addr;
            UINT lenBeforeParse = remaining_packets_length;

            if (!WinDivertHelperParsePacket(packet_addr, remaining_packets_length, &ipHdr, &ipv6Hdr, &protocol, NULL, NULL, &tcpHdr, &udpHdr,
                                            (PVOID *)&packet_data, &packet_data_len, &packet_addr, &remaining_packets_length)) {
                qDebug() << "WinDivertHelperParsePacket failed, remaining " << remaining_packets_length << " bytes";
                break;
            }

            if (index >= num_of_total_packets) {
                qDebug() << "错误: 解析出的数据包数量超过了 RecvEx 报告的地址数量。";
                break;
            }
            WINDIVERT_ADDRESS addr = addrBuffer[index++];

            std::string srcAddrString;
            std::string dstAddrString;

            if (ipHdr != nullptr) {
                srcAddrString = Utils::FormatIpv4Address(ipHdr->SrcAddr);
                dstAddrString = Utils::FormatIpv4Address(ipHdr->DstAddr);
            } else if (ipv6Hdr != nullptr) {
                srcAddrString = Utils::FormatIpv6Address(ipv6Hdr->SrcAddr);
                dstAddrString = Utils::FormatIpv6Address(ipv6Hdr->DstAddr);
            }

            UINT packet_data_len_to_send = lenBeforeParse - remaining_packets_length; // 当前数据包长度=解析前剩余长度-解析后剩余长度
            if (tcpHdr != nullptr) {
                UINT16 srcPort = WinDivertHelperNtohs(tcpHdr->SrcPort);
                UINT16 dstPort = WinDivertHelperNtohs(tcpHdr->DstPort);
                if ((srcPort < 1024 || dstPort < 1024) && (dstPort != 22 & dstPort != 53 && dstPort != 443 && dstPort != 80 && dstPort != 123)) {
                    qDebug() << "addr.Impostor: " << addr.Impostor << "; src: " << srcAddrString << ":" << srcPort << " -> dst: " << dstAddrString << ":"
                             << dstPort;
                }

                if (addr.IPv6 == 1) {
                    if (srcPort == proxy_port) {
                        // 代理程序返回给客户端的数据 (IPv6)
                        std::string tcpTupleKey = endpointMapper_->createIpv6EndpointKey(dstAddrString, dstPort); // KEY: 原目标地址+伪端口

                        Ipv6EndpointPair tcpTuple;
                        if (endpointMapper_->findIpv6TcpMapping(tcpTupleKey, tcpTuple)) {
                            // 找到映射，修改数据包
                            memcpy(ipv6Hdr->SrcAddr, tcpTuple.dstAddr, 16);
                            tcpHdr->SrcPort = tcpTuple.dstPort;
                            memcpy(ipv6Hdr->DstAddr, tcpTuple.srcAddr, 16);
                            tcpHdr->DstPort = tcpTuple.srcPort;
                            addr.Outbound = FALSE;
                            WinDivertHelperCalcChecksums(pStartOfCurrentPacket, packet_data_len_to_send, &addr, 0);
                        } else {
                            qDebug() << "tcpTupleKey: " << tcpTupleKey << " 未找到活动映射";
                            // 丢弃包
                            continue;
                        }
                    } else {
                        // 客户端出方向数据包 (IPv6)
                        if (portProcessMonitor_ != nullptr && portProcessMonitor_->isPortInTargetProcess(srcPort, nullptr)) {

                            if (enable_ipv6_ == false) {
                                continue;
                            }

                            // 获取或创建映射
                            uint16_t pseudoPort = endpointMapper_->getOrCreateIpv6TcpMapping((const UINT8 *)ipv6Hdr->SrcAddr, tcpHdr->SrcPort,
                                                                                             (const UINT8 *)ipv6Hdr->DstAddr, tcpHdr->DstPort);

                            // 转发到代理服务器
                            UINT8 srcAddr[16];
                            memcpy(srcAddr, ipv6Hdr->SrcAddr, 16);
                            memcpy(ipv6Hdr->SrcAddr, ipv6Hdr->DstAddr, 16);
                            tcpHdr->SrcPort = WinDivertHelperHtons(pseudoPort);
                            memcpy(ipv6Hdr->DstAddr, srcAddr, 16);
                            tcpHdr->DstPort = WinDivertHelperHtons(proxy_port);
                            addr.Outbound = FALSE;
                            WinDivertHelperCalcChecksums(pStartOfCurrentPacket, packet_data_len_to_send, &addr, 0);
                        }
                    }
                } else {
                    if (srcPort == proxy_port) {
                        // 代理程序返回给客户端的数据
                        std::string tcpTupleKey = endpointMapper_->createIpv4EndpointKey(dstAddrString, dstPort); // KEY: 原目标地址+伪端口

                        Ipv4EndpointPair tcpTuple;
                        if (endpointMapper_->findIpv4TcpMapping(tcpTupleKey, tcpTuple)) {
                            // 找到映射，修改数据包
                            ipHdr->SrcAddr = tcpTuple.dstAddr;
                            tcpHdr->SrcPort = tcpTuple.dstPort;
                            ipHdr->DstAddr = tcpTuple.srcAddr;
                            tcpHdr->DstPort = tcpTuple.srcPort;
                            addr.Outbound = FALSE;
                            WinDivertHelperCalcChecksums(pStartOfCurrentPacket, packet_data_len_to_send, &addr, 0);
                        } else {
                            qDebug() << "tcpTupleKey: " << tcpTupleKey << " 未找到活动映射";
                            // 丢弃包
                            continue;
                        }
                    } else {
                        // 客户端出方向数据包
                        if (portProcessMonitor_ != nullptr && portProcessMonitor_->isPortInTargetProcess(srcPort, nullptr)) {
                            // 获取或创建映射
                            uint16_t pseudoPort = endpointMapper_->getOrCreateIpv4TcpMapping(ipHdr->SrcAddr, tcpHdr->SrcPort, ipHdr->DstAddr, tcpHdr->DstPort);

                            // 转发到代理服务器
                            UINT32 srcAddr = ipHdr->SrcAddr;
                            ipHdr->SrcAddr = ipHdr->DstAddr;
                            tcpHdr->SrcPort = WinDivertHelperHtons(pseudoPort);
                            ipHdr->DstAddr = srcAddr;
                            tcpHdr->DstPort = WinDivertHelperHtons(proxy_port);
                            addr.Outbound = FALSE;
                            WinDivertHelperCalcChecksums(pStartOfCurrentPacket, packet_data_len_to_send, &addr, 0);
                        }
                    }
                }
            }
            if (udpHdr != nullptr) {
                UINT16 srcPort = WinDivertHelperNtohs(udpHdr->SrcPort);
                UINT16 dstPort = WinDivertHelperNtohs(udpHdr->DstPort);

                if ((srcPort < 1024 || dstPort < 1024) && (dstPort != 53 && dstPort != 443 && dstPort != 80 && dstPort != 123)) {
                    qDebug() << "addr.Impostor: " << addr.Impostor << "; src: " << srcAddrString << ":" << srcPort << " -> dst: " << dstAddrString << ":"
                             << dstPort;
                }
                std::string process_name;
                if (dstPort == 53) {
                    if (enable_ipv6_ == false && addr.IPv6 == 1) {
                        continue;
                    }
                    proxyServer_->handleUdpPacket(packet_data, packet_data_len, srcAddrString, srcPort, dstAddrString, dstPort, addr.IPv6, process_name);
                    continue;
                }
                if (portProcessMonitor_ != nullptr && portProcessMonitor_->isPortInTargetProcess(srcPort, &process_name)) {
                    if (enable_ipv6_ == false && addr.IPv6 == 1) {
                        continue;
                    }
                    bool handled =
                        proxyServer_->handleUdpPacket(packet_data, packet_data_len, srcAddrString, srcPort, dstAddrString, dstPort, addr.IPv6, process_name);
                    if (!handled) {
                        qDebug() << "UDP 数据包未处理";
                    }
                    continue;
                }
            }

            if (num_of_packets_to_be_sent < num_of_total_packets &&                                                              // 数据包数量还没满
                (length_of_packets_to_be_sent + packet_data_len_to_send) <= sizeof(send_packet_batch_buffer)) {                  // 缓冲区够用
                memcpy(send_packet_batch_buffer + length_of_packets_to_be_sent, pStartOfCurrentPacket, packet_data_len_to_send); // 拷贝包
                length_of_packets_to_be_sent += packet_data_len_to_send;                                                         // 更新数据包长度
                send_addr_array[num_of_packets_to_be_sent] = addr; // 将当前数据包地址添加到地址数组
                num_of_packets_to_be_sent++;                       // 更新数据包数量
            } else {
                qDebug() << "警告: 发送批处理缓冲区已满或单个数据包过大 (" << packet_data_len_to_send << " bytes)，数据包 " << index
                         << " 未添加到当前发送批次。";
            }
        }

        if (remaining_packets_length > 0) {
            qDebug() << "警告: 在解析完 " << index << " 个数据包后，批处理中仍有 " << remaining_packets_length << " 字节数据剩余。";
        }

        if (num_of_packets_to_be_sent > 0) {
            if (!WinDivertSendEx(net_handle_, send_packet_batch_buffer, length_of_packets_to_be_sent, NULL, 0, send_addr_array,
                                 num_of_packets_to_be_sent * sizeof(WINDIVERT_ADDRESS), NULL)) {
                if (st.stop_requested()) {
                    break;
                }
                qDebug() << "警告: WinDivertSendEx 失败: " << GetLastError();
            }
        }
    }
    qDebug() << "Network listener thread stopped.";
}