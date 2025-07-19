#include "hasaki/packet_forwarder.h"

#include "hasaki/utils.h"
#include "hasaki/mainwindow.h"

#include <QDebug>

#define BATCH_SIZE 64
#define PACKET_BUFFER_SIZE (BATCH_SIZE * 1500)

PacketForwarder::PacketForwarder() { 
    endpointMapper_ = EndpointMapper::getInstance(); 
}

PacketForwarder::~PacketForwarder() { stop(); }

void PacketForwarder::setSocks5Server(const std::string &addr, uint16_t port) {
    socks5_address_ = addr;
    socks5_port_ = port;
}

void PacketForwarder::setProxyPort(uint16_t port) { proxy_port_ = port; }

void PacketForwarder::setSocks5UdpRelay(const std::string &addr, uint16_t port) {
    socks5_udp_relay_addr_ = addr;
    socks5_udp_relay_port_ = port;
    
    // 设置UDP会话管理器的SOCKS5 UDP中继地址和端口
    udp_session_manager_.setSocks5UdpRelay(addr, port);
    
    // 如果有MainWindow，设置接口映射表
    if (mainWindow_) {
        const QMap<QString, int>& adapterIpMap = mainWindow_->getAdapterIpMap();
        hasaki::UdpSessionManager::InterfaceMap ifMap;
        
        for (auto it = adapterIpMap.begin(); it != adapterIpMap.end(); ++it) {
            ifMap[it.key().toStdString()] = it.value();
        }
        
        udp_session_manager_.setInterfaceMap(ifMap);
    }
}

bool PacketForwarder::start() {
    // Seed for random port generation
    srand(time(NULL));
    
    // 初始化UDP会话管理器
    if (!udp_session_manager_.initialize()) {
        qDebug() << "初始化UDP会话管理器失败";
        return false;
    }

    net_handle_ = WinDivertOpen("outbound and (tcp or udp) and !impostor and ip.DstAddr!=127.0.0.1 and ip.DstAddr!=::1", WINDIVERT_LAYER_NETWORK, 0, 0);
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

    // 关闭UDP会话管理器
    udp_session_manager_.shutdown();

    // 清理所有映射
    if (endpointMapper_ != nullptr) {
        endpointMapper_->clearAllMappings();
    }
}

void PacketForwarder::setPortProcessMonitor(PortProcessMonitor *monitor) { portProcessMonitor_ = monitor; }

void PacketForwarder::net_thread_func(std::stop_token st) {
    UINT8 packetBuffer[PACKET_BUFFER_SIZE];
    UINT packetLen;
    WINDIVERT_ADDRESS addrBuffer[BATCH_SIZE];

    // WinDivertSendEx 需要的缓冲区和地址数组
    unsigned char send_packet_batch_buffer[PACKET_BUFFER_SIZE];
    WINDIVERT_ADDRESS send_addr_array[BATCH_SIZE];

    qDebug() << "Network listener thread started.";

    UINT send_total_packet_data_len;
    UINT send_num_packets_in_batch;

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
        UINT8 packetsReceived = addrLen / sizeof(WINDIVERT_ADDRESS);
        PWINDIVERT_IPHDR ipHdr = NULL;
        PWINDIVERT_IPV6HDR ipv6Hdr = NULL;
        PWINDIVERT_TCPHDR tcpHdr = NULL;
        PWINDIVERT_UDPHDR udpHdr = NULL;
        UINT8 protocol = 0;
        UINT addrIndex = 0;
        send_total_packet_data_len = 0;
        send_num_packets_in_batch = 0;

        PVOID pCurrentPacketInBatch = packetBuffer;
        UINT currentRemainingLenInBatch = packetLen;

        while (WinDivertHelperParsePacket(pCurrentPacketInBatch, currentRemainingLenInBatch, &ipHdr, &ipv6Hdr, &protocol, NULL, NULL, &tcpHdr, &udpHdr, NULL,
                                          NULL, &pCurrentPacketInBatch, &currentRemainingLenInBatch)) {
            if (addrIndex >= packetsReceived) {
                qDebug() << "错误: 解析出的数据包数量超过了 RecvEx 报告的地址数量。";
                break;
            }
            WINDIVERT_ADDRESS addr = addrBuffer[addrIndex++];
            PVOID packet_data_to_send = NULL;
            UINT packet_data_len_to_send = 0;

            std::string srcAddrString;
            std::string dstAddrString;

            if (ipHdr != NULL) {
                packet_data_to_send = (PVOID)ipHdr;
                packet_data_len_to_send = WinDivertHelperNtohs(ipHdr->Length);
                srcAddrString = FormatIpv4Address(ipHdr->SrcAddr);
                dstAddrString = FormatIpv4Address(ipHdr->DstAddr);
            } else if (ipv6Hdr != NULL) {
                packet_data_to_send = (PVOID)ipv6Hdr;
                packet_data_len_to_send = sizeof(WINDIVERT_IPV6HDR) + WinDivertHelperNtohs(ipv6Hdr->Length);
                srcAddrString = FormatIpv6Address(ipv6Hdr->SrcAddr);
                dstAddrString = FormatIpv6Address(ipv6Hdr->DstAddr);
            }

            if (tcpHdr != NULL) {
                UINT16 srcPort = WinDivertHelperNtohs(tcpHdr->SrcPort);
                UINT16 dstPort = WinDivertHelperNtohs(tcpHdr->DstPort);
                if (addr.IPv6 == 1) {
                    if (srcPort == proxy_port_) {
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
                            WinDivertHelperCalcChecksums(packet_data_to_send, packet_data_len_to_send, &addr, 0);
                        } else {
                            qDebug() << "tcpTupleKey: " << tcpTupleKey << " 未找到活动映射";
                            // 丢弃包
                            continue;
                        }
                    } else {
                        // 客户端出方向数据包 (IPv6)
                        if (portProcessMonitor_ != nullptr && portProcessMonitor_->isPortInTargetProcess(srcPort)) {
                            // 获取或创建映射
                            uint16_t pseudoPort = endpointMapper_->getOrCreateIpv6TcpMapping((const UINT8 *)ipv6Hdr->SrcAddr, tcpHdr->SrcPort,
                                                                                             (const UINT8 *)ipv6Hdr->DstAddr, tcpHdr->DstPort);

                            // 转发到代理服务器
                            UINT8 srcAddr[16];
                            memcpy(srcAddr, ipv6Hdr->SrcAddr, 16);
                            memcpy(ipv6Hdr->SrcAddr, ipv6Hdr->DstAddr, 16);
                            tcpHdr->SrcPort = WinDivertHelperHtons(pseudoPort);
                            memcpy(ipv6Hdr->DstAddr, srcAddr, 16);
                            tcpHdr->DstPort = WinDivertHelperHtons(proxy_port_);
                            addr.Outbound = FALSE;
                            WinDivertHelperCalcChecksums(packet_data_to_send, packet_data_len_to_send, &addr, 0);
                        }
                    }
                } else {
                    if (srcPort == proxy_port_) {
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
                            WinDivertHelperCalcChecksums(packet_data_to_send, packet_data_len_to_send, &addr, 0);
                        } else {
                            qDebug() << "tcpTupleKey: " << tcpTupleKey << " 未找到活动映射";
                            // 丢弃包
                            continue;
                        }
                    } else {
                        // 客户端出方向数据包
                        if (portProcessMonitor_ != nullptr && portProcessMonitor_->isPortInTargetProcess(srcPort)) {
                            // 获取或创建映射
                            uint16_t pseudoPort = endpointMapper_->getOrCreateIpv4TcpMapping(ipHdr->SrcAddr, tcpHdr->SrcPort, ipHdr->DstAddr, tcpHdr->DstPort);

                            // 转发到代理服务器
                            UINT32 srcAddr = ipHdr->SrcAddr;
                            ipHdr->SrcAddr = ipHdr->DstAddr;
                            tcpHdr->SrcPort = WinDivertHelperHtons(pseudoPort);
                            ipHdr->DstAddr = srcAddr;
                            tcpHdr->DstPort = WinDivertHelperHtons(proxy_port_);
                            addr.Outbound = FALSE;
                            WinDivertHelperCalcChecksums(packet_data_to_send, packet_data_len_to_send, &addr, 0);
                        }
                    }
                }
            }
            if (udpHdr != NULL) {
                UINT16 srcPort = WinDivertHelperNtohs(udpHdr->SrcPort);
                UINT16 dstPort = WinDivertHelperNtohs(udpHdr->DstPort);

                if (addr.IPv6 == 1) {
                    // 客户端发出的UDP包 (IPv6)
                    if (portProcessMonitor_ != nullptr && portProcessMonitor_->isPortInTargetProcess(srcPort)) {
                        // 暂时不处理53端口
                        if (dstPort != 53) {
                            // 使用UDP会话管理器处理IPv6 UDP数据包
                            bool handled = udp_session_manager_.handleUdpPacket(
                                (const char*)((const UINT8*)ipv6Hdr + sizeof(WINDIVERT_IPV6HDR) + sizeof(WINDIVERT_UDPHDR)),
                                packet_data_len_to_send - sizeof(WINDIVERT_IPV6HDR) - sizeof(WINDIVERT_UDPHDR),
                                srcAddrString, srcPort, dstAddrString, dstPort,
                                true, 0);
                            
                            if (handled) {
                                // 数据包已处理，不需要继续发送
                                continue;
                            }
                        }
                    }
                } else {
                    // 客户端发出的UDP包 (IPv4)
                    // 暂时不处理53端口
                    if (dstPort != 53) {
                        if (portProcessMonitor_ != nullptr && portProcessMonitor_->isPortInTargetProcess(srcPort)) {
                            // 使用UDP会话管理器处理IPv4 UDP数据包
                            bool handled = udp_session_manager_.handleUdpPacket(
                                (const char*)((const UINT8*)ipHdr + ipHdr->HdrLength * 4 + sizeof(WINDIVERT_UDPHDR)),
                                packet_data_len_to_send - ipHdr->HdrLength * 4 - sizeof(WINDIVERT_UDPHDR),
                                srcAddrString, srcPort, dstAddrString, dstPort,
                                false, 0);
                            
                            if (handled) {
                                // 数据包已处理，不需要继续发送
                                continue;
                            }
                        }
                    }
                }
            }
            if (send_num_packets_in_batch < packetsReceived && (send_total_packet_data_len + packet_data_len_to_send) <= sizeof(send_packet_batch_buffer)) {
                memcpy(send_packet_batch_buffer + send_total_packet_data_len, packet_data_to_send, packet_data_len_to_send);
                send_total_packet_data_len += packet_data_len_to_send;
                send_addr_array[send_num_packets_in_batch] = addr;
                send_num_packets_in_batch++;
            } else {
                qDebug() << "警告: 发送批处理缓冲区已满或单个数据包过大 (" << packet_data_len_to_send << " bytes)，数据包 " << addrIndex
                         << " 未添加到当前发送批次。";
            }
        }

        if (currentRemainingLenInBatch > 0 && addrIndex < packetsReceived) {
            qDebug() << "警告: 在解析完 " << addrIndex << " 个数据包后，批处理中仍有 " << currentRemainingLenInBatch << " 字节数据剩余。";
        }

        if (send_num_packets_in_batch > 0) {
            if (!WinDivertSendEx(net_handle_, send_packet_batch_buffer, send_total_packet_data_len, NULL, 0, send_addr_array,
                                 send_num_packets_in_batch * sizeof(WINDIVERT_ADDRESS), NULL)) {
                if (st.stop_requested()) {
                    break;
                }
                qDebug() << "警告: WinDivertSendEx 失败: " << GetLastError();
            }
        }
    }
    qDebug() << "Network listener thread stopped.";
}