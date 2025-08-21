#include "hasaki/proxy_server.h"

#include <QDebug>
#include <WinSock2.h>
#include <minwindef.h>
#include <qdebug.h>
#include <qlogging.h>
#include "hasaki/mainwindow.h"
#include "hasaki/udp_session_manager.h"
#include "hasaki/socks5_client.h"
#include "hasaki/tcp_session_manager.h"

#pragma comment(lib, "ws2_32.lib")

ProxyServer::ProxyServer(EndpointMapper *endpoint_mapper)
    : endpoint_mapper_(endpoint_mapper), is_running_(false), iocp_handle_(nullptr), tcp_listen_socket_(INVALID_SOCKET), socks5_control_socket_(INVALID_SOCKET),
      lpfn_acceptex_(nullptr) {
    // 使用UdpSessionManager单例
    udp_session_manager_ = hasaki::UdpSessionManager::getInstance();
    tcp_session_manager_ = hasaki::TcpSessionManager::getInstance();
}

ProxyServer::~ProxyServer() { stop(); }

void ProxyServer::setSocks5Server(const std::string &address, uint16_t port) {
    socks5_address_ = address;
    socks5_port_ = port;
    qDebug() << "SOCKS5服务器设置为: " << QString::fromStdString(address) << ":" << port;
}

void ProxyServer::setAdapterIpMap(const QMap<QString, int> &adapter_ip_map) { adapter_ip_map_ = adapter_ip_map; }

void ProxyServer::setUdpPacketInjector(hasaki::UdpPacketInjector *udp_packet_injector) { udp_packet_injector_ = udp_packet_injector; }

bool ProxyServer::start(uint16_t port, uint16_t worker_threads) {

    udp_session_manager_->start();

    if (socks5_address_.empty() || socks5_port_ == 0) {
        qDebug() << "错误: 未设置SOCKS5服务器地址和端口";
        return false;
    }

    port_ = port;

    if (is_running_) {
        return true;
    }

    // 初始化Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        qDebug() << "WSAStartup失败";
        return false;
    }

    // 创建IOCP
    iocp_handle_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
    if (iocp_handle_ == nullptr) {
        qDebug() << "创建IOCP失败: " << GetLastError();
        WSACleanup();
        return false;
    }

    // 创建监听套接字
    tcp_listen_socket_ = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (tcp_listen_socket_ == INVALID_SOCKET) {
        qDebug() << "创建监听套接字失败: " << WSAGetLastError();
        CloseHandle(iocp_handle_);
        WSACleanup();
        return false;
    }

    DWORD dwV6Only = 0;
    if (setsockopt(tcp_listen_socket_, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&dwV6Only, sizeof(dwV6Only)) != 0) {
        qDebug() << "setsockopt IPV6_V6ONLY 失败: " << WSAGetLastError();
        closesocket(tcp_listen_socket_);
        CloseHandle(iocp_handle_);
        WSACleanup();
        return false;
    }

    BOOL bReuseAddr = TRUE;
    if (setsockopt(tcp_listen_socket_, SOL_SOCKET, SO_REUSEADDR, (char *)&bReuseAddr, sizeof(bReuseAddr)) == SOCKET_ERROR) {
        qDebug() << "setsockopt SO_REUSEADDR 失败: " << WSAGetLastError();
        closesocket(tcp_listen_socket_);
        CloseHandle(iocp_handle_);
        WSACleanup();
        return false;
    }

    // 绑定地址
    sockaddr_in6 server_addr;
    memset(&server_addr, 0, sizeof(server_addr)); // 清零结构体
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any;
    server_addr.sin6_port = htons(port_);

    if (bind(tcp_listen_socket_, (SOCKADDR *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        qDebug() << "绑定套接字失败: " << WSAGetLastError();
        closesocket(tcp_listen_socket_);
        CloseHandle(iocp_handle_);
        WSACleanup();
        return false;
    }

    // 开始监听
    if (listen(tcp_listen_socket_, SOMAXCONN) == SOCKET_ERROR) {
        qDebug() << "监听失败: " << WSAGetLastError();
        closesocket(tcp_listen_socket_);
        CloseHandle(iocp_handle_);
        WSACleanup();
        return false;
    }

    // 请求SOCKS5 UDP关联
    socks5_control_socket_ = Socks5Client::associateUdp(socks5_address_, socks5_port_, "0.0.0.0", 0, socks5_udp_relay_addr_, socks5_udp_relay_port_);
    if (socks5_control_socket_ == INVALID_SOCKET) {
        qDebug() << "SOCKS5 UDP关联失败";
        CloseHandle(iocp_handle_);
        WSACleanup();
        return false;
    }

    // 加载AcceptEx函数
    GUID guidAcceptEx = WSAID_ACCEPTEX;
    DWORD dwBytes = 0;
    if (WSAIoctl(tcp_listen_socket_, SIO_GET_EXTENSION_FUNCTION_POINTER, &guidAcceptEx, sizeof(guidAcceptEx), &lpfn_acceptex_, sizeof(lpfn_acceptex_), &dwBytes,
                 nullptr, nullptr) == SOCKET_ERROR) {
        qDebug() << "加载AcceptEx失败: " << WSAGetLastError();
        closesocket(tcp_listen_socket_);
        CloseHandle(iocp_handle_);
        WSACleanup();
        return false;
    }

    // 将监听套接字关联到IOCP
    if (CreateIoCompletionPort((HANDLE)tcp_listen_socket_, iocp_handle_, 0, 0) == nullptr) {
        qDebug() << "关联监听套接字到IOCP失败: " << GetLastError();
        closesocket(tcp_listen_socket_);
        CloseHandle(iocp_handle_);
        WSACleanup();
        return false;
    }

    // 启动工作线程
    is_running_ = true;
    for (uint16_t i = 0; i < worker_threads; ++i) {
        worker_threads_.emplace_back(&ProxyServer::worker_thread_func, this);
    }

    // 发布初始接受请求
    for (uint16_t i = 0; i < worker_threads * 2; ++i) {
        post_tcp_accept(tcp_listen_socket_, new PerIOContext());
    }

    qDebug() << "代理服务器已启动，监听端口: " << port;
    return true;
}

void ProxyServer::stop() {
    if (!is_running_) {
        return;
    }

    is_running_ = false;

    // 通知工作线程退出
    if (iocp_handle_ != nullptr) {
        for (size_t i = 0; i < worker_threads_.size(); ++i) {
            PerIOContext *io_context = new PerIOContext();
            io_context->operation = OP_EXIT;
            PostQueuedCompletionStatus(iocp_handle_, 0, 0, (LPOVERLAPPED)io_context);
        }

        // 等待工作线程退出
        for (auto &thread : worker_threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        worker_threads_.clear();

        CloseHandle(iocp_handle_);
        iocp_handle_ = nullptr;
    }

    // 关闭监听套接字
    if (tcp_listen_socket_ != INVALID_SOCKET) {
        closesocket(tcp_listen_socket_);
        tcp_listen_socket_ = INVALID_SOCKET;
    }

    // 关闭SOCKS5控制套接字
    if (socks5_control_socket_ != INVALID_SOCKET) {
        closesocket(socks5_control_socket_);
        socks5_control_socket_ = INVALID_SOCKET;
    }

    tcp_session_manager_->clearAllSessions();
    udp_session_manager_->shutdown();

    WSACleanup();
    qDebug() << "代理服务器已停止";
}

void ProxyServer::worker_thread_func() {
    ULONG_PTR completion_key = 0;
    while (is_running_) {
        DWORD bytes_transferred = 0;
        PerIOContext *io_context = nullptr;
        if (!GetQueuedCompletionStatus(iocp_handle_, &bytes_transferred, &completion_key, (LPOVERLAPPED *)&io_context, INFINITE)) {
            DWORD dwError = GetLastError();
            if (io_context == nullptr) {
                if (dwError == ERROR_ABANDONED_WAIT_0 || dwError == ERROR_INVALID_HANDLE) {
                    qDebug() << "IOCP句柄已关闭，工作线程退出";
                    break;
                }
                qDebug() << "GetQueuedCompletionStatus失败，无重叠结构, 错误码: " << dwError;
                continue;
            } else {
                std::shared_ptr<hasaki::UdpSession> udp_session = std::move(io_context->udp_session);

                if (dwError == ERROR_CONNECTION_ABORTED &&
                    (io_context->operation == IO_RECV_TCP || io_context->operation == IO_RECV_UDP)) { // The network connection was aborted by the local system
                } else if (dwError == 121) {                                                          // ERROR_SEM_TIMEOUT
                    qDebug() << "超时121. socket:" << io_context->socket << "socket_type:" << io_context->socket_type << "operation:" << io_context->operation
                             << "mapper_key:" << io_context->tcp_session->mapper_key_;
                } else {
                    if (dwError != 995) {
                        qDebug() << "GetQueuedCompletionStatus 失败，错误码：" << dwError << ",operation" << io_context->operation;
                    }
                }

                if (io_context->operation == IO_RECV_TCP || io_context->operation == IO_SEND_TCP) { // tcp
                    tcp_session_manager_->removeSession(io_context->tcp_session->mapper_key_);
                    delete io_context;
                } else if (io_context->operation == IO_ACCEPT) {
                    delete io_context;
                    qDebug() << "GetQueuedCompletionStatus IO_ACCEPT失败, post_tcp_accept";
                    if (is_running_) {
                        post_tcp_accept(tcp_listen_socket_, new PerIOContext());
                    }
                }
            }
        } else {
            if (io_context->operation == OP_EXIT) {
                delete io_context;
                break;
            }

            std::shared_ptr<hasaki::UdpSession> udp_session = std::move(io_context->udp_session);

            if (!is_running_ || (bytes_transferred == 0 && io_context->operation != IO_ACCEPT)) {

                if (io_context->operation == IO_RECV_TCP || io_context->operation == IO_SEND_TCP) { // tcp
                    tcp_session_manager_->removeSession(io_context->tcp_session->mapper_key_);
                    delete io_context;
                }
                continue;
            }

            switch (io_context->operation) {
            case IO_ACCEPT:
                handle_tcp_accept(io_context);
                break;

            case IO_RECV_TCP:
                handle_tcp_receive(io_context, bytes_transferred);
                break;

            case IO_SEND_TCP:
                handle_tcp_send(io_context, bytes_transferred);
                break;

            case IO_RECV_UDP:
                handle_udp_receive(udp_session, bytes_transferred);
                break;

            case IO_SEND_UDP:
                handle_udp_send(io_context, bytes_transferred);
                break;

            default:
                qDebug() << "Unknown operation: " << io_context->operation;
                delete io_context;
                break;
            }
        }
    }
    qDebug() << "工作线程已退出";
}

bool ProxyServer::handle_tcp_accept(PerIOContext *io_context) {
    SOCKET client_socket = io_context->socket;

    // 更新套接字上下文
    if (setsockopt(client_socket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&tcp_listen_socket_, sizeof(tcp_listen_socket_)) != 0) {
        qDebug() << "SO_UPDATE_ACCEPT_CONTEXT 失败: " << WSAGetLastError();
        closesocket(client_socket);
        delete io_context;
        if (is_running_) {
            post_tcp_accept(tcp_listen_socket_, new PerIOContext());
        }
        return false;
    }

    // 获取连接的目标地址和端口
    std::string target_addr;
    uint16_t target_port;
    std::string mapper_key;
    MappingType mapping_type;
    if (!get_tcp_connection_target(client_socket, target_addr, target_port, mapper_key, mapping_type)) {
        qDebug() << "无法获取连接目标";
        closesocket(client_socket);
        delete io_context;
        if (is_running_) {
            post_tcp_accept(tcp_listen_socket_, new PerIOContext());
        }
        return false;
    }

    // 通过SOCKS5代理连接到目标
    SOCKET target_socket = Socks5Client::connectTarget(socks5_address_, socks5_port_, target_addr, target_port);

    if (target_socket == INVALID_SOCKET) {
        qDebug() << "无法通过SOCKS5连接到目标: " << QString::fromStdString(target_addr) << ":" << target_port;
        closesocket(client_socket);
        delete io_context;
        if (is_running_) {
            post_tcp_accept(tcp_listen_socket_, new PerIOContext());
        }
        return false;
    }

    // 将新接受的客户端套接字关联到IOCP
    if (CreateIoCompletionPort((HANDLE)client_socket, iocp_handle_, 0, 0) == nullptr) {
        qDebug() << "关联客户端套接字到IOCP失败: " << GetLastError();
        closesocket(client_socket);
        closesocket(target_socket);
        delete io_context;
        if (is_running_) {
            post_tcp_accept(tcp_listen_socket_, new PerIOContext());
        }
        return false;
    }

    // 将目标套接字关联到IOCP
    if (CreateIoCompletionPort((HANDLE)target_socket, iocp_handle_, 0, 0) == nullptr) {
        qDebug() << "关联目标套接字到IOCP失败: " << GetLastError();
        closesocket(client_socket);
        closesocket(target_socket);
        delete io_context;
        if (is_running_) {
            post_tcp_accept(tcp_listen_socket_, new PerIOContext());
        }
        return false;
    }

    // Accept操作的上下文已经完成其使命，可以释放
    delete io_context;

    // 创建会话
    auto tcp_session = tcp_session_manager_->createSession(client_socket, target_socket, mapper_key, mapping_type);

    // 为客户端套接字创建新的IO上下文用于接收
    PerIOContext *client_io_context = new PerIOContext();
    client_io_context->socket = client_socket;
    client_io_context->operation = IO_RECV_TCP;
    client_io_context->tcp_session = tcp_session;
    client_io_context->socket_type = CLIENT_SOCKET;

    // 为目标套接字创建新的IO上下文用于接收
    PerIOContext *target_io_context = new PerIOContext();
    target_io_context->socket = target_socket;
    target_io_context->operation = IO_RECV_TCP;
    target_io_context->tcp_session = tcp_session;
    target_io_context->socket_type = TARGET_SOCKET;

    // 为两个方向都投递接收请求
    DWORD flags = 0;
    if (WSARecv(client_io_context->socket, &client_io_context->wsa_buf, 1, nullptr, &flags, &client_io_context->overlapped, nullptr) == SOCKET_ERROR) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            qDebug() << "为客户端投递WSARecv失败: " << WSAGetLastError();
            delete client_io_context;
            delete target_io_context;
            tcp_session_manager_->removeSession(mapper_key);
            if (is_running_) {
                post_tcp_accept(tcp_listen_socket_, new PerIOContext());
            }
            return false;
        }
    }

    if (WSARecv(target_io_context->socket, &target_io_context->wsa_buf, 1, nullptr, &flags, &target_io_context->overlapped, nullptr) == SOCKET_ERROR) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            qDebug() << "为目标投递WSARecv失败: " << WSAGetLastError();
            tcp_session_manager_->removeSession(mapper_key);
            delete target_io_context;
            if (is_running_) {
                post_tcp_accept(tcp_listen_socket_, new PerIOContext());
            }
            return false;
        }
    }

    // 重新发布一个Accept请求
    if (is_running_) {
        post_tcp_accept(tcp_listen_socket_, new PerIOContext());
    }

    return true;
}

bool ProxyServer::handle_tcp_receive(PerIOContext *io_context, DWORD bytes_transferred) {
    auto tcp_session = io_context->tcp_session;
    SOCKET peer_socket = (io_context->socket_type == CLIENT_SOCKET) ? tcp_session->target_socket : tcp_session->client_socket;

    if (peer_socket == INVALID_SOCKET) {
        qDebug() << "对端套接字无效";
        delete io_context;
        return false;
    }
    // 创建发送上下文
    PerIOContext *send_context = new PerIOContext();
    send_context->socket = peer_socket;
    send_context->operation = IO_SEND_TCP;
    send_context->tcp_session = tcp_session;

    // 复制数据
    memcpy(send_context->buffer, io_context->buffer, bytes_transferred);
    send_context->wsa_buf.len = bytes_transferred;

    // 发送数据
    if (WSASend(send_context->socket, &send_context->wsa_buf, 1, nullptr, 0, &send_context->overlapped, nullptr) == SOCKET_ERROR) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            qDebug() << "WSASend失败: " << WSAGetLastError() << " socket_type: " << io_context->socket_type;
            delete send_context;
            delete io_context;
            tcp_session_manager_->removeSession(tcp_session->mapper_key_);
            return false;
        }
    }

    // 继续接收
    DWORD flags = 0;
    io_context->reset();
    if (WSARecv(io_context->socket, &io_context->wsa_buf, 1, nullptr, &flags, &io_context->overlapped, nullptr) == SOCKET_ERROR) {
        int wsaError = WSAGetLastError();
        if (wsaError != WSA_IO_PENDING) {
            qDebug() << "WSARecv失败: " << wsaError << " socket_type: " << io_context->socket_type;
            delete io_context;
            tcp_session_manager_->removeSession(tcp_session->mapper_key_);
            return false;
        }
    }
    return true;
}

void ProxyServer::handle_udp_receive(std::shared_ptr<hasaki::UdpSession> udp_session, DWORD bytes_transferred) {
    // qDebug() << "handle_udp_receive";
    udp_session->update_activity_time();
    auto io_context = udp_session->io_context.get();
    const char *data = io_context->buffer;
    if (bytes_transferred < 10) {
        return;
    }
    // 处理来自SOCKS5服务器的返回流量
    char atyp = data[3];
    std::string orig_dst_addr;
    uint16_t orig_dst_port;
    size_t header_len = 0;

    if (atyp == 0x01) { // IPv4
        if (bytes_transferred < 10)
            return;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &data[4], ip_str, INET_ADDRSTRLEN);
        orig_dst_addr = ip_str;
        orig_dst_port = ntohs(*(uint16_t *)&data[8]);
        header_len = 10;
    } else if (atyp == 0x04) { // IPv6
        if (bytes_transferred < 22)
            return;
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &data[4], ip_str, INET6_ADDRSTRLEN);
        orig_dst_addr = ip_str;
        orig_dst_port = ntohs(*(uint16_t *)&data[20]);
        header_len = 22;
    } else {
        // 不支持的地址类型
        qDebug() << "不支持的地址类型: " << static_cast<int>(atyp);
        return;
    }

    // 获取网络接口索引
    int interface_index = 1;
    if (!udp_session) {
        qDebug() << "UDP会话不存在";
        return;
    }
    QString clientIpQt = QString::fromStdString(udp_session->client_ip);
    if (adapter_ip_map_.contains(clientIpQt)) {
        interface_index = adapter_ip_map_.value(clientIpQt);
    } else {
        qDebug() << "未找到接口映射: " << QString::fromStdString(udp_session->client_ip);
    }

    // qDebug() << "发送伪造UDP数据包: " << QString::fromStdString(orig_dst_addr) << ":" << orig_dst_port << " -> " <<
    // QString::fromStdString(udp_session->client_ip) << ":" << udp_session->client_port; 使用UDP包注入器发送数据包
    bool result = udp_packet_injector_->sendSpoofedPacket(orig_dst_addr,                  // 源IP (原始目标地址)
                                                          orig_dst_port,                  // 源端口 (原始目标端口)
                                                          udp_session->client_ip,         // 目标IP (客户端IP)
                                                          udp_session->client_port,       // 目标端口 (客户端端口)
                                                          data + header_len,              // 负载数据
                                                          bytes_transferred - header_len, // 负载长度
                                                          interface_index                 // 网络接口索引
    );

    if (!result) {
        qDebug() << "发送伪造UDP数据包失败";
    }

    // 继续投递新的UDP接收请求
    post_udp_recv(udp_session);
}

bool ProxyServer::get_tcp_connection_target(SOCKET socket, std::string &target_addr, uint16_t &target_port, std::string &mapper_key,
                                            MappingType &mapping_type) {
    if (!endpoint_mapper_) {
        qDebug() << "错误: 未设置EndpointMapper";
        return false;
    }

    sockaddr_storage remoteAddr;
    int addrLen = sizeof(remoteAddr);
    if (getpeername(socket, (struct sockaddr *)&remoteAddr, &addrLen) == SOCKET_ERROR) {
        qDebug() << "getpeername failed with error: " << WSAGetLastError();
        return false;
    }

    // 获取伪源端口
    uint16_t pseudo_port = 0;
    std::string remote_addr_str;

    if (remoteAddr.ss_family == AF_INET) {
        // qDebug() << "IPv4";
        //  IPv4
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&remoteAddr;
        pseudo_port = ntohs(addr_in->sin_port);

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr_in->sin_addr), ip_str, INET_ADDRSTRLEN);
        remote_addr_str = ip_str;

        // 查找IPv4 TCP映射
        Ipv4EndpointPair pair;
        mapper_key = endpoint_mapper_->createIpv4EndpointKey(remote_addr_str, pseudo_port);

        if (endpoint_mapper_->findIpv4TcpMapping(mapper_key, pair)) {
            target_addr = Utils::FormatIpv4Address(pair.dstAddr);
            target_port = WinDivertHelperNtohs(pair.dstPort);
            mapping_type = MappingType::IPV4_TCP;
            // qDebug() << "从EndpointMapper获取IPv4目标: " << QString::fromStdString(key) << ":" << target_port;
            return true;
        }
    } else if (remoteAddr.ss_family == AF_INET6) {
        // IPv6
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&remoteAddr;
        if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
            // 是 IPv4 映射地址，应作为 IPv4 处理
            // qDebug() << "检测到IPv4映射的IPv6地址，将按IPv4处理。";

            // 提取IPv4地址部分
            // IPv4 地址在 sin6_addr 的最后4个字节
            struct in_addr ipv4_addr;
            memcpy(&ipv4_addr, &addr_in6->sin6_addr.s6_addr[12], sizeof(ipv4_addr));

            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ipv4_addr, ip_str, INET_ADDRSTRLEN);
            remote_addr_str = ip_str;
            pseudo_port = ntohs(addr_in6->sin6_port);

            // 在 IPv4 映射表中查找
            Ipv4EndpointPair pair;
            mapper_key = endpoint_mapper_->createIpv4EndpointKey(remote_addr_str, pseudo_port);

            if (endpoint_mapper_->findIpv4TcpMapping(mapper_key, pair)) {
                target_addr = Utils::FormatIpv4Address(pair.dstAddr);
                target_port = WinDivertHelperNtohs(pair.dstPort);
                mapping_type = MappingType::IPV4_TCP;
                // qDebug() << "从EndpointMapper(IPv4 via IPv6 mapped)获取目标: " << QString::fromStdString(key) << ":" << target_port;
                return true;
            }

        } else {
            // qDebug() << "纯IPv6";
            //  是纯粹的 IPv6 地址
            pseudo_port = ntohs(addr_in6->sin6_port);
            remote_addr_str = Utils::FormatIpv6Address((UINT32 *)addr_in6->sin6_addr.s6_addr);

            // 查找IPv6 TCP映射
            Ipv6EndpointPair pair;
            mapper_key = endpoint_mapper_->createIpv6EndpointKey(remote_addr_str, pseudo_port);

            if (endpoint_mapper_->findIpv6TcpMapping(mapper_key, pair)) {
                target_addr = Utils::FormatIpv6Address((UINT32 *)pair.dstAddr);
                target_port = WinDivertHelperNtohs(pair.dstPort);
                mapping_type = MappingType::IPV6_TCP;
                // qDebug() << "从EndpointMapper获取IPv6目标: " << QString::fromStdString(key) << ":" << target_port;
                return true;
            }
        }
    }

    qDebug().noquote().nospace() << "无法从EndpointMapper获取目标信息: " << QString::fromStdString(remote_addr_str) << ":" << pseudo_port;
    mapping_type = MappingType::UNKNOWN;
    return false;
}

bool ProxyServer::handle_tcp_send(PerIOContext *io_context, DWORD bytes_transferred) {
    // 发送完成，删除上下文
    delete io_context;
    return true;
}

void ProxyServer::handle_udp_send(PerIOContext *io_context, DWORD bytes_transferred) {}

void ProxyServer::post_tcp_accept(SOCKET listen_socket, PerIOContext *io_context) {
    io_context->operation = IO_ACCEPT;

    // 创建接受套接字
    io_context->socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (io_context->socket == INVALID_SOCKET) {
        qDebug() << "创建接受套接字失败: " << WSAGetLastError();
        delete io_context;
        return;
    }

    DWORD dwV6Only = 0;
    if (setsockopt(io_context->socket, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&dwV6Only, sizeof(dwV6Only)) != 0) {
        qDebug() << "setsockopt IPV6_V6ONLY 失败: " << WSAGetLastError();
        closesocket(io_context->socket);
        delete io_context;
        return;
    }

    // 调用AcceptEx
    DWORD bytesReceived = 0;
    if (!lpfn_acceptex_(listen_socket, io_context->socket, io_context->buffer, 0, sizeof(sockaddr_storage), sizeof(sockaddr_storage), &bytesReceived,
                        &io_context->overlapped)) {
        int wsaError = WSAGetLastError();
        if (wsaError != WSA_IO_PENDING) {
            qDebug() << "AcceptEx失败: " << wsaError;
            closesocket(io_context->socket);
            delete io_context;
            return;
        }
    }
}

void ProxyServer::post_udp_recv(std::shared_ptr<hasaki::UdpSession> udp_session) {
    // qDebug() << "post_udp_recv";
    auto io_context = udp_session->io_context.get();
    io_context->reset();
    io_context->operation = IO_RECV_UDP;

    io_context->udp_session = udp_session;
    DWORD flags = 0;
    if (WSARecvFrom(udp_session->local_socket, &io_context->wsa_buf, 1, nullptr, &flags, (SOCKADDR *)&io_context->remote_addr, &io_context->remote_addr_len,
                    &io_context->overlapped, nullptr) == SOCKET_ERROR) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            qDebug() << "WSARecvFrom失败: " << WSAGetLastError();
            io_context->udp_session.reset();
        }
    }
}

bool ProxyServer::handleUdpPacket(const char *packet_data, uint packet_len, const std::string &src_ip, uint16_t src_port, const std::string &dst_ip,
                                  uint16_t dst_port, bool is_ipv6) {

    // 获取或创建会话
    bool is_new_session = false;
    auto session = udp_session_manager_->getOrCreateSession(src_ip, src_port, dst_ip, dst_port, is_ipv6, &is_new_session);
    if (!session) {
        qDebug() << "创建UDP会话失败";
        return false;
    }

    // 构造SOCKS5 UDP请求头
    char header[512];
    size_t header_len = Socks5Client::constructSocks5UdpHeader(header, dst_ip, dst_port, is_ipv6);
    if (header_len == 0) {
        qDebug() << "构造SOCKS5 UDP请求头失败";
        return false;
    }

    // 创建完整数据包
    char *send_buffer = new char[header_len + packet_len];
    memcpy(send_buffer, header, header_len);

    // 只有当packet_data不为空且packet_len大于0时才复制数据
    if (packet_data != nullptr && packet_len > 0) {
        memcpy(send_buffer + header_len, packet_data, packet_len);
    } else {
        qDebug() << "收到空的UDP数据包";
    }

    // 发送数据到SOCKS5服务器
    bool result = sendToSocks5Server(session, send_buffer, header_len + packet_len);

    if (!result) {
        qDebug() << "发送UDP数据到SOCKS5服务器失败: " << WSAGetLastError() << "remote_addr: " << dst_ip << ":" << dst_port;
    }
    delete[] send_buffer;

    if (is_new_session) {
        // 将UDP套接字关联到IOCP
        // qDebug() << "关联UDP套接字到IOCP";
        if (CreateIoCompletionPort((HANDLE)session->local_socket, iocp_handle_, 0, 0) == nullptr) {
            qDebug() << "关联UDP套接字到IOCP失败: " << GetLastError();
            closesocket(session->local_socket);
            session->local_socket = INVALID_SOCKET;
            return false;
        }

        // 投递UDP_RECV
        post_udp_recv(session);
    }
    return result;
}

bool ProxyServer::sendToSocks5Server(const std::shared_ptr<hasaki::UdpSession> &session, const char *data, size_t data_len) {
    if (!session || session->local_socket == INVALID_SOCKET) {
        return false;
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
    int bytes_sent = sendto(session->local_socket, data, data_len, 0, (sockaddr *)&to_addr, to_addr_len);

    if (bytes_sent == SOCKET_ERROR) {
        return false;
    }

    return true;
}