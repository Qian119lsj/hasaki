#include "hasaki/proxy_server.h"

#include <QDebug>
#include <qdebug.h>
#include <qlogging.h>
#include "hasaki/mainwindow.h"

#pragma comment(lib, "ws2_32.lib")

ProxyServer::ProxyServer(EndpointMapper *endpoint_mapper)
    : endpoint_mapper_(endpoint_mapper), packet_forwarder_(nullptr), is_running_(false), iocp_handle_(nullptr), listen_socket_(INVALID_SOCKET),
      udp_socket_(INVALID_SOCKET), socks5_control_socket_(INVALID_SOCKET), lpfn_acceptex_(nullptr) {
    // 初始化UDP数据包注入器
    if (!udp_packet_injector_.initialize()) {
        qDebug() << "警告: UDP数据包注入器初始化失败，可能需要管理员权限";
    }
}

ProxyServer::~ProxyServer() { 
    stop(); 
    udp_packet_injector_.shutdown();
}

void ProxyServer::setSocks5Server(const std::string &address, uint16_t port) {
    socks5_address_ = address;
    socks5_port_ = port;
    qDebug() << "SOCKS5服务器设置为: " << QString::fromStdString(address) << ":" << port;
}

void ProxyServer::setPacketForwarder(PacketForwarder *forwarder) { packet_forwarder_ = forwarder; }

bool ProxyServer::start(uint16_t port, uint16_t worker_threads) {
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
    listen_socket_ = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket_ == INVALID_SOCKET) {
        qDebug() << "创建监听套接字失败: " << WSAGetLastError();
        CloseHandle(iocp_handle_);
        WSACleanup();
        return false;
    }

    DWORD dwV6Only = 0;
    if (setsockopt(listen_socket_, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&dwV6Only, sizeof(dwV6Only)) != 0) {
        qDebug() << "setsockopt IPV6_V6ONLY 失败: " << WSAGetLastError();
        closesocket(listen_socket_);
        CloseHandle(iocp_handle_);
        WSACleanup();
        return false;
    }

    BOOL bReuseAddr = TRUE;
    if (setsockopt(listen_socket_, SOL_SOCKET, SO_REUSEADDR, (char *)&bReuseAddr, sizeof(bReuseAddr)) == SOCKET_ERROR) {
        qDebug() << "setsockopt SO_REUSEADDR 失败: " << WSAGetLastError();
        closesocket(listen_socket_);
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

    if (bind(listen_socket_, (SOCKADDR *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        qDebug() << "绑定套接字失败: " << WSAGetLastError();
        closesocket(listen_socket_);
        CloseHandle(iocp_handle_);
        WSACleanup();
        return false;
    }

    // 开始监听
    if (listen(listen_socket_, SOMAXCONN) == SOCKET_ERROR) {
        qDebug() << "监听失败: " << WSAGetLastError();
        closesocket(listen_socket_);
        CloseHandle(iocp_handle_);
        WSACleanup();
        return false;
    }

    // 创建UDP套接字
    udp_socket_ = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket_ == INVALID_SOCKET) {
        qDebug() << "创建UDP套接字失败: " << WSAGetLastError();
        closesocket(listen_socket_);
        CloseHandle(iocp_handle_);
        WSACleanup();
        return false;
    }

    if (setsockopt(udp_socket_, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&dwV6Only, sizeof(dwV6Only)) != 0) {
        qDebug() << "UDP setsockopt IPV6_V6ONLY 失败: " << WSAGetLastError();
        closesocket(listen_socket_);
        closesocket(udp_socket_);
        CloseHandle(iocp_handle_);
        WSACleanup();
        return false;
    }

    if (bind(udp_socket_, (SOCKADDR *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        qDebug() << "绑定UDP套接字失败: " << WSAGetLastError();
        closesocket(listen_socket_);
        closesocket(udp_socket_);
        CloseHandle(iocp_handle_);
        WSACleanup();
        return false;
    }

    // 请求SOCKS5 UDP关联
    socks5_control_socket_ = socks5_client_.associateUdp(socks5_address_, socks5_port_, "0.0.0.0", 0, socks5_udp_relay_addr_, socks5_udp_relay_port_);
    if (socks5_control_socket_ == INVALID_SOCKET) {
        qDebug() << "SOCKS5 UDP关联失败";
        closesocket(listen_socket_);
        closesocket(udp_socket_);
        CloseHandle(iocp_handle_);
        WSACleanup();
        return false;
    }
    qDebug() << "SOCKS5 UDP关联成功，中继地址: " << QString::fromStdString(socks5_udp_relay_addr_) << ":" << socks5_udp_relay_port_;
    if (packet_forwarder_) {
        packet_forwarder_->setSocks5UdpRelay(socks5_udp_relay_addr_, socks5_udp_relay_port_);
    }

    // 加载AcceptEx函数
    GUID guidAcceptEx = WSAID_ACCEPTEX;
    DWORD dwBytes = 0;
    if (WSAIoctl(listen_socket_, SIO_GET_EXTENSION_FUNCTION_POINTER, &guidAcceptEx, sizeof(guidAcceptEx), &lpfn_acceptex_, sizeof(lpfn_acceptex_), &dwBytes,
                 nullptr, nullptr) == SOCKET_ERROR) {
        qDebug() << "加载AcceptEx失败: " << WSAGetLastError();
        closesocket(listen_socket_);
        CloseHandle(iocp_handle_);
        WSACleanup();
        return false;
    }

    PerSocketData *tcp_per_socket_data = new PerSocketData();
    tcp_per_socket_data->clientSocket = listen_socket_;
    tcp_per_socket_data->serverSocket = INVALID_SOCKET;
    tcp_per_socket_data->ipVersion = IPVersion::IPV6;
    tcp_per_socket_data->protocolType = ProtocolType::TCP;

    // 将监听套接字关联到IOCP
    if (CreateIoCompletionPort((HANDLE)listen_socket_, iocp_handle_, (ULONG_PTR)tcp_per_socket_data, 0) == nullptr) {
        qDebug() << "关联监听套接字到IOCP失败: " << GetLastError();
        closesocket(listen_socket_);
        CloseHandle(iocp_handle_);
        WSACleanup();
        return false;
    }

    PerSocketData *udp_per_socket_data = new PerSocketData();
    udp_per_socket_data->clientSocket = udp_socket_;
    udp_per_socket_data->serverSocket = INVALID_SOCKET;
    udp_per_socket_data->ipVersion = IPVersion::IPV6;
    udp_per_socket_data->protocolType = ProtocolType::UDP;

    // 将UDP套接字关联到IOCP
    if (CreateIoCompletionPort((HANDLE)udp_socket_, iocp_handle_, (ULONG_PTR)udp_per_socket_data, 0) == nullptr) {
        qDebug() << "关联UDP套接字到IOCP失败: " << GetLastError();
        closesocket(listen_socket_);
        closesocket(udp_socket_);
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
        post_tcp_accept(listen_socket_, new IOContext());
    }

    // 发布初始UDP接收请求
    for (uint16_t i = 0; i < worker_threads * 2; ++i) {
        IOContext *io_context = new IOContext();
        io_context->per_socket_data = udp_per_socket_data;
        post_udp_recv(udp_socket_, io_context);
    }

    qDebug() << "代理服务器已启动，监听端口: " << port;
    return true;
}

void ProxyServer::stop() {
    if (!is_running_) {
        return;
    }

    is_running_ = false;

    // 关闭监听套接字
    if (listen_socket_ != INVALID_SOCKET) {
        closesocket(listen_socket_);
        listen_socket_ = INVALID_SOCKET;
    }

    // 关闭UDP套接字
    if (udp_socket_ != INVALID_SOCKET) {
        closesocket(udp_socket_);
        udp_socket_ = INVALID_SOCKET;
    }

    // 关闭SOCKS5控制套接字
    if (socks5_control_socket_ != INVALID_SOCKET) {
        closesocket(socks5_control_socket_);
        socks5_control_socket_ = INVALID_SOCKET;
    }

    // 通知工作线程退出
    if (iocp_handle_ != nullptr) {
        for (size_t i = 0; i < worker_threads_.size(); ++i) {
            PerSocketData *per_socket_data = new PerSocketData();
            per_socket_data->operation = OP_EXIT;
            PostQueuedCompletionStatus(iocp_handle_, 0, (ULONG_PTR)per_socket_data, nullptr);
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

    WSACleanup();
    qDebug() << "代理服务器已停止";
}

void ProxyServer::worker_thread_func() {

    while (is_running_) {
        DWORD bytes_transferred = 0;
        IOContext *io_context = nullptr;
        PerSocketData *per_socket_data = nullptr;

        // 等待完成通知
        BOOL result = GetQueuedCompletionStatus(iocp_handle_, &bytes_transferred, (PULONG_PTR)&per_socket_data, (LPOVERLAPPED *)&io_context, INFINITE);

        if (!is_running_) {
            
            long remainingIo = per_socket_data->ioCount.fetch_sub(1) - 1;
            if (io_context->session) {
                io_context->session->close();
            }
            if (per_socket_data) {
                per_socket_data->TryToCloseSocketData(per_socket_data);
            }
            if (remainingIo == 0 && per_socket_data->isClosing.load() == true) {
                delete per_socket_data;
            }
            delete io_context;
            break;
        }

        // 检查是否收到退出信号
        if (bytes_transferred == 0 && per_socket_data->operation == OP_EXIT) {
            delete per_socket_data;
            delete io_context;
            break;
        }

        if (!result) {
            DWORD dwError = GetLastError();
            qDebug() << "GetQueuedCompletionStatus 失败，错误码：" << dwError << "per_socket_data" << per_socket_data << "io_context" << io_context;
            
            if (io_context->session) {
                long remaingIo = io_context->per_socket_data->ioCount.fetch_sub(1)-1;
                if (io_context->per_socket_data->protocolType == ProtocolType::TCP) {
                    io_context->session->close();
                    if (remaingIo == 0 && io_context->per_socket_data->isClosing.load() == true) {
                        delete io_context->per_socket_data;
                    }
                } else if (io_context->per_socket_data->protocolType == ProtocolType::UDP) {
                    IOContext *new_io_context = new IOContext();
                    new_io_context->per_socket_data = io_context->per_socket_data;
                    post_udp_recv(io_context->per_socket_data->clientSocket, new_io_context);
                }
            }
            delete io_context;
            continue;
        }

        long remainingIo = per_socket_data->ioCount.fetch_sub(1) - 1;


        if (bytes_transferred == 0 && io_context->operation != IO_ACCEPT) {
            if (io_context->session) {
                io_context->session->close();
            }
            delete io_context;
            continue;
        }

        if (remainingIo == 0 && per_socket_data->isClosing.load() == true) {
            delete per_socket_data;
            continue;
        }

        switch (io_context->operation) {
        case IO_ACCEPT:
            handle_tcp_accept(per_socket_data, io_context);
            break;

        case IO_RECV:
            handle_tcp_receive(per_socket_data, io_context, bytes_transferred);
            break;

        case IO_SEND:
            handle_tcp_send(per_socket_data, io_context, bytes_transferred);
            break;

        case IO_RECV_UDP:
            handle_udp_receive(per_socket_data, io_context, bytes_transferred);
            break;

        case IO_SEND_UDP:
            handle_udp_send(io_context, bytes_transferred);
            break;

        default:
            delete io_context;
            break;
        }
    }

    qDebug() << "工作线程已退出";
}

bool ProxyServer::handle_tcp_accept(PerSocketData *per_socket_data, IOContext *io_context) {
    SOCKET client_socket = io_context->socket;

    // 更新套接字上下文
    if (setsockopt(client_socket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (char *)&listen_socket_, sizeof(listen_socket_)) != 0) {
        qDebug() << "SO_UPDATE_ACCEPT_CONTEXT 失败: " << WSAGetLastError();
        closesocket(client_socket);
        delete io_context;
        post_tcp_accept(per_socket_data->clientSocket, new IOContext());
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
        post_tcp_accept(per_socket_data->clientSocket, new IOContext());
        return false;
    }

    // 通过SOCKS5代理连接到目标
    SOCKET target_socket = socks5_client_.connectTarget(socks5_address_, socks5_port_, target_addr, target_port);

    if (target_socket == INVALID_SOCKET) {
        qDebug() << "无法通过SOCKS5连接到目标: " << QString::fromStdString(target_addr) << ":" << target_port;
        closesocket(client_socket);
        delete io_context;
        post_tcp_accept(per_socket_data->clientSocket, new IOContext());
        return false;
    }

    // 将新接受的客户端套接字关联到IOCP
    PerSocketData *tcp_per_socket_data = new PerSocketData();
    tcp_per_socket_data->clientSocket = client_socket;
    tcp_per_socket_data->serverSocket = per_socket_data->clientSocket;
    tcp_per_socket_data->ipVersion = IPVersion::IPV6;
    tcp_per_socket_data->protocolType = ProtocolType::TCP;
    if (CreateIoCompletionPort((HANDLE)client_socket, iocp_handle_, (ULONG_PTR)tcp_per_socket_data, 0) == nullptr) {
        qDebug() << "关联客户端套接字到IOCP失败: " << GetLastError();
        closesocket(client_socket);
        closesocket(target_socket);
        delete io_context;
        post_tcp_accept(per_socket_data->clientSocket, new IOContext());
        return false;
    }

    PerSocketData *tcp_per_socket_data2 = new PerSocketData();
    tcp_per_socket_data2->clientSocket = target_socket;
    tcp_per_socket_data2->ipVersion = IPVersion::IPV6;
    tcp_per_socket_data2->protocolType = ProtocolType::TCP;
    // 将目标套接字关联到IOCP
    if (CreateIoCompletionPort((HANDLE)target_socket, iocp_handle_, (ULONG_PTR)tcp_per_socket_data2, 0) == nullptr) {
        qDebug() << "关联目标套接字到IOCP失败: " << GetLastError();
        closesocket(client_socket);
        closesocket(target_socket);
        delete io_context;
        post_tcp_accept(per_socket_data->clientSocket, new IOContext());
        return false;
    }

    // Accept操作的上下文已经完成其使命，可以释放
    delete io_context;

    // 创建会话
    auto session = std::make_shared<ProxySession>(client_socket, target_socket, mapper_key, mapping_type);
    session->client_per_socket_data = tcp_per_socket_data;
    session->target_per_socket_data = tcp_per_socket_data2;

    // 为客户端套接字创建新的IO上下文用于接收
    IOContext *client_io_context = new IOContext();
    client_io_context->socket = client_socket;
    client_io_context->operation = IO_RECV;
    client_io_context->session = session;
    client_io_context->socket_type = CLIENT_SOCKET;
    client_io_context->per_socket_data = tcp_per_socket_data;

    // 为目标套接字创建新的IO上下文用于接收
    IOContext *target_io_context = new IOContext();
    target_io_context->socket = target_socket;
    target_io_context->operation = IO_RECV;
    target_io_context->session = session;
    target_io_context->socket_type = TARGET_SOCKET;
    target_io_context->per_socket_data = tcp_per_socket_data2;

    // 为两个方向都投递接收请求
    DWORD flags = 0;
    tcp_per_socket_data->ioCount.fetch_add(1);
    if (WSARecv(client_io_context->socket, &client_io_context->wsa_buf, 1, nullptr, &flags, &client_io_context->overlapped, nullptr) == SOCKET_ERROR) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            qDebug() << "为客户端投递WSARecv失败: " << WSAGetLastError();
            session->close();
            delete client_io_context;
            delete target_io_context;
            delete tcp_per_socket_data;
            delete tcp_per_socket_data2;
            post_tcp_accept(per_socket_data->clientSocket, new IOContext());
            return false;
        }
    }

    tcp_per_socket_data2->ioCount.fetch_add(1);
    if (WSARecv(target_io_context->socket, &target_io_context->wsa_buf, 1, nullptr, &flags, &target_io_context->overlapped, nullptr) == SOCKET_ERROR) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            qDebug() << "为目标投递WSARecv失败: " << WSAGetLastError();
            session->close();
            delete client_io_context;
            delete target_io_context;
            delete tcp_per_socket_data;
            delete tcp_per_socket_data2;
            post_tcp_accept(per_socket_data->clientSocket, new IOContext());
            return false;
        }
    }

    // 重新发布一个Accept请求
    post_tcp_accept(per_socket_data->clientSocket, new IOContext());

    return true;
}

bool ProxyServer::handle_tcp_receive(PerSocketData *per_socket_data, IOContext *io_context, DWORD bytes_transferred) {
    if (per_socket_data->isClosing.load() == true) {
        // 如果连接已经在关闭，则不再发起新的 I/O
        delete io_context; // 释放为这次失败操作准备的 IOContext
        return false;
    }

    // 从上下文中获取会话和对端套接字
    auto connection = io_context->session;
    if (!connection) {
        // 没有会话，无法继续
        delete io_context;
        closesocket(per_socket_data->clientSocket);
        delete per_socket_data;
        return false;
    }
    SOCKET peer_socket = (io_context->socket_type == CLIENT_SOCKET) ? connection->get_target_socket() : connection->get_client_socket();
    PerSocketData *peer_per_socket_data = (io_context->socket_type == CLIENT_SOCKET) ? connection->target_per_socket_data : connection->client_per_socket_data;
    // 检查对端套接字是否有效
    if (peer_socket == INVALID_SOCKET) {
        qDebug() << "对端套接字无效";
        connection->close();
        delete io_context;
        return false;
    }

    // 创建发送上下文
    IOContext *send_context = new IOContext();
    send_context->per_socket_data = peer_per_socket_data;
    send_context->socket = peer_socket;
    send_context->operation = IO_SEND;
    send_context->session = connection; // 关联会话

    // 复制数据
    memcpy(send_context->buffer, io_context->buffer, bytes_transferred);
    send_context->wsa_buf.len = bytes_transferred;

    // 发送数据
    peer_per_socket_data->ioCount.fetch_add(1);
    if (WSASend(send_context->socket, &send_context->wsa_buf, 1, nullptr, 0, &send_context->overlapped, nullptr) == SOCKET_ERROR) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            qDebug() << "WSASend失败: " << WSAGetLastError();
            delete send_context;
            delete io_context;
            if (peer_per_socket_data->ioCount.fetch_sub(1) - 1 == 0 && peer_per_socket_data->isClosing.load() == false) {
                delete peer_per_socket_data;
            }
            connection->close();
            return false;
        }
    }

    // 继续接收
    DWORD flags = 0;
    // 重置WSA缓冲区长度
    io_context->wsa_buf.buf = io_context->buffer;
    io_context->wsa_buf.len = sizeof(io_context->buffer);

    per_socket_data->ioCount.fetch_add(1);
    if (WSARecv(io_context->socket, &io_context->wsa_buf, 1, nullptr, &flags, &io_context->overlapped, nullptr) == SOCKET_ERROR) {
        int wsaError = WSAGetLastError();
        if (wsaError != WSA_IO_PENDING) {
            qDebug() << "WSARecv失败: " << wsaError;
            delete io_context;
            if (per_socket_data->ioCount.fetch_sub(1) - 1 == 0 && per_socket_data->isClosing.load() == false) {
                delete per_socket_data;
            }
            connection->close();
            return false;
        }
    }

    return true;
}

void ProxyServer::handle_udp_receive(PerSocketData *per_socket_data, IOContext *io_context, DWORD bytes_transferred) {
    char remote_ip_str[INET6_ADDRSTRLEN];
    uint16_t remote_port;

    // 首先，获取远程地址信息
    if (io_context->remote_addr.ss_family == AF_INET) {
        sockaddr_in *addr_in = (sockaddr_in *)&io_context->remote_addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, remote_ip_str, sizeof(remote_ip_str));
        remote_port = ntohs(addr_in->sin_port);
    } else if (io_context->remote_addr.ss_family == AF_INET6) {
        sockaddr_in6 *addr_in6 = (sockaddr_in6 *)&io_context->remote_addr;
        if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
            struct in_addr ipv4_addr;
            memcpy(&ipv4_addr, &addr_in6->sin6_addr.s6_addr[12], sizeof(ipv4_addr));
            inet_ntop(AF_INET, &ipv4_addr, remote_ip_str, INET_ADDRSTRLEN);
        } else {
            inet_ntop(AF_INET6, &addr_in6->sin6_addr, remote_ip_str, sizeof(remote_ip_str));
        }
        remote_port = ntohs(addr_in6->sin6_port);
    } else {
        qDebug() << "未知的UDP数据包来源地址类型";
        IOContext *new_io_context = new IOContext();
        new_io_context->per_socket_data = per_socket_data;
        post_udp_recv(per_socket_data->clientSocket, new_io_context);
        delete io_context;
        return;
    }

    // 检查数据包来源是否为SOCKS5服务器
    if (remote_ip_str == socks5_udp_relay_addr_ && remote_port == socks5_udp_relay_port_) {
        // 处理来自SOCKS5服务器的返回流量
        handle_socks5_server_response(per_socket_data, io_context, bytes_transferred);
    } else {
        // 处理来自客户端的去向流量
        handle_client_udp_request(per_socket_data, io_context, bytes_transferred, remote_ip_str, remote_port);
    }
    
    // 继续投递新的UDP接收请求
    IOContext *new_io_context = new IOContext();
    new_io_context->per_socket_data = per_socket_data;
    post_udp_recv(per_socket_data->clientSocket, new_io_context);
    delete io_context;
}

void ProxyServer::handle_socks5_server_response(PerSocketData *per_socket_data, IOContext *io_context, DWORD bytes_transferred) {
    // 来自SOCKS5服务器的返回流量
    // qDebug() << "来自SOCKS5服务器的返回流量";
    const char *data = io_context->buffer;
    if (bytes_transferred < 10) { // SOCKS5 UDP响应头至少10字节 (IPv4)
        return;
    }

    char atyp = data[3];
    std::string orig_dst_addr;
    uint16_t orig_dst_port;
    size_t header_len = 0;
    MappingType reverse_mapping_type = MappingType::UNKNOWN;

    if (atyp == 0x01) { // IPv4
        if (bytes_transferred < 10)
            return;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &data[4], ip_str, INET_ADDRSTRLEN);
        orig_dst_addr = ip_str;
        orig_dst_port = ntohs(*(uint16_t *)&data[8]);
        header_len = 10;
        reverse_mapping_type = MappingType::IPV4_UDP;
    } else if (atyp == 0x04) { // IPv6
        if (bytes_transferred < 22)
            return;
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &data[4], ip_str, INET6_ADDRSTRLEN);
        orig_dst_addr = ip_str;
        orig_dst_port = ntohs(*(uint16_t *)&data[20]);
        header_len = 22;
        reverse_mapping_type = MappingType::IPV6_UDP;
    } else {
        // 不支持的地址类型
        return;
    }

    // qDebug() << "orig_dst_addr: " << orig_dst_addr << " orig_dst_port: " << orig_dst_port << " reverse_mapping_type: " << static_cast<int>(reverse_mapping_type);
    std::string reverse_key = endpoint_mapper_->createUdpReverseKey(orig_dst_addr, orig_dst_port, reverse_mapping_type);
    std::string mapper_key;
    if (endpoint_mapper_->findUdpReverseMapping(reverse_key, mapper_key)) {
        // qDebug() << "通过 reverse_key: " << reverse_key << " 找到udp反向映射: mapper_key: " << mapper_key;

        
        std::string client_ip;
        uint16_t client_port = 0;
        int ifIdx = 0; // 网络适配器索引

        bool client_found = false;

        if (reverse_mapping_type == MappingType::IPV4_UDP) {
            //通过mapper_key获取原始四元组
            Ipv4EndpointPair pair;
            endpoint_mapper_->findIpv4UdpMapping(mapper_key, pair);
            client_ip = FormatIpv4Address(pair.srcAddr);
            client_port = WinDivertHelperNtohs(pair.srcPort);
            client_found = true;
            
        } else if (reverse_mapping_type == MappingType::IPV6_UDP) {
            //通过mapper_key获取原始四元组
            Ipv6EndpointPair pair;
            endpoint_mapper_->findIpv6UdpMapping(mapper_key, pair);
            client_ip = FormatIpv6Address((UINT32*)pair.srcAddr);
            client_port = WinDivertHelperNtohs(pair.srcPort);
            client_found = true;
        }

        if (client_found) {
            // 查找适配器索引
            MainWindow* mainWindow = getMainWindow();
            if (mainWindow) {
                const QMap<QString, int>& adapterIpMap = mainWindow->getAdapterIpMap();
                QString clientIpQt = QString::fromStdString(client_ip);
                if (adapterIpMap.contains(clientIpQt)) {
                    ifIdx = adapterIpMap.value(clientIpQt);
                }
            }
            // qDebug() << "orig_dst_addr: " << orig_dst_addr << " orig_dst_port: " << orig_dst_port << " client_ip: " << client_ip << " client_port: " << client_port << " ifIdx: " << ifIdx;
            // 使用UdpPacketInjector发送数据包
            bool result = udp_packet_injector_.sendSpoofedPacket(
                orig_dst_addr,                    // 源IP (原始目标地址)
                orig_dst_port,                    // 源端口 (原始目标端口)
                client_ip,                        // 目标IP (客户端IP)
                client_port,                      // 目标端口 (客户端端口)
                data + header_len,                // 负载数据
                bytes_transferred - header_len,   // 负载长度
                ifIdx                             // 网络适配器索引
            );
            
            if (!result) {
                qDebug() << "发送伪造UDP数据包失败";
            }
        }
    }
}

void ProxyServer::handle_client_udp_request(PerSocketData *per_socket_data, IOContext *io_context, DWORD bytes_transferred, 
                                           const char* remote_ip_str, uint16_t remote_port) {
    // 来自客户端的去向流量
    // qDebug() << "来自客户端的去向流量";
    std::string target_addr_str;
    uint16_t target_port;
    std::string mapper_key;
    MappingType mapping_type = MappingType::UNKNOWN;

    if (get_udp_connection_target(io_context->remote_addr, target_addr_str, target_port, mapper_key, mapping_type)) {
        endpoint_mapper_->createUdpReverseMapping(target_addr_str, target_port, mapper_key, mapping_type);
        // qDebug() << "获取原始目标成功: " << target_addr_str << " " << target_port << " mapper_key: " << mapper_key
        //  << " mapping_type: " << static_cast<int>(mapping_type);
        
        // 构造SOCKS5 UDP请求头
        char header[512];
        size_t header_len = construct_socks5_udp_header(header, target_addr_str, target_port, mapping_type);
        if (header_len == 0) {
            return; // 构造头部失败
        }

        char send_buffer[8192];
        memcpy(send_buffer, header, header_len);
        memcpy(send_buffer + header_len, io_context->buffer, bytes_transferred);

        send_udp_to_socks5_server(per_socket_data, udp_socket_, send_buffer, bytes_transferred + header_len);
    } else {
        // qDebug() << "未找到UDP映射: " << remote_ip_str << ":" << remote_port;
    }
}

size_t ProxyServer::construct_socks5_udp_header(char* header, const std::string& target_addr, uint16_t target_port, MappingType mapping_type) {
    size_t header_len = 0;
    header[0] = 0x00;
    header[1] = 0x00;
    header[2] = 0x00;

    if (mapping_type == MappingType::IPV4_UDP) {
        header[3] = 0x01;
        inet_pton(AF_INET, target_addr.c_str(), &header[4]);
        *(uint16_t *)&header[8] = htons(target_port);
        header_len = 10;
    } else if (mapping_type == MappingType::IPV6_UDP) {
        header[3] = 0x04;
        inet_pton(AF_INET6, target_addr.c_str(), &header[4]);
        *(uint16_t *)&header[20] = htons(target_port);
        header_len = 22;
    } else {
        return 0; // 不支持的映射类型
    }
    
    return header_len;
}

void ProxyServer::send_udp_to_socks5_server(PerSocketData *per_socket_data, SOCKET udp_socket, const char* buffer, size_t buffer_len) {
    IOContext *send_context = new IOContext();
    send_context->per_socket_data = per_socket_data;
    send_context->socket = udp_socket;
    send_context->operation = IO_SEND_UDP;
    memcpy(send_context->buffer, buffer, buffer_len);
    send_context->wsa_buf.len = buffer_len;

    sockaddr_in6 socks5_udp_sockaddr;
    memset(&socks5_udp_sockaddr, 0, sizeof(socks5_udp_sockaddr));
    socks5_udp_sockaddr.sin6_family = AF_INET6;
    socks5_udp_sockaddr.sin6_port = htons(socks5_udp_relay_port_);

    // 将IPv4地址转换为IPv4映射的IPv6地址
    in_addr v4addr;
    inet_pton(AF_INET, socks5_udp_relay_addr_.c_str(), &v4addr);
    // 设置 ::ffff: 前缀
    socks5_udp_sockaddr.sin6_addr.s6_addr[10] = 0xff;
    socks5_udp_sockaddr.sin6_addr.s6_addr[11] = 0xff;
    // 复制IPv4地址
    memcpy(&socks5_udp_sockaddr.sin6_addr.s6_addr[12], &v4addr, sizeof(v4addr));

    if (WSASendTo(send_context->socket, &send_context->wsa_buf, 1, nullptr, 0, (SOCKADDR *)&socks5_udp_sockaddr, sizeof(socks5_udp_sockaddr),
                  &send_context->overlapped, nullptr) == SOCKET_ERROR) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            qDebug() << "WSASendTo失败: " << WSAGetLastError();
            delete send_context;
        }
    }
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
        //qDebug() << "IPv4";
        // IPv4
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&remoteAddr;
        pseudo_port = ntohs(addr_in->sin_port);

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(addr_in->sin_addr), ip_str, INET_ADDRSTRLEN);
        remote_addr_str = ip_str;

        // 查找IPv4 TCP映射
        Ipv4EndpointPair pair;
        mapper_key = endpoint_mapper_->createIpv4EndpointKey(remote_addr_str, pseudo_port);

        if (endpoint_mapper_->findIpv4TcpMapping(mapper_key, pair)) {
            target_addr = FormatIpv4Address(pair.dstAddr);
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
            //qDebug() << "检测到IPv4映射的IPv6地址，将按IPv4处理。";

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
                target_addr = FormatIpv4Address(pair.dstAddr);
                target_port = WinDivertHelperNtohs(pair.dstPort);
                mapping_type = MappingType::IPV4_TCP;
                // qDebug() << "从EndpointMapper(IPv4 via IPv6 mapped)获取目标: " << QString::fromStdString(key) << ":" << target_port;
                return true;
            }

        } else {
            //qDebug() << "纯IPv6";
            // 是纯粹的 IPv6 地址
            pseudo_port = ntohs(addr_in6->sin6_port);
            remote_addr_str = FormatIpv6Address((UINT32 *)addr_in6->sin6_addr.s6_addr);

            // 查找IPv6 TCP映射
            Ipv6EndpointPair pair;
            mapper_key = endpoint_mapper_->createIpv6EndpointKey(remote_addr_str, pseudo_port);

            if (endpoint_mapper_->findIpv6TcpMapping(mapper_key, pair)) {
                target_addr = FormatIpv6Address((UINT32 *)pair.dstAddr);
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

bool ProxyServer::get_udp_connection_target(const sockaddr_storage &remote_addr, std::string &target_addr, uint16_t &target_port, std::string &mapper_key,
                                            MappingType &mapping_type) {
    if (!endpoint_mapper_) {
        qDebug() << "错误: 未设置EndpointMapper";
        return false;
    }

    std::string remote_addr_str;
    uint16_t remote_port;

    if (remote_addr.ss_family == AF_INET) {
        // IPv4
        const auto *addr_in = (const sockaddr_in *)&remote_addr;
        remote_port = ntohs(addr_in->sin_port);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, INET_ADDRSTRLEN);
        remote_addr_str = ip_str;

        mapper_key = endpoint_mapper_->createIpv4EndpointKey(remote_addr_str, remote_port);
        Ipv4EndpointPair pair;
        if (endpoint_mapper_->findIpv4UdpMapping(mapper_key, pair)) {
            target_addr = FormatIpv4Address(pair.dstAddr);
            target_port = WinDivertHelperNtohs(pair.dstPort);
            mapping_type = MappingType::IPV4_UDP;
            return true;
        }
    } else if (remote_addr.ss_family == AF_INET6) {
        // IPv6
        const auto *addr_in6 = (const sockaddr_in6 *)&remote_addr;
        remote_port = ntohs(addr_in6->sin6_port);

        if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
            // IPv4-mapped IPv6 address
            struct in_addr ipv4_addr;
            memcpy(&ipv4_addr, &addr_in6->sin6_addr.s6_addr[12], sizeof(ipv4_addr));
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ipv4_addr, ip_str, INET_ADDRSTRLEN);
            remote_addr_str = ip_str;

            mapper_key = endpoint_mapper_->createIpv4EndpointKey(remote_addr_str, remote_port);
            Ipv4EndpointPair pair;
            if (endpoint_mapper_->findIpv4UdpMapping(mapper_key, pair)) {
                target_addr = FormatIpv4Address(pair.dstAddr);
                target_port = WinDivertHelperNtohs(pair.dstPort);
                mapping_type = MappingType::IPV4_UDP;
                return true;
            }
        } else {
            // Pure IPv6 address
            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip_str, INET6_ADDRSTRLEN);
            remote_addr_str = ip_str;

            mapper_key = endpoint_mapper_->createIpv6EndpointKey(remote_addr_str, remote_port);
            Ipv6EndpointPair pair;
            if (endpoint_mapper_->findIpv6UdpMapping(mapper_key, pair)) {
                target_addr = FormatIpv6Address((UINT32 *)pair.dstAddr);
                target_port = WinDivertHelperNtohs(pair.dstPort);
                mapping_type = MappingType::IPV6_UDP;
                return true;
            }
        }
    } else {
        qDebug() << "未知的UDP数据包来源地址类型";
        mapping_type = MappingType::UNKNOWN;
        return false;
    }

    // If we reach here, mapping was not found
    qDebug().noquote().nospace() << "无法从EndpointMapper获取UDP目标信息: " << QString::fromStdString(remote_addr_str) << ":" << remote_port;
    mapping_type = MappingType::UNKNOWN;
    return false;
}


bool ProxyServer::handle_tcp_send(PerSocketData *per_socket_data, IOContext *io_context, DWORD bytes_transferred) {
    // 发送完成，删除上下文
    delete io_context;
    return true;
}

void ProxyServer::handle_udp_send(IOContext *io_context, DWORD bytes_transferred) {
    // Sending completed, just clean up the context.
    delete io_context;
}

void ProxyServer::post_tcp_accept(SOCKET listen_socket, IOContext *io_context) {
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
    if (!lpfn_acceptex_(listen_socket, io_context->socket, io_context->buffer, 0, sizeof(sockaddr_storage), sizeof(sockaddr_storage), nullptr,
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

void ProxyServer::post_udp_recv(SOCKET udp_socket, IOContext *io_context) {
    io_context->reset();
    io_context->operation = IO_RECV_UDP;

    DWORD flags = 0;
    if (WSARecvFrom(udp_socket, &io_context->wsa_buf, 1, nullptr, &flags, (SOCKADDR *)&io_context->remote_addr, &io_context->remote_addr_len,
                    &io_context->overlapped, nullptr) == SOCKET_ERROR) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            qDebug() << "WSARecvFrom失败: " << WSAGetLastError();
            delete io_context;
        }
    }
}