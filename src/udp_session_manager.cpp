#include "hasaki/udp_session_manager.h"
#include <QDebug>
#include <sstream>

namespace hasaki {

UdpSessionManager::UdpSessionManager() 
    : socks5_udp_relay_port_(0), is_running_(false) {
}

UdpSessionManager::~UdpSessionManager() {
    shutdown();
}

bool UdpSessionManager::initialize() {
    // 初始化UDP包注入器
    if (!packet_injector_.initialize()) {
        qDebug() << "UDP包注入器初始化失败，可能需要管理员权限";
        return false;
    }
    
    is_running_ = true;
    return true;
}

void UdpSessionManager::shutdown() {
    is_running_ = false;
    
    // 关闭所有会话
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    for (auto& pair : sessions_) {
        auto& session = pair.second;
        session->is_active = false;
        
        if (session->local_socket != INVALID_SOCKET) {
            closesocket(session->local_socket);
            session->local_socket = INVALID_SOCKET;
        }
        
        if (session->recv_thread.joinable()) {
            session->recv_thread.join();
        }
    }
    
    sessions_.clear();
    
    // 关闭UDP包注入器
    packet_injector_.shutdown();
}

void UdpSessionManager::setSocks5UdpRelay(const std::string &addr, uint16_t port) {
    socks5_udp_relay_addr_ = addr;
    socks5_udp_relay_port_ = port;
    qDebug() << "UdpSessionManager: 设置SOCKS5 UDP中继地址为" << QString::fromStdString(addr) << ":" << port;
}

void UdpSessionManager::setInterfaceMap(const InterfaceMap& interface_map) {
    interface_map_ = interface_map;
}

std::string UdpSessionManager::createSessionKey(const std::string& client_ip, uint16_t client_port) {
    std::stringstream ss;
    ss << client_ip << ":" << client_port;
    return ss.str();
}

bool UdpSessionManager::handleUdpPacket(const char* packet_data, size_t packet_len, 
                                       const std::string& src_ip, uint16_t src_port,
                                       const std::string& dst_ip, uint16_t dst_port,
                                       bool is_ipv6, int interface_index) {
    if (!is_running_) {
        return false;
    }
    
    if (socks5_udp_relay_addr_.empty() || socks5_udp_relay_port_ == 0) {
        qDebug() << "SOCKS5 UDP中继地址未设置";
        return false;
    }
    
    // 获取或创建会话
    auto session = getOrCreateSession(src_ip, src_port, dst_ip, dst_port, is_ipv6, interface_index);
    if (!session) {
        qDebug() << "创建UDP会话失败";
        return false;
    }
    
    // 构造SOCKS5 UDP请求头
    char header[512];
    size_t header_len = constructSocks5UdpHeader(header, dst_ip, dst_port, is_ipv6);
    if (header_len == 0) {
        qDebug() << "构造SOCKS5 UDP请求头失败";
        return false;
    }
    
    // 创建完整数据包
    char* send_buffer = new char[header_len + packet_len];
    memcpy(send_buffer, header, header_len);
    memcpy(send_buffer + header_len, packet_data, packet_len);
    
    // 发送数据到SOCKS5服务器
    bool result = sendToSocks5Server(session, send_buffer, header_len + packet_len);
    
    delete[] send_buffer;
    return result;
}

std::shared_ptr<UdpSession> UdpSessionManager::getOrCreateSession(
    const std::string& client_ip, uint16_t client_port, 
    const std::string& dest_ip, uint16_t dest_port,
    bool is_ipv6, int interface_index) {
    
    // 创建会话键
    std::string session_key = createSessionKey(client_ip, client_port);
    
    // 查找现有会话
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        auto it = sessions_.find(session_key);
        if (it != sessions_.end()) {
            return it->second;
        }
    }
    
    // 创建新会话
    auto session = std::make_shared<UdpSession>();
    session->client_ip = client_ip;
    session->client_port = client_port;
    session->dest_ip = dest_ip;
    session->dest_port = dest_port;
    session->is_ipv6 = is_ipv6;
    session->interface_index = interface_index;
    session->is_active = true;
    
    // 创建本地UDP套接字
    SOCKET sock = socket(is_ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        qDebug() << "创建UDP套接字失败: " << WSAGetLastError();
        return nullptr;
    }
    
    // 绑定到任意地址和端口
    if (!is_ipv6) {
        sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = 0; // 让系统分配端口
        
        if (bind(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            qDebug() << "绑定UDP套接字失败: " << WSAGetLastError();
            closesocket(sock);
            return nullptr;
        }
    } 
    else {
        sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_any;
        addr.sin6_port = 0; // 让系统分配端口
        
        if (bind(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            qDebug() << "绑定UDP套接字失败: " << WSAGetLastError();
            closesocket(sock);
            return nullptr;
        }
    }
    
    session->local_socket = sock;
    
    // 启动接收线程
    session->recv_thread = std::thread(&UdpSessionManager::sessionRecvThread, this, session);
    
    // 添加到会话映射表
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        sessions_[session_key] = session;
    }
    
    return session;
}

void UdpSessionManager::sessionRecvThread(std::shared_ptr<UdpSession> session) {
    char buffer[8192];
    sockaddr_storage from_addr;
    int from_addr_len = sizeof(from_addr);
    
    // 设置接收超时
    DWORD timeout = 1000; // 1秒
    setsockopt(session->local_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    while (session->is_active && is_running_) {
        // 接收数据
        int bytes_received = recvfrom(session->local_socket, buffer, sizeof(buffer), 0,
                                     (sockaddr*)&from_addr, &from_addr_len);
                                     
        if (bytes_received == SOCKET_ERROR) {
            int error = WSAGetLastError();
            if (error == WSAETIMEDOUT) {
                // 超时，继续等待
                continue;
            }
            
            qDebug() << "UDP接收错误: " << error;
            break;
        }
        
        // 检查数据是否来自SOCKS5服务器
        char from_ip[INET6_ADDRSTRLEN];
        uint16_t from_port = 0;
        
        if (from_addr.ss_family == AF_INET) {
            sockaddr_in* addr_in = (sockaddr_in*)&from_addr;
            inet_ntop(AF_INET, &addr_in->sin_addr, from_ip, sizeof(from_ip));
            from_port = ntohs(addr_in->sin_port);
        } 
        else if (from_addr.ss_family == AF_INET6) {
            sockaddr_in6* addr_in6 = (sockaddr_in6*)&from_addr;
            inet_ntop(AF_INET6, &addr_in6->sin6_addr, from_ip, sizeof(from_ip));
            from_port = ntohs(addr_in6->sin6_port);
        }
        
        std::string from_ip_str(from_ip);
        
        if (from_ip_str == socks5_udp_relay_addr_ && from_port == socks5_udp_relay_port_) {
            // 来自SOCKS5服务器的响应
            handleSocks5Response(session, buffer, bytes_received);
        }
    }
}

size_t UdpSessionManager::constructSocks5UdpHeader(char* header, const std::string& target_addr, 
                                                 uint16_t target_port, bool is_ipv6) {
    size_t header_len = 0;
    header[0] = 0x00; // RSV
    header[1] = 0x00; // RSV
    header[2] = 0x00; // FRAG
    
    if (!is_ipv6) {
        header[3] = 0x01; // ATYP: IPv4
        inet_pton(AF_INET, target_addr.c_str(), &header[4]);
        *(uint16_t*)&header[8] = htons(target_port);
        header_len = 10;
    } 
    else {
        header[3] = 0x04; // ATYP: IPv6
        inet_pton(AF_INET6, target_addr.c_str(), &header[4]);
        *(uint16_t*)&header[20] = htons(target_port);
        header_len = 22;
    }
    
    return header_len;
}

bool UdpSessionManager::sendToSocks5Server(const std::shared_ptr<UdpSession>& session, 
                                         const char* data, size_t data_len) {
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
    } 
    else {
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
    int bytes_sent = sendto(session->local_socket, data, data_len, 0, 
                           (sockaddr*)&to_addr, to_addr_len);
                           
    if (bytes_sent == SOCKET_ERROR) {
        qDebug() << "发送UDP数据到SOCKS5服务器失败: " << WSAGetLastError();
        return false;
    }
    
    return true;
}

void UdpSessionManager::handleSocks5Response(std::shared_ptr<UdpSession> session, 
                                           const char* data, size_t data_len) {
    if (data_len < 10) { // SOCKS5 UDP响应头至少10字节 (IPv4)
        return;
    }
    
    char atyp = data[3];
    std::string orig_dst_addr;
    uint16_t orig_dst_port;
    size_t header_len = 0;
    
    if (atyp == 0x01) { // IPv4
        if (data_len < 10)
            return;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &data[4], ip_str, INET_ADDRSTRLEN);
        orig_dst_addr = ip_str;
        orig_dst_port = ntohs(*(uint16_t*)&data[8]);
        header_len = 10;
    } 
    else if (atyp == 0x04) { // IPv6
        if (data_len < 22)
            return;
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &data[4], ip_str, INET6_ADDRSTRLEN);
        orig_dst_addr = ip_str;
        orig_dst_port = ntohs(*(uint16_t*)&data[20]);
        header_len = 22;
    } 
    else {
        // 不支持的地址类型
        return;
    }
    
    // 获取网络接口索引
    int interface_index = session->interface_index;
    
    // 如果会话中没有保存接口索引，则尝试从接口映射表中查找
    if (interface_index == 0) {
        auto it = interface_map_.find(session->client_ip);
        if (it != interface_map_.end()) {
            interface_index = it->second;
        }
    }
    
    // 使用UDP包注入器发送数据包
    bool result = packet_injector_.sendSpoofedPacket(
        orig_dst_addr,                    // 源IP (原始目标地址)
        orig_dst_port,                    // 源端口 (原始目标端口)
        session->client_ip,               // 目标IP (客户端IP)
        session->client_port,             // 目标端口 (客户端端口)
        data + header_len,                // 负载数据
        data_len - header_len,            // 负载长度
        interface_index                   // 网络接口索引
    );
    
    if (!result) {
        qDebug() << "发送伪造UDP数据包失败";
    }
}

} // namespace hasaki