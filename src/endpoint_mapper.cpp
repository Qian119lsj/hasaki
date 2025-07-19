#include "hasaki/endpoint_mapper.h"
#include <QDebug>
#include <qdebug.h>

// 静态成员初始化
std::unique_ptr<EndpointMapper> EndpointMapper::instance_ = nullptr;
std::mutex EndpointMapper::instance_mutex_;

EndpointMapper::EndpointMapper() : next_pseudo_port_(MIN_PSEUDO_PORT) {
}

EndpointMapper::~EndpointMapper() {
    clearAllMappings();
}

EndpointMapper* EndpointMapper::getInstance() {
    std::lock_guard<std::mutex> lock(instance_mutex_);
    if (instance_ == nullptr) {
        instance_ = std::make_unique<EndpointMapper>();
    }
    return instance_.get();
}

uint16_t EndpointMapper::generatePseudoPort() {
    std::lock_guard<std::mutex> lock(pseudo_port_mutex_);
    uint16_t port = next_pseudo_port_++;
    if (next_pseudo_port_ > MAX_PSEUDO_PORT) {
        next_pseudo_port_ = MIN_PSEUDO_PORT;
    }
    return port;
}

std::string EndpointMapper::createIpv4EndpointKey(const std::string& dstAddr, uint16_t pseudoPort) {
    return dstAddr + ":" + std::to_string(pseudoPort);
}

std::string EndpointMapper::createIpv6EndpointKey(const std::string& dstAddr, uint16_t pseudoPort) {
    return "[" + dstAddr + "]:" + std::to_string(pseudoPort);
}

std::string EndpointMapper::createUdpReverseKey(const std::string& srcAddr, uint16_t srcPort, MappingType mapping_type) {
    if (mapping_type == MappingType::IPV6_UDP) {
        return "[" + srcAddr + "]:" + std::to_string(srcPort);
    }
    // 默认为IPv4格式
    return srcAddr + ":" + std::to_string(srcPort);
}

void EndpointMapper::createUdpReverseMapping(const std::string& target_addr, uint16_t target_port, const std::string& mapper_key, MappingType mapping_type) {
    std::string reverse_key = createUdpReverseKey(target_addr, target_port, mapping_type);
    // qDebug() << "创建udp反向映射: reverse_key:" << reverse_key << " mapper_key: " << mapper_key;
    std::unique_lock<std::shared_mutex> lock(udpReverseMutex_);
    udpReverseMappings_[reverse_key] = mapper_key;
}

bool EndpointMapper::findUdpReverseMapping(const std::string& reverse_key, std::string& out_mapper_key) {
    std::shared_lock<std::shared_mutex> lock(udpReverseMutex_);
    auto it = udpReverseMappings_.find(reverse_key);
    if (it != udpReverseMappings_.end()) {
        out_mapper_key = it->second;
        return true;
    }
    return false;
}

uint16_t EndpointMapper::getOrCreateIpv4TcpMapping(UINT32 srcAddr, USHORT srcPort, UINT32 dstAddr, USHORT dstPort) {
    // 首先尝试查找现有映射
    {
        std::shared_lock<std::shared_mutex> lock(ipv4TcpMutex_);
        for (const auto& pair : ipv4TcpMappings_) {
            if (pair.second.srcAddr == srcAddr && pair.second.srcPort == srcPort && 
                pair.second.dstAddr == dstAddr && pair.second.dstPort == dstPort) {
                // 找到现有映射，提取伪源端口
                return std::stoi(pair.first.substr(pair.first.find(":") + 1));
            }
        }
    }
    
    // 没有找到现有映射，创建新的
    uint16_t pseudoPort = generatePseudoPort();
    std::string dstAddrStr = FormatIpv4Address(dstAddr);
    std::string key = createIpv4EndpointKey(dstAddrStr, pseudoPort);
    
    {
        std::unique_lock<std::shared_mutex> lock(ipv4TcpMutex_);
        ipv4TcpMappings_.emplace(key, Ipv4EndpointPair{srcAddr, srcPort, dstAddr, dstPort});
    }
    
    qDebug().noquote().nospace() << "创建IPv4 TCP映射: "<<key << " " << FormatIpv4Address(srcAddr) << ":" << WinDivertHelperNtohs(srcPort) 
             << "->" << QString::fromStdString(dstAddrStr) << ":" << WinDivertHelperNtohs(dstPort);
    
    return pseudoPort;
}

uint16_t EndpointMapper::getOrCreateIpv6TcpMapping(const UINT8* srcAddr, USHORT srcPort, const UINT8* dstAddr, USHORT dstPort) {
    // 首先尝试查找现有映射
    {
        std::shared_lock<std::shared_mutex> lock(ipv6TcpMutex_);
        for (const auto& pair : ipv6TcpMappings_) {
            if (memcmp(pair.second.srcAddr, srcAddr, 16) == 0 && pair.second.srcPort == srcPort && 
                memcmp(pair.second.dstAddr, dstAddr, 16) == 0 && pair.second.dstPort == dstPort) {
                // 找到现有映射，提取伪源端口
                return std::stoi(pair.first.substr(pair.first.find("]:") + 2));
            }
        }
    }
    
    // 没有找到现有映射，创建新的
    uint16_t pseudoPort = generatePseudoPort();
    std::string dstAddrStr = FormatIpv6Address((UINT32*)dstAddr);
    std::string key = createIpv6EndpointKey(dstAddrStr, pseudoPort);
    
    {
        std::unique_lock<std::shared_mutex> lock(ipv6TcpMutex_);
        Ipv6EndpointPair pair;
        memcpy(pair.srcAddr, srcAddr, 16);
        pair.srcPort = srcPort;
        memcpy(pair.dstAddr, dstAddr, 16);
        pair.dstPort = dstPort;
        ipv6TcpMappings_.emplace(key, pair);
    }
    
    qDebug().noquote().nospace() << "创建IPv6 TCP映射: "<<key<<" [" << FormatIpv6Address((UINT32*)srcAddr) << "]:" << WinDivertHelperNtohs(srcPort) 
             << "->[" << FormatIpv6Address((UINT32*)dstAddr) << "]:" << WinDivertHelperNtohs(dstPort);
    
    return pseudoPort;
}

uint16_t EndpointMapper::getOrCreateIpv4UdpMapping(UINT32 srcAddr, USHORT srcPort, UINT32 dstAddr, USHORT dstPort) {
    // 首先尝试查找现有映射
    {
        std::shared_lock<std::shared_mutex> lock(ipv4UdpMutex_);
        for (const auto& pair : ipv4UdpMappings_) {
            if (pair.second.srcAddr == srcAddr && pair.second.srcPort == srcPort && 
                pair.second.dstAddr == dstAddr && pair.second.dstPort == dstPort) {
                // 找到现有映射，提取伪源端口
                return std::stoi(pair.first.substr(pair.first.find(":") + 1));
            }
        }
    }
    
    // 没有找到现有映射，创建新的
    uint16_t pseudoPort = generatePseudoPort();
    std::string dstAddrStr = FormatIpv4Address(dstAddr);
    std::string key = createIpv4EndpointKey(dstAddrStr, pseudoPort);
    
    {
        std::unique_lock<std::shared_mutex> lock(ipv4UdpMutex_);
        ipv4UdpMappings_.emplace(key, Ipv4EndpointPair{srcAddr, srcPort, dstAddr, dstPort});
    }
    
    qDebug().noquote().nospace() << "创建IPv4 UDP映射:"<<key << " " << FormatIpv4Address(srcAddr) << ":" << WinDivertHelperNtohs(srcPort) 
             << "->" << QString::fromStdString(dstAddrStr) << ":" << WinDivertHelperNtohs(dstPort);
    
    return pseudoPort;
}

uint16_t EndpointMapper::getOrCreateIpv6UdpMapping(const UINT8* srcAddr, USHORT srcPort, const UINT8* dstAddr, USHORT dstPort) {
    // 首先尝试查找现有映射
    {
        std::shared_lock<std::shared_mutex> lock(ipv6UdpMutex_);
        for (const auto& pair : ipv6UdpMappings_) {
            if (memcmp(pair.second.srcAddr, srcAddr, 16) == 0 && pair.second.srcPort == srcPort && 
                memcmp(pair.second.dstAddr, dstAddr, 16) == 0 && pair.second.dstPort == dstPort) {
                // 找到现有映射，提取伪源端口
                return std::stoi(pair.first.substr(pair.first.find("]:") + 2));
            }
        }
    }
    
    // 没有找到现有映射，创建新的
    uint16_t pseudoPort = generatePseudoPort();
    std::string dstAddrStr = FormatIpv6Address((UINT32*)dstAddr);
    std::string key = createIpv6EndpointKey(dstAddrStr, pseudoPort);
    
    {
        std::unique_lock<std::shared_mutex> lock(ipv6UdpMutex_);
        Ipv6EndpointPair pair;
        memcpy(pair.srcAddr, srcAddr, 16);
        pair.srcPort = srcPort;
        memcpy(pair.dstAddr, dstAddr, 16);
        pair.dstPort = dstPort;
        ipv6UdpMappings_.emplace(key, pair);
    }
    
    qDebug().noquote().nospace() << "创建IPv6 UDP映射: "<<key<<" [" << FormatIpv6Address((UINT32*)srcAddr) << "]:" << WinDivertHelperNtohs(srcPort) 
             << "->[" << FormatIpv6Address((UINT32*)dstAddr) << "]:" << WinDivertHelperNtohs(dstPort);
    
    return pseudoPort;
}

bool EndpointMapper::findIpv4TcpMapping(const std::string& key, Ipv4EndpointPair& pair) {
    std::shared_lock<std::shared_mutex> lock(ipv4TcpMutex_);
    auto it = ipv4TcpMappings_.find(key);
    if (it != ipv4TcpMappings_.end()) {
        pair = it->second;
        return true;
    }
    return false;
}

bool EndpointMapper::findIpv6TcpMapping(const std::string& key, Ipv6EndpointPair& pair) {
    std::shared_lock<std::shared_mutex> lock(ipv6TcpMutex_);
    auto it = ipv6TcpMappings_.find(key);
    if (it != ipv6TcpMappings_.end()) {
        pair = it->second;
        return true;
    }
    return false;
}

bool EndpointMapper::findIpv4UdpMapping(const std::string& key, Ipv4EndpointPair& pair) {
    std::shared_lock<std::shared_mutex> lock(ipv4UdpMutex_);
    auto it = ipv4UdpMappings_.find(key);
    if (it != ipv4UdpMappings_.end()) {
        pair = it->second;
        return true;
    }
    return false;
}

bool EndpointMapper::findIpv6UdpMapping(const std::string& key, Ipv6EndpointPair& pair) {
    std::shared_lock<std::shared_mutex> lock(ipv6UdpMutex_);
    auto it = ipv6UdpMappings_.find(key);
    if (it != ipv6UdpMappings_.end()) {
        pair = it->second;
        return true;
    }
    return false;
}

bool EndpointMapper::removeMapping(const std::string& key, MappingType type) {
    bool removed = false;
    
    switch (type) {
    case MappingType::IPV4_TCP:
        {
            std::unique_lock<std::shared_mutex> lock(ipv4TcpMutex_);
            auto it = ipv4TcpMappings_.find(key);
            if (it != ipv4TcpMappings_.end()) {
                ipv4TcpMappings_.erase(it);
                removed = true;
                qDebug().noquote() << "删除IPv4 TCP映射:" << QString::fromStdString(key);
            }
        }
        break;
    case MappingType::IPV6_TCP:
        {
            std::unique_lock<std::shared_mutex> lock(ipv6TcpMutex_);
            auto it = ipv6TcpMappings_.find(key);
            if (it != ipv6TcpMappings_.end()) {
                ipv6TcpMappings_.erase(it);
                removed = true;
                qDebug().noquote() << "删除IPv6 TCP映射:" << QString::fromStdString(key);
            }
        }
        break;
    case MappingType::IPV4_UDP:
        {
            std::unique_lock<std::shared_mutex> lock(ipv4UdpMutex_);
            auto it = ipv4UdpMappings_.find(key);
            if (it != ipv4UdpMappings_.end()) {
                ipv4UdpMappings_.erase(it);
                removed = true;
                qDebug().noquote() << "删除IPv4 UDP映射:" << QString::fromStdString(key);
            }
        }
        break;
    case MappingType::IPV6_UDP:
        {
            std::unique_lock<std::shared_mutex> lock(ipv6UdpMutex_);
            auto it = ipv6UdpMappings_.find(key);
            if (it != ipv6UdpMappings_.end()) {
                ipv6UdpMappings_.erase(it);
                removed = true;
                qDebug().noquote() << "删除IPv6 UDP映射:" << QString::fromStdString(key);
            }
        }
        break;
    case MappingType::UNKNOWN:
        qDebug() << "尝试删除未知类型的映射:" << QString::fromStdString(key);
        break;
    }

    if (type == MappingType::IPV4_UDP || type == MappingType::IPV6_UDP) {
        // 尝试也删除反向映射，但这需要我们知道目标地址和端口，
        // 而不仅仅是mapper_key。这部分逻辑需要在调用处处理。
    }

    return removed;
}

void EndpointMapper::clearAllMappings() {
    {
        std::unique_lock<std::shared_mutex> lock(ipv4TcpMutex_);
        ipv4TcpMappings_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lock(ipv6TcpMutex_);
        ipv6TcpMappings_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lock(ipv4UdpMutex_);
        ipv4UdpMappings_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lock(ipv6UdpMutex_);
        ipv6UdpMappings_.clear();
    }
    {
        std::unique_lock<std::shared_mutex> lock(udpReverseMutex_);
        udpReverseMappings_.clear();
    }
    
    qDebug() << "已清理所有端点映射";
} 