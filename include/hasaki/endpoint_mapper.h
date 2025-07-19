#pragma once

#include "hasaki/utils.h"

#include <map>
#include <shared_mutex>
#include <string>
#include <mutex>
#include <memory>

// 端点映射器类，用于管理伪源端口映射
class EndpointMapper {
public:
    EndpointMapper();
    ~EndpointMapper();

    // 获取或创建IPv4 TCP映射
    uint16_t getOrCreateIpv4TcpMapping(UINT32 srcAddr, USHORT srcPort, UINT32 dstAddr, USHORT dstPort);
    
    // 获取或创建IPv6 TCP映射
    uint16_t getOrCreateIpv6TcpMapping(const UINT8* srcAddr, USHORT srcPort, const UINT8* dstAddr, USHORT dstPort);
    
    // 获取或创建IPv4 UDP映射
    uint16_t getOrCreateIpv4UdpMapping(UINT32 srcAddr, USHORT srcPort, UINT32 dstAddr, USHORT dstPort);
    
    // 获取或创建IPv6 UDP映射
    uint16_t getOrCreateIpv6UdpMapping(const UINT8* srcAddr, USHORT srcPort, const UINT8* dstAddr, USHORT dstPort);
    
    // 查找IPv4 TCP映射
    bool findIpv4TcpMapping(const std::string& key, Ipv4EndpointPair& pair);
    
    // 查找IPv6 TCP映射
    bool findIpv6TcpMapping(const std::string& key, Ipv6EndpointPair& pair);
    
    // 查找IPv4 UDP映射
    bool findIpv4UdpMapping(const std::string& key, Ipv4EndpointPair& pair);
    
    // 查找IPv6 UDP映射
    bool findIpv6UdpMapping(const std::string& key, Ipv6EndpointPair& pair);
    
    // 删除指定类型的映射
    bool removeMapping(const std::string& key, MappingType type);
    
    // 清理所有映射
    void clearAllMappings();

    // 创建端点对的键
    std::string createIpv4EndpointKey(const std::string& dstAddr, uint16_t pseudoPort);
    std::string createIpv6EndpointKey(const std::string& dstAddr, uint16_t pseudoPort);
    
    // 创建反向映射的键
    std::string createUdpReverseKey(const std::string& srcAddr, uint16_t srcPort, MappingType mapping_type);

    // 为UDP创建反向映射
    void createUdpReverseMapping(const std::string& target_addr, uint16_t target_port, const std::string& mapper_key, MappingType mapping_type);

    // 查找UDP反向映射
    bool findUdpReverseMapping(const std::string& reverse_key, std::string& out_mapper_key);

private:
    // 生成新的伪源端口
    uint16_t generatePseudoPort();
    
    // 伪源端口范围
    static constexpr uint16_t MIN_PSEUDO_PORT = 10000;
    static constexpr uint16_t MAX_PSEUDO_PORT = 30000;
    
    // 当前伪源端口
    uint16_t next_pseudo_port_;
    std::mutex pseudo_port_mutex_;
    
    // IPv4 TCP映射表
    std::map<std::string, Ipv4EndpointPair> ipv4TcpMappings_;
    std::shared_mutex ipv4TcpMutex_;
    
    // IPv6 TCP映射表
    std::map<std::string, Ipv6EndpointPair> ipv6TcpMappings_;
    std::shared_mutex ipv6TcpMutex_;
    
    // IPv4 UDP映射表
    std::map<std::string, Ipv4EndpointPair> ipv4UdpMappings_;
    std::shared_mutex ipv4UdpMutex_;
    
    // IPv6 UDP映射表
    std::map<std::string, Ipv6EndpointPair> ipv6UdpMappings_;
    std::shared_mutex ipv6UdpMutex_;
    
    // UDP反向映射表 (目标地址 -> mapper_key)
    std::map<std::string, std::string> udpReverseMappings_;
    std::shared_mutex udpReverseMutex_;

    // 单例实例
    static std::unique_ptr<EndpointMapper> instance_;
    static std::mutex instance_mutex_;
    
public:
    // 获取单例实例
    static EndpointMapper* getInstance();
}; 