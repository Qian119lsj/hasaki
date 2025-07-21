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
    
    // 查找IPv4 TCP映射
    bool findIpv4TcpMapping(const std::string& key, Ipv4EndpointPair& pair);
    
    // 查找IPv6 TCP映射
    bool findIpv6TcpMapping(const std::string& key, Ipv6EndpointPair& pair);
    
    // 删除指定类型的映射
    bool removeMapping(const std::string& key, MappingType type);
    
    // 清理所有映射
    void clearAllMappings();

    // 创建端点对的键
    std::string createIpv4EndpointKey(const std::string& dstAddr, uint16_t pseudoPort);
    std::string createIpv6EndpointKey(const std::string& dstAddr, uint16_t pseudoPort);

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

    // 单例实例
    static std::unique_ptr<EndpointMapper> instance_;
    static std::mutex instance_mutex_;
    
public:
    // 获取单例实例
    static EndpointMapper* getInstance();
}; 