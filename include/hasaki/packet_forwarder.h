#pragma once

#include "hasaki/portprocessmonitor.h"
#include "hasaki/endpoint_mapper.h"
#include "hasaki/proxy_server.h"

#include <stop_token>
#include <thread>

class PacketForwarder {
public:
    PacketForwarder();
    ~PacketForwarder();

    bool start();
    void stop();
    void setPortProcessMonitor(PortProcessMonitor* monitor);
    void setEnableIpv6(bool enable);
    void setProxyServer(ProxyServer* proxyServer);

private:
    bool enable_ipv6_ = true;
    void net_thread_func(std::stop_token st);

    HANDLE       net_handle_ = INVALID_HANDLE_VALUE;
    std::jthread net_thread_;


    PortProcessMonitor* portProcessMonitor_ = nullptr;
    ProxyServer* proxyServer_ = nullptr;
    EndpointMapper* endpointMapper_ = nullptr;
};