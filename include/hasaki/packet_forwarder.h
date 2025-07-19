#pragma once

#include "hasaki/portprocessmonitor.h"
#include "hasaki/endpoint_mapper.h"
#include "hasaki/udp_session_manager.h"

#include <stop_token>
#include <string>
#include <thread>

class MainWindow; // 前向声明

class PacketForwarder {
public:
    PacketForwarder();
    ~PacketForwarder();

    bool start();
    void stop();
    void setPortProcessMonitor(PortProcessMonitor* monitor);
    void setProxyPort(uint16_t port);
    void setSocks5UdpRelay(const std::string& addr, uint16_t port);
    void setSocks5Server(const std::string& addr, uint16_t port);
    void setMainWindow(MainWindow* mainWindow) { mainWindow_ = mainWindow; }
    MainWindow* getMainWindow() const { return mainWindow_; }

private:
    void net_thread_func(std::stop_token st);

    HANDLE       net_handle_ = INVALID_HANDLE_VALUE;
    std::jthread net_thread_;

    std::string socks5_address_;
    uint16_t socks5_port_ = 0;
    std::string socks5_udp_relay_addr_;
    uint16_t socks5_udp_relay_port_ = 0;

    USHORT proxy_port_ = 998;

    PortProcessMonitor* portProcessMonitor_ = nullptr;
    EndpointMapper* endpointMapper_ = nullptr;
    MainWindow* mainWindow_ = nullptr; // MainWindow引用
    
    // UDP会话管理器
    hasaki::UdpSessionManager udp_session_manager_;
};