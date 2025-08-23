# Hasaki - 游戏进程网络代理工具

<div align="center">

一个功能强大的游戏进程网络代理工具。

[![License](https://img.shields.io/badge/license-GPL%20v3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](#系统要求)
[![Qt](https://img.shields.io/badge/Qt-6.9.0-green.svg)](https://qt.io/)
[![C++](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](#技术栈)

</div>

## 🎯 项目概述

Hasaki 是一个基于 Qt 框架开发的游戏进程网络代理工具，旨在为游戏开发者、网络调试人员提供强大的网络流量监控、转发和管理功能。通过集成 WinDivert 库，实现对游戏进程网络通信的精确控制和深度分析。

### 核心特性

- 🔍 **进程监控**: 实时监控指定游戏进程的网络活动
- 🌐 **流量代理**: 支持 TCP/UDP 流量的透明代理和转发
- 📊 **实时统计**: 提供详细的流量统计和速率监控
- ⚙️ **配置管理**: 灵活的代理配置和预设管理系统
- 🔒 **多协议支持**: 支持 SOCKS5 和 Shadowsocks 2022 等代理协议
- 💉 **数据包注入**: 支持自定义数据包的注入和测试
- 🎮 **游戏友好**: 专为游戏应用优化的低延迟代理机制

## 🚀 快速开始

### 系统要求

- **操作系统**: Windows 10/11 (x64)
- **权限**: 管理员权限（用于网络驱动操作）

## 🛠️ 开发构建

### 开发环境要求

- **Qt**: 6.9.0
- **CMake**: 3.24
- **编译器**: Clang (推荐) 或 MSVC 2019+
- **包管理器**: vcpkg

### 依赖库

- **WinDivert**: 网络数据包捕获和注入
- **Qt6**: GUI 框架和网络库
- **Windows SDK**: Windows 平台 API

### 构建步骤

1. **克隆项目**
   ```bash
   git clone https://github.com/Qian119lsj/hasaki.git
   cd hasaki
   ```

2. **配置 vcpkg**
   ```bash
   # 在CMakePresets.json中 设置 vcpkg 工具链
   ```

3. **安装依赖**
   ```bash
   # 安装 Qt Ninja LLVM工具链
   ```

4. **配置和构建**
   ```bash
   # 使用 CMake 配置项目
   cmake --preset clang-release
   
   # 构建项目
   cmake --build --preset build-clang-release
   ```

5. **安装和部署**
   ```bash
   # 安装
   cmake --install out/build/clang-release
   ```

### 开发指南

#### 项目结构

```
hasaki/
├── include/hasaki/          # 头文件目录
│   ├── app_settings.h       # 应用程序设置管理
│   ├── console_manager.h    # 控制台输出管理
│   ├── packet_forwarder.h   # 数据包转发逻辑
│   ├── proxy_server.h       # 代理服务器实现
│   └── ...                  # 其他模块头文件
├── src/                     # 源码目录
│   ├── main.cpp            # 程序入口
│   ├── mainwindow.cpp      # 主窗口实现
│   └── ...                 # 对应的实现文件
├── third_party/windivert/   # WinDivert 网络库
├── CMakeLists.txt          # CMake 配置文件
└── README.md               # 项目说明文档
```

#### 核心架构

- **MainWindow**: 主界面控制器，协调各功能模块
- **ProxyServer**: 代理服务核心，处理网络流量转发
- **PacketForwarder**: 数据包转发引擎，基于 WinDivert
- **SessionManager**: TCP/UDP 会话管理器
- **AppSettings**: 配置管理系统

## 📚 技术文档

### 架构设计

项目采用模块化设计，主要组件包括：

- **网络层**: 基于 WinDivert 的底层网络操作
- **代理层**: SOCKS5/Shadowsocks 协议实现
- **会话层**: TCP/UDP 会话生命周期管理
- **界面层**: Qt Widgets 图形用户界面
- **配置层**: 设置持久化和管理

## 📄 许可证

本项目采用 **GPL v2** 许可证 - 详情请参阅 [LICENSE](LICENSE) 文件。

### 第三方库许可证

- **WinDivert**: 双重许可（LGPL v3 或 GPL v2）- 我们选择 LGPL v3 兼容许可
- **Qt Framework**: LGPL v3（开源版本）
- **其他依赖**: 各自遵循相应的开源许可证

> ⚠️ **重要提示**: 由于使用了 WinDivert 库，本项目必须遵循 GPL 许可证的相关条款。如果您计划将此项目用于商业用途，请仔细阅读 GPL v3 许可证的要求。

## 🙏 致谢

- [Qt Framework](https://qt.io/) - 强大的跨平台 GUI 框架
- [WinDivert](https://www.reqrypt.org/windivert.html) - Windows 数据包捕获和注入库
- 所有为本项目做出贡献的开发者

