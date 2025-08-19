#include "hasaki/console_manager.h"

#include <windows.h>
#include <cstdio>
#include <iostream>
#include <QDebug>

// 声明一个静态变量来持有控制台的句柄
static HWND g_consoleHwnd = NULL;

void console_manager::show() {
    // 如果句柄为空，说明控制台从未创建过
    if (g_consoleHwnd == NULL) {
        if (!AllocConsole()) {
            return; // 创建失败
        }

        // 获取新创建的控制台的窗口句柄
        g_consoleHwnd = GetConsoleWindow();
        if (g_consoleHwnd == NULL) {
            // 如果获取失败，释放刚创建的控制台以避免资源泄漏
            FreeConsole();
            return;
        }

        // 首次创建时，必须重定向 I/O
        FILE *pFile = nullptr;
        freopen_s(&pFile, "CONOUT$", "w", stdout);
        freopen_s(&pFile, "CONOUT$", "w", stderr);
        freopen_s(&pFile, "CONIN$", "r", stdin);

        std::cout.clear();
        std::clog.clear();
        std::cerr.clear();
        std::cin.clear();
    }

    // 使用 ShowWindow 来显示它
    ShowWindow(g_consoleHwnd, SW_SHOW);
}

void console_manager::hide() {
    // 只在句柄有效时才隐藏
    if (g_consoleHwnd != NULL) {
        ShowWindow(g_consoleHwnd, SW_HIDE);
    }
}

void console_manager::toggle() {
    // 如果从未创建过，则直接显示
    if (g_consoleHwnd == NULL) {
        show();
        return;
    }

    // IsWindowVisible 检查窗口当前是否可见
    if (IsWindowVisible(g_consoleHwnd)) {
        hide();
    } else {
        show();
    }
}
