#ifndef CONSOLEMANAGER_H
#define CONSOLEMANAGER_H

namespace ConsoleManager {

/**
 * @brief 显示控制台窗口。
 * 如果控制台已存在，则不做任何事。
 */
void show();

/**
 * @brief 隐藏（销毁）控制台窗口。
 * 如果控制台不存在，则不做任何事。
 */
void hide();

/**
 * @brief 切换控制台的显示/隐藏状态。
 */
void toggle();

}

#endif // CONSOLEMANAGER_H
