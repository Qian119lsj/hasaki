#pragma once

#include "hasaki/utils.h"

#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <memory>

// 前向声明创建器类
class DelayedDeleteManagerCreator;

// 延迟删除管理器类，负责管理所有延迟删除任务
class DelayedDeleteManager {
    // 声明友元类，允许创建器访问私有构造函数
    friend class DelayedDeleteManagerCreator;

public:
    // 获取单例实例
    static DelayedDeleteManager* getInstance();

    // 添加延迟删除任务
    void addTask(const std::string& key, MappingType type, uint64_t delayMs = 130000);

    // 停止管理器
    void stop();

    // 清除所有任务
    void clearAllTasks();

    // 析构函数
    ~DelayedDeleteManager();

private:
    // 私有构造函数，确保单例模式
    DelayedDeleteManager();

    // 工作线程函数
    void workerThread();

    // 获取当前时间戳（毫秒）
    uint64_t getCurrentTimeMs();

    // 任务列表
    std::vector<DelayedDeleteTask> tasks_;
    
    // 互斥锁，保护任务列表
    std::mutex taskMutex_;
    
    // 条件变量，用于通知工作线程有新任务或需要退出
    std::condition_variable cv_;
    
    // 工作线程
    std::thread worker_;
    
    // 是否运行标志
    std::atomic<bool> running_;

    // 单例实例
    static std::unique_ptr<DelayedDeleteManager> instance_;
    static std::mutex instanceMutex_;
}; 