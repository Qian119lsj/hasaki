#include "hasaki/delayed_delete_manager.h"
#include "hasaki/endpoint_mapper.h"
#include <QDebug>
#include <algorithm>

// 创建器类，用于创建DelayedDeleteManager实例
class DelayedDeleteManagerCreator {
public:
    static std::unique_ptr<DelayedDeleteManager> createInstance() { return std::unique_ptr<DelayedDeleteManager>(new DelayedDeleteManager()); }
};

// 静态成员初始化
std::unique_ptr<DelayedDeleteManager> DelayedDeleteManager::instance_ = nullptr;
std::mutex DelayedDeleteManager::instanceMutex_;

DelayedDeleteManager::DelayedDeleteManager() : running_(true) {
    // 启动工作线程
    worker_ = std::thread(&DelayedDeleteManager::workerThread, this);
    qDebug() << "延迟删除管理器已启动";
}

DelayedDeleteManager::~DelayedDeleteManager() { stop(); }

DelayedDeleteManager *DelayedDeleteManager::getInstance() {
    std::lock_guard<std::mutex> lock(instanceMutex_);
    if (instance_ == nullptr) {
        instance_ = DelayedDeleteManagerCreator::createInstance();
    }
    return instance_.get();
}

void DelayedDeleteManager::addTask(const std::string &key, MappingType type, uint64_t delayMs) {
    // 计算删除时间点
    uint64_t deleteTime = getCurrentTimeMs() + delayMs;

    {
        std::lock_guard<std::mutex> lock(taskMutex_);
        tasks_.emplace_back(key, type, deleteTime);
    }

    // 通知工作线程有新任务
    cv_.notify_one();
}

void DelayedDeleteManager::stop() {
    if (running_) {
        // 设置运行标志为false
        running_ = false;

        // 通知工作线程退出
        cv_.notify_one();

        // 等待工作线程结束
        if (worker_.joinable()) {
            worker_.join();
        }
        clearAllTasks();

        qDebug() << "延迟删除管理器已停止";
    }
}

void DelayedDeleteManager::clearAllTasks() {
    std::lock_guard<std::mutex> lock(taskMutex_);
    tasks_.clear();
}

void DelayedDeleteManager::workerThread() {
    while (running_) {
        // 计算下一个任务的执行时间
        uint64_t nextTaskTime = UINT64_MAX;

        {
            std::lock_guard<std::mutex> lock(taskMutex_);

            // 获取当前时间
            uint64_t now = getCurrentTimeMs();

            // 处理所有到期的任务
            auto it = tasks_.begin();
            while (it != tasks_.end()) {
                if (it->deleteTime <= now) {
                    // 执行删除操作
                    EndpointMapper *mapper = EndpointMapper::getInstance();
                    if (mapper) {
                        if (!mapper->removeMapping(it->key, it->type)) {
                            qDebug() << "延迟删除映射失败:" << QString::fromStdString(it->key) << "类型:" << static_cast<int>(it->type) << "，映射可能已不存在";
                        }
                    }

                    // 从任务列表中移除
                    it = tasks_.erase(it);
                } else {
                    // 更新下一个任务时间
                    nextTaskTime = std::min(nextTaskTime, it->deleteTime);
                    ++it;
                }
            }
        }

        // 等待下一个任务或新任务通知
        std::unique_lock<std::mutex> lock(taskMutex_);
        if (nextTaskTime != UINT64_MAX) {
            // 计算等待时间
            uint64_t waitTime = nextTaskTime - getCurrentTimeMs();
            if (waitTime > 0) {
                // 等待指定时间或有新任务通知
                cv_.wait_for(lock, std::chrono::milliseconds(waitTime),
                             [this]() { return !running_ || tasks_.empty() || tasks_.front().deleteTime <= getCurrentTimeMs(); });
            }
        } else if (!tasks_.empty()) {
            // 有任务但都未到期，等待最早的任务
            cv_.wait_until(lock, std::chrono::system_clock::time_point(std::chrono::milliseconds(tasks_.front().deleteTime)));
        } else {
            // 没有任务，等待新任务通知
            cv_.wait(lock, [this]() { return !running_ || !tasks_.empty(); });
        }
    }
}

uint64_t DelayedDeleteManager::getCurrentTimeMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}