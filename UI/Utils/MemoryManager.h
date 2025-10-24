#ifndef MEMORYMANAGER_H
#define MEMORYMANAGER_H

#include <QObject>
#include <QTimer>
#include <QMutex>
#include <QHash>
#include <memory>

/**
 * @brief Memory management and monitoring utility
 * 
 * This class provides memory monitoring, leak detection, and recovery
 * mechanisms for the packet capture GUI application.
 */
class MemoryManager : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Memory usage statistics
     */
    struct MemoryStats {
        qint64 totalMemory;         ///< Total system memory
        qint64 availableMemory;     ///< Available system memory
        qint64 processMemory;       ///< Current process memory usage
        qint64 peakMemory;          ///< Peak memory usage since start
        double memoryUsagePercent;  ///< Memory usage percentage
        int allocationCount;        ///< Number of allocations tracked
        int deallocationCount;      ///< Number of deallocations tracked
    };

    /**
     * @brief Memory pressure levels
     */
    enum MemoryPressure {
        Low = 0,        ///< Normal memory usage
        Medium,         ///< Moderate memory pressure
        High,           ///< High memory pressure
        Critical        ///< Critical memory situation
    };

    /**
     * @brief Get singleton instance
     */
    static MemoryManager* instance();

    /**
     * @brief Initialize memory manager
     */
    void initialize();

    /**
     * @brief Enable/disable memory monitoring
     */
    void setMonitoringEnabled(bool enabled);

    /**
     * @brief Set monitoring interval in milliseconds
     */
    void setMonitoringInterval(int intervalMs);

    /**
     * @brief Set memory pressure thresholds (as percentages)
     */
    void setMemoryThresholds(double medium, double high, double critical);

    /**
     * @brief Get current memory statistics
     */
    MemoryStats getMemoryStats() const;

    /**
     * @brief Get current memory pressure level
     */
    MemoryPressure getMemoryPressure() const;

    /**
     * @brief Force garbage collection and cleanup
     */
    void performCleanup();

    /**
     * @brief Check for memory leaks
     */
    bool checkForLeaks();

    /**
     * @brief Get memory usage report
     */
    QString generateMemoryReport() const;

    /**
     * @brief Safe memory allocation with error handling
     */
    template<typename T>
    std::unique_ptr<T> safeAllocate(size_t count = 1);

    /**
     * @brief Safe array allocation with error handling
     */
    template<typename T>
    std::unique_ptr<T[]> safeAllocateArray(size_t count);

    /**
     * @brief Register memory allocation for tracking
     */
    void registerAllocation(void* ptr, size_t size, const QString& context = QString());

    /**
     * @brief Register memory deallocation for tracking
     */
    void registerDeallocation(void* ptr);

public slots:
    /**
     * @brief Handle low memory situation
     */
    void handleLowMemory();

    /**
     * @brief Handle critical memory situation
     */
    void handleCriticalMemory();

signals:
    /**
     * @brief Emitted when memory pressure changes
     */
    void memoryPressureChanged(MemoryPressure pressure);

    /**
     * @brief Emitted when low memory is detected
     */
    void lowMemoryWarning();

    /**
     * @brief Emitted when critical memory is detected
     */
    void criticalMemoryWarning();

    /**
     * @brief Emitted when memory statistics update
     */
    void memoryStatsUpdated(const MemoryStats& stats);

    /**
     * @brief Emitted when potential memory leak is detected
     */
    void memoryLeakDetected(const QString& details);

private slots:
    /**
     * @brief Monitor memory usage
     */
    void monitorMemory();

private:
    explicit MemoryManager(QObject *parent = nullptr);
    ~MemoryManager();

    /**
     * @brief Get system memory information
     */
    void updateSystemMemoryInfo();

    /**
     * @brief Get process memory information
     */
    void updateProcessMemoryInfo();

    /**
     * @brief Calculate memory pressure level
     */
    MemoryPressure calculateMemoryPressure() const;

    /**
     * @brief Trigger memory cleanup based on pressure
     */
    void triggerCleanupIfNeeded();

    /**
     * @brief Format memory size for display
     */
    QString formatMemorySize(qint64 bytes) const;

    static MemoryManager* s_instance;

    // Configuration
    bool m_monitoringEnabled;
    int m_monitoringInterval;
    double m_mediumThreshold;
    double m_highThreshold;
    double m_criticalThreshold;

    // Statistics
    mutable QMutex m_statsMutex;
    MemoryStats m_currentStats;
    MemoryPressure m_currentPressure;
    MemoryPressure m_lastPressure;

    // Monitoring
    QTimer* m_monitorTimer;

    // Allocation tracking
    struct AllocationInfo {
        size_t size;
        QString context;
        qint64 timestamp;
    };
    mutable QMutex m_allocationMutex;
    QHash<void*, AllocationInfo> m_allocations;
    int m_allocationCount;
    int m_deallocationCount;
};

// Template implementations
template<typename T>
std::unique_ptr<T> MemoryManager::safeAllocate(size_t count)
{
    try {
        if (getMemoryPressure() >= Critical) {
            performCleanup();
            
            // Check again after cleanup
            if (getMemoryPressure() >= Critical) {
                throw std::bad_alloc();
            }
        }

        auto ptr = std::make_unique<T>();
        registerAllocation(ptr.get(), sizeof(T) * count, QString("safeAllocate<%1>").arg(typeid(T).name()));
        return ptr;
        
    } catch (const std::bad_alloc&) {
        // Try emergency cleanup
        performCleanup();
        
        try {
            auto ptr = std::make_unique<T>();
            registerAllocation(ptr.get(), sizeof(T) * count, QString("safeAllocate<%1>_retry").arg(typeid(T).name()));
            return ptr;
        } catch (const std::bad_alloc&) {
            // Final failure
            emit criticalMemoryWarning();
            throw;
        }
    }
}

template<typename T>
std::unique_ptr<T[]> MemoryManager::safeAllocateArray(size_t count)
{
    try {
        if (getMemoryPressure() >= Critical) {
            performCleanup();
            
            if (getMemoryPressure() >= Critical) {
                throw std::bad_alloc();
            }
        }

        auto ptr = std::make_unique<T[]>(count);
        registerAllocation(ptr.get(), sizeof(T) * count, QString("safeAllocateArray<%1>[%2]").arg(typeid(T).name()).arg(count));
        return ptr;
        
    } catch (const std::bad_alloc&) {
        performCleanup();
        
        try {
            auto ptr = std::make_unique<T[]>(count);
            registerAllocation(ptr.get(), sizeof(T) * count, QString("safeAllocateArray<%1>[%2]_retry").arg(typeid(T).name()).arg(count));
            return ptr;
        } catch (const std::bad_alloc&) {
            emit criticalMemoryWarning();
            throw;
        }
    }
}

#endif // MEMORYMANAGER_H