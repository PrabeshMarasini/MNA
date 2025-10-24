#include "MemoryManager.h"
#include "ErrorHandler.h"
#include <QApplication>
#include <QDebug>
#include <QMutexLocker>
#include <QDateTime>
#include <QTextStream>

#ifdef Q_OS_LINUX
#include <sys/sysinfo.h>
#include <unistd.h>
#include <fstream>
#endif

#ifdef Q_OS_WIN
#include <windows.h>
#include <psapi.h>
#endif

MemoryManager* MemoryManager::s_instance = nullptr;

MemoryManager::MemoryManager(QObject *parent)
    : QObject(parent)
    , m_monitoringEnabled(false)
    , m_monitoringInterval(5000) // 5 seconds default
    , m_mediumThreshold(70.0)    // 70% memory usage
    , m_highThreshold(85.0)      // 85% memory usage
    , m_criticalThreshold(95.0)  // 95% memory usage
    , m_currentPressure(Low)
    , m_lastPressure(Low)
    , m_monitorTimer(new QTimer(this))
    , m_allocationCount(0)
    , m_deallocationCount(0)
{
    // Initialize stats
    memset(&m_currentStats, 0, sizeof(m_currentStats));
    
    connect(m_monitorTimer, &QTimer::timeout, this, &MemoryManager::monitorMemory);
    
    qDebug() << "MemoryManager: Initialized";
}

MemoryManager::~MemoryManager()
{
    if (m_monitoringEnabled) {
        setMonitoringEnabled(false);
    }
    
    // Check for remaining allocations
    if (!m_allocations.isEmpty()) {
        LOG_MEMORY_ERROR(QString("Memory leak detected: %1 unfreed allocations").arg(m_allocations.size()),
                        generateMemoryReport());
    }
}

MemoryManager* MemoryManager::instance()
{
    if (!s_instance) {
        s_instance = new MemoryManager();
    }
    return s_instance;
}

void MemoryManager::initialize()
{
    updateSystemMemoryInfo();
    updateProcessMemoryInfo();
    setMonitoringEnabled(true);
    
    LOG_INFO("MemoryManager initialized");
}

void MemoryManager::setMonitoringEnabled(bool enabled)
{
    if (m_monitoringEnabled == enabled) return;
    
    m_monitoringEnabled = enabled;
    
    if (enabled) {
        m_monitorTimer->start(m_monitoringInterval);
        LOG_INFO("Memory monitoring enabled");
    } else {
        m_monitorTimer->stop();
        LOG_INFO("Memory monitoring disabled");
    }
}

void MemoryManager::setMonitoringInterval(int intervalMs)
{
    m_monitoringInterval = intervalMs;
    if (m_monitoringEnabled) {
        m_monitorTimer->setInterval(intervalMs);
    }
}

void MemoryManager::setMemoryThresholds(double medium, double high, double critical)
{
    m_mediumThreshold = medium;
    m_highThreshold = high;
    m_criticalThreshold = critical;
    
    LOG_INFO(QString("Memory thresholds updated: Medium=%1%, High=%2%, Critical=%3%")
             .arg(medium).arg(high).arg(critical));
}

MemoryManager::MemoryStats MemoryManager::getMemoryStats() const
{
    QMutexLocker locker(&m_statsMutex);
    return m_currentStats;
}

MemoryManager::MemoryPressure MemoryManager::getMemoryPressure() const
{
    return m_currentPressure;
}

void MemoryManager::performCleanup()
{
    LOG_INFO("Performing memory cleanup");
    
    try {
        // Force Qt to clean up deleted objects
        QApplication::processEvents();
        
        // Trigger garbage collection if available
        // Note: Qt doesn't have explicit GC, but we can clean up caches
        
        // Clear any internal caches or temporary data
        // This would be application-specific
        
        // Update memory stats after cleanup
        updateProcessMemoryInfo();
        
        LOG_INFO("Memory cleanup completed");
        
    } catch (const std::exception &e) {
        LOG_MEMORY_ERROR("Exception during memory cleanup", e.what());
    } catch (...) {
        LOG_MEMORY_ERROR("Unknown exception during memory cleanup", "");
    }
}

bool MemoryManager::checkForLeaks()
{
    QMutexLocker locker(&m_allocationMutex);
    
    if (m_allocations.isEmpty()) {
        return false;
    }
    
    // Check for old allocations that might be leaks
    qint64 currentTime = QDateTime::currentMSecsSinceEpoch();
    int suspiciousAllocations = 0;
    
    for (auto it = m_allocations.begin(); it != m_allocations.end(); ++it) {
        qint64 age = currentTime - it.value().timestamp;
        if (age > 300000) { // 5 minutes
            suspiciousAllocations++;
        }
    }
    
    if (suspiciousAllocations > 0) {
        QString details = QString("Found %1 allocations older than 5 minutes (total: %2)")
                         .arg(suspiciousAllocations).arg(m_allocations.size());
        emit memoryLeakDetected(details);
        LOG_MEMORY_ERROR("Potential memory leak detected", details);
        return true;
    }
    
    return false;
}

QString MemoryManager::generateMemoryReport() const
{
    QMutexLocker statsLocker(&m_statsMutex);
    QMutexLocker allocLocker(&m_allocationMutex);
    
    QString report;
    QTextStream stream(&report);
    
    stream << "=== MEMORY USAGE REPORT ===\n";
    stream << "Generated: " << QDateTime::currentDateTime().toString(Qt::ISODate) << "\n\n";
    
    // System memory
    stream << "SYSTEM MEMORY:\n";
    stream << "  Total: " << formatMemorySize(m_currentStats.totalMemory) << "\n";
    stream << "  Available: " << formatMemorySize(m_currentStats.availableMemory) << "\n";
    stream << "  Usage: " << QString::number(m_currentStats.memoryUsagePercent, 'f', 1) << "%\n\n";
    
    // Process memory
    stream << "PROCESS MEMORY:\n";
    stream << "  Current: " << formatMemorySize(m_currentStats.processMemory) << "\n";
    stream << "  Peak: " << formatMemorySize(m_currentStats.peakMemory) << "\n\n";
    
    // Memory pressure
    stream << "MEMORY PRESSURE: ";
    switch (m_currentPressure) {
        case Low: stream << "Low\n"; break;
        case Medium: stream << "Medium\n"; break;
        case High: stream << "High\n"; break;
        case Critical: stream << "Critical\n"; break;
    }
    stream << "\n";
    
    // Allocation tracking
    stream << "ALLOCATION TRACKING:\n";
    stream << "  Total Allocations: " << m_allocationCount << "\n";
    stream << "  Total Deallocations: " << m_deallocationCount << "\n";
    stream << "  Current Tracked: " << m_allocations.size() << "\n";
    stream << "  Potential Leaks: " << (m_allocationCount - m_deallocationCount) << "\n\n";
    
    // Recent allocations
    if (!m_allocations.isEmpty()) {
        stream << "RECENT ALLOCATIONS (Last 10):\n";
        // Show recent allocations (up to 10)
        auto keys = m_allocations.keys();
        int count = 0;
        for (auto it = keys.rbegin(); it != keys.rend() && count < 10; ++it, ++count) {
            const auto& info = m_allocations[*it];
            stream << "  " << formatMemorySize(info.size) 
                   << " - " << info.context 
                   << " (" << QDateTime::fromMSecsSinceEpoch(info.timestamp).toString() << ")\n";
        }
    }
    
    stream << "\n=== END OF REPORT ===\n";
    
    return report;
}

void MemoryManager::registerAllocation(void* ptr, size_t size, const QString& context)
{
    if (!ptr) return;
    
    QMutexLocker locker(&m_allocationMutex);
    
    AllocationInfo info;
    info.size = size;
    info.context = context;
    info.timestamp = QDateTime::currentMSecsSinceEpoch();
    
    m_allocations[ptr] = info;
    m_allocationCount++;
}

void MemoryManager::registerDeallocation(void* ptr)
{
    if (!ptr) return;
    
    QMutexLocker locker(&m_allocationMutex);
    
    if (m_allocations.remove(ptr) > 0) {
        m_deallocationCount++;
    }
}

void MemoryManager::handleLowMemory()
{
    LOG_WARNING("Low memory situation detected");
    
    // Perform light cleanup
    QApplication::processEvents();
    
    emit lowMemoryWarning();
}

void MemoryManager::handleCriticalMemory()
{
    LOG_CRITICAL("Critical memory situation detected");
    
    // Perform aggressive cleanup
    performCleanup();
    
    // Force immediate garbage collection
    QApplication::processEvents();
    
    emit criticalMemoryWarning();
}

void MemoryManager::monitorMemory()
{
    updateSystemMemoryInfo();
    updateProcessMemoryInfo();
    
    MemoryPressure newPressure = calculateMemoryPressure();
    
    if (newPressure != m_currentPressure) {
        m_lastPressure = m_currentPressure;
        m_currentPressure = newPressure;
        
        emit memoryPressureChanged(newPressure);
        
        // Trigger appropriate response
        switch (newPressure) {
            case Medium:
                if (m_lastPressure < Medium) {
                    LOG_WARNING("Memory pressure increased to Medium");
                }
                break;
            case High:
                if (m_lastPressure < High) {
                    LOG_WARNING("Memory pressure increased to High");
                    handleLowMemory();
                }
                break;
            case Critical:
                if (m_lastPressure < Critical) {
                    LOG_CRITICAL("Memory pressure reached Critical level");
                    handleCriticalMemory();
                }
                break;
            default:
                break;
        }
    }
    
    // Check for memory leaks periodically
    static int leakCheckCounter = 0;
    if (++leakCheckCounter >= 12) { // Every minute if monitoring every 5 seconds
        checkForLeaks();
        leakCheckCounter = 0;
    }
    
    emit memoryStatsUpdated(m_currentStats);
}

void MemoryManager::updateSystemMemoryInfo()
{
    QMutexLocker locker(&m_statsMutex);
    
#ifdef Q_OS_LINUX
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        m_currentStats.totalMemory = info.totalram * info.mem_unit;
        m_currentStats.availableMemory = info.freeram * info.mem_unit;
    }
#elif defined(Q_OS_WIN)
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        m_currentStats.totalMemory = memInfo.ullTotalPhys;
        m_currentStats.availableMemory = memInfo.ullAvailPhys;
    }
#endif
    
    if (m_currentStats.totalMemory > 0) {
        qint64 usedMemory = m_currentStats.totalMemory - m_currentStats.availableMemory;
        m_currentStats.memoryUsagePercent = (double)usedMemory / m_currentStats.totalMemory * 100.0;
    }
}

void MemoryManager::updateProcessMemoryInfo()
{
    QMutexLocker locker(&m_statsMutex);
    
#ifdef Q_OS_LINUX
    std::ifstream statusFile("/proc/self/status");
    std::string line;
    
    while (std::getline(statusFile, line)) {
        if (line.substr(0, 6) == "VmRSS:") {
            size_t pos = line.find_first_of("0123456789");
            if (pos != std::string::npos) {
                qint64 rss = std::stoll(line.substr(pos)) * 1024; // Convert KB to bytes
                m_currentStats.processMemory = rss;
                if (rss > m_currentStats.peakMemory) {
                    m_currentStats.peakMemory = rss;
                }
            }
            break;
        }
    }
#elif defined(Q_OS_WIN)
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        m_currentStats.processMemory = pmc.WorkingSetSize;
        if (pmc.PeakWorkingSetSize > m_currentStats.peakMemory) {
            m_currentStats.peakMemory = pmc.PeakWorkingSetSize;
        }
    }
#endif
    
    // Update allocation counts
    QMutexLocker allocLocker(&m_allocationMutex);
    m_currentStats.allocationCount = m_allocationCount;
    m_currentStats.deallocationCount = m_deallocationCount;
}

MemoryManager::MemoryPressure MemoryManager::calculateMemoryPressure() const
{
    double usage = m_currentStats.memoryUsagePercent;
    
    if (usage >= m_criticalThreshold) {
        return Critical;
    } else if (usage >= m_highThreshold) {
        return High;
    } else if (usage >= m_mediumThreshold) {
        return Medium;
    } else {
        return Low;
    }
}

void MemoryManager::triggerCleanupIfNeeded()
{
    MemoryPressure pressure = getMemoryPressure();
    
    if (pressure >= High) {
        performCleanup();
    }
}

QString MemoryManager::formatMemorySize(qint64 bytes) const
{
    const qint64 KB = 1024;
    const qint64 MB = KB * 1024;
    const qint64 GB = MB * 1024;
    
    if (bytes >= GB) {
        return QString("%1 GB").arg(bytes / (double)GB, 0, 'f', 2);
    } else if (bytes >= MB) {
        return QString("%1 MB").arg(bytes / (double)MB, 0, 'f', 1);
    } else if (bytes >= KB) {
        return QString("%1 KB").arg(bytes / (double)KB, 0, 'f', 0);
    } else {
        return QString("%1 bytes").arg(bytes);
    }
}