#include "ARPSpoofingController.h"
#include <QDebug>
#include <QDir>
#include <QThread>
#include <QMutexLocker>
#include <QTimer>
#include <QQueue>
#include <unistd.h>
#include <sys/time.h>

// For pthread_tryjoin_np
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <pthread.h>

ARPSpoofingController::ARPSpoofingController(QObject *parent)
    : QObject(parent)
    , spoofingThread(nullptr)
    , spoofingWorker(nullptr)
    , spoofing(false)
    , packetProcessTimer(new QTimer(this))
    , stopTimeoutTimer(nullptr)
{
    // Setup packet processing timer in main thread
    connect(packetProcessTimer, &QTimer::timeout, this, &ARPSpoofingController::processQueuedPackets);
    packetProcessTimer->setInterval(50); // Process packets every 50ms for responsive GUI
}

ARPSpoofingController::~ARPSpoofingController()
{
    if (spoofing) {
        stopSpoofing();
    }
    cleanupWorker();
}

void ARPSpoofingController::startSpoofing(const QStringList &targetIPs, const QString &interface)
{
    QMutexLocker locker(&spoofingMutex);
    
    if (spoofing) {
        qWarning() << "ARP spoofing already in progress";
        return;
    }
    
    if (targetIPs.isEmpty()) {
        emit spoofingError("No target IPs specified");
        return;
    }
    
    currentTargets = targetIPs;
    currentInterface = interface;
    
    setupWorker();
    
    spoofing = true;
    spoofingWorker->startSpoofing(targetIPs, interface);
    
    // Start packet processing timer in main thread
    packetProcessTimer->start();
    printf("[DEBUG] ARPSpoofingController: Started packet processing timer\n");
}

void ARPSpoofingController::stopSpoofing()
{
    QMutexLocker locker(&spoofingMutex);
    
    if (!spoofing) {
        return;
    }
    
    // Stop packet processing timer immediately
    packetProcessTimer->stop();
    printf("[DEBUG] ARPSpoofingController: Stopped packet processing timer\n");
    
    if (spoofingWorker) {
        // Use queued connection for non-blocking call
        QMetaObject::invokeMethod(spoofingWorker, "stopSpoofing", Qt::QueuedConnection);
    }
    
    // Set up timeout timer for stop operation
    if (!stopTimeoutTimer) {
        stopTimeoutTimer = new QTimer(this);
        stopTimeoutTimer->setSingleShot(true);
        connect(stopTimeoutTimer, &QTimer::timeout, this, &ARPSpoofingController::handleStopTimeout);
    }
    
    stopTimeoutTimer->start(6000); // 6 second timeout
    
    // Don't wait for completion here - let signals handle it
    spoofing = false;
    
    printf("[DEBUG] ARPSpoofingController: Stop request sent with timeout protection\n");
}

bool ARPSpoofingController::isSpoofing() const
{
    QMutexLocker locker(&spoofingMutex);
    return spoofing;
}

QStringList ARPSpoofingController::getCurrentTargets() const
{
    QMutexLocker locker(&spoofingMutex);
    return currentTargets;
}

QString ARPSpoofingController::getCurrentInterface() const
{
    QMutexLocker locker(&spoofingMutex);
    return currentInterface;
}

void ARPSpoofingController::setupWorker()
{
    cleanupWorker();
    
    spoofingThread = new QThread(this);
    spoofingWorker = new ARPSpoofingWorker();
    spoofingWorker->moveToThread(spoofingThread);
    
    // Connect worker signals
    connect(spoofingWorker, &ARPSpoofingWorker::spoofingStarted,
            this, &ARPSpoofingController::handleSpoofingStarted);
    connect(spoofingWorker, &ARPSpoofingWorker::spoofingStopped,
            this, &ARPSpoofingController::handleSpoofingStopped);
    connect(spoofingWorker, &ARPSpoofingWorker::packetCaptured,
            this, &ARPSpoofingController::handlePacketCaptured);
    connect(spoofingWorker, &ARPSpoofingWorker::errorOccurred,
            this, &ARPSpoofingController::handleWorkerError);
    connect(spoofingWorker, &ARPSpoofingWorker::finished,
            this, &ARPSpoofingController::handleWorkerFinished);
    
    // Connect thread management
    connect(spoofingWorker, &ARPSpoofingWorker::finished, spoofingThread, &QThread::quit);
    connect(spoofingThread, &QThread::finished, spoofingWorker, &QObject::deleteLater);
    connect(spoofingThread, &QThread::finished, spoofingThread, &QObject::deleteLater);
    
    spoofingThread->start();
}

void ARPSpoofingController::cleanupWorker()
{
    if (spoofingThread && spoofingThread->isRunning()) {
        // Request graceful shutdown
        spoofingThread->quit();
        
        // Wait with timeout
        if (!spoofingThread->wait(3000)) {
            qWarning() << "ARPSpoofingController: Thread didn't quit gracefully, terminating";
            spoofingThread->terminate();
            
            // Give it a moment to terminate
            if (!spoofingThread->wait(1000)) {
                qWarning() << "ARPSpoofingController: Thread termination failed";
            }
        }
    }
    
    spoofingThread = nullptr;
    spoofingWorker = nullptr;
}

void ARPSpoofingController::handleSpoofingStarted()
{
    emit spoofingStatusChanged(true);
}

void ARPSpoofingController::handleSpoofingStopped()
{
    if (stopTimeoutTimer) {
        stopTimeoutTimer->stop();
    }
    
    QMutexLocker locker(&spoofingMutex);
    spoofing = false;
    emit spoofingStatusChanged(false);
}

void ARPSpoofingController::handlePacketCaptured(const QByteArray &packetData, const struct timeval &timestamp)
{
    printf("[DEBUG] ARPSpoofingController: Received packet from worker, size: %d\n", packetData.size());
    printf("[DEBUG] ARPSpoofingController: Emitting targetPacketCaptured signal\n");
    emit targetPacketCaptured(packetData, timestamp);
}

void ARPSpoofingController::handleWorkerError(const QString &error)
{
    QMutexLocker locker(&spoofingMutex);
    spoofing = false;
    emit spoofingError(error);
}

void ARPSpoofingController::handleWorkerFinished()
{
    QMutexLocker locker(&spoofingMutex);
    spoofing = false;
}

void ARPSpoofingController::handleStopTimeout()
{
    qWarning() << "ARPSpoofingController: Stop operation timed out";
    
    {
        QMutexLocker locker(&spoofingMutex);
        spoofing = false;
    }
    
    // Force cleanup
    cleanupWorker();
    
    emit spoofingStatusChanged(false);
    emit spoofingError("Stop operation timed out - forced cleanup performed");
}

void ARPSpoofingController::processQueuedPackets()
{
    if (!spoofingWorker) {
        return;
    }
    
    // Access worker's packet queue safely
    QMutexLocker locker(&spoofingWorker->queueMutex);
    
    if (spoofingWorker->packetQueue.isEmpty()) {
        return;
    }
    
    printf("[DEBUG] ARPSpoofingController: Processing %d queued packets from main thread\n", spoofingWorker->packetQueue.size());
    
    while (!spoofingWorker->packetQueue.isEmpty()) {
        QByteArray packetData = spoofingWorker->packetQueue.dequeue();
        
        // Create timestamp
        struct timeval timestamp;
        gettimeofday(&timestamp, nullptr);
        
        printf("[DEBUG] ARPSpoofingController: Emitting targetPacketCaptured for packet size: %d\n", packetData.size());
        
        // Emit signal to forward to GUI
        emit targetPacketCaptured(packetData, timestamp);
    }
}

// ARPSpoofingWorker Implementation

// Static instance for C callback
ARPSpoofingWorker* ARPSpoofingWorker::instance = nullptr;

ARPSpoofingWorker::ARPSpoofingWorker()
    : shouldStop(false)
    , threadsStarted(false)
    , cleanupTimer(nullptr)
    , cleanupInProgress(false)
    , cleanupAttempts(0)
{
    instance = this;
}

ARPSpoofingWorker::~ARPSpoofingWorker()
{
    cleanupSpoofing();
    if (instance == this) {
        instance = nullptr;
    }
}

void ARPSpoofingWorker::startSpoofing(const QStringList &targetIPs, const QString &interface)
{
    this->targetIPs = targetIPs;
    this->interface = interface;
    shouldStop = false;
    
    qDebug() << "Starting ARP spoofing for targets:" << targetIPs << "on interface:" << interface;
    
    if (!initializeSpoofing(targetIPs, interface)) {
        emit errorOccurred("Failed to initialize ARP spoofing");
        emit finished();
        return;
    }
    
    emit spoofingStarted();
    
    qDebug() << "ARPSpoofingWorker: Spoofing started successfully, threads running in background";
}

void ARPSpoofingWorker::stopSpoofing()
{
    shouldStop = true;
    
    // Signal C backend to shutdown
    request_arp_shutdown();
    
    // Deactivate targets immediately
    for (int i = 0; i < target_count; i++) {
        targets[i].active = 0;
    }
    
    // Start asynchronous cleanup
    cleanupInProgress = true;
    cleanupAttempts = 0;
    
    if (!cleanupTimer) {
        cleanupTimer = new QTimer(this);
        connect(cleanupTimer, &QTimer::timeout, this, &ARPSpoofingWorker::performAsyncCleanup);
    }
    
    cleanupTimer->start(CLEANUP_TIMEOUT_MS);
    
    qDebug() << "ARPSpoofingWorker: Initiated async cleanup";
}

bool ARPSpoofingWorker::initializeSpoofing(const QStringList &targetIPs, const QString &interface)
{
    // Check if running as root (required for ARP spoofing)
    if (geteuid() != 0) {
        emit errorOccurred("ARP spoofing requires root privileges. Please run as root or with sudo.");
        return false;
    }
    
    // Change to the directory containing the backend code
    QString originalDir = QDir::currentPath();
    QDir::setCurrent("../src/packetcapture");
    
    // First, discover devices to get their MAC addresses
    scan_result_t scanResult;
    memset(&scanResult, 0, sizeof(scanResult));
    
    int result = run_lan_scan(&scanResult);
    
    // Restore original directory
    QDir::setCurrent(originalDir);
    
    if (result < 0) {
        emit errorOccurred("Failed to scan network for device information");
        return false;
    }
    
    // Setup the backend ARP spoofing
    if (!setupTargetsFromIPs(targetIPs, interface)) {
        return false;
    }
    
    // Get attacker MAC address
    strncpy(iface_name, interface.toUtf8().constData(), IFNAMSIZ - 1);
    iface_name[IFNAMSIZ - 1] = '\0';
    
    get_attacker_mac(iface_name, attacker_mac);
    get_interface_index(iface_name, &ifindex);
    
    // Start ARP spoofing thread
    if (pthread_create(&arpThread, NULL, arp_spoof_thread, NULL) != 0) {
        emit errorOccurred("Failed to create ARP spoofing thread");
        return false;
    }
    
    // Start packet sniffing thread
    if (pthread_create(&sniffThread, NULL, sniff_thread, NULL) != 0) {
        emit errorOccurred("Failed to create packet sniffing thread");
        pthread_cancel(arpThread);
        return false;
    }
    
    threadsStarted = true;
    return true;
}

bool ARPSpoofingWorker::setupTargetsFromIPs(const QStringList &targetIPs, const QString &interface)
{
    // Change to the directory containing the backend code
    QString originalDir = QDir::currentPath();
    QDir::setCurrent("../src/packetcapture");
    
    // Discover devices to get MAC addresses
    scan_result_t scanResult;
    memset(&scanResult, 0, sizeof(scanResult));
    
    int result = run_lan_scan(&scanResult);
    
    // Restore original directory
    QDir::setCurrent(originalDir);
    
    if (result < 0) {
        return false;
    }
    
    // Create target indices array for the backend
    int targetIndices[MAX_TARGETS];
    int validTargetCount = 0;
    
    // Find indices of target IPs in the scan results
    for (const QString &targetIP : targetIPs) {
        for (int i = 0; i < scanResult.count && validTargetCount < MAX_TARGETS; i++) {
            if (QString::fromUtf8(scanResult.devices[i].ip) == targetIP) {
                targetIndices[validTargetCount] = i;
                validTargetCount++;
                break;
            }
        }
    }
    
    if (validTargetCount == 0) {
        emit errorOccurred("No valid targets found in network scan");
        return false;
    }
    
    // Setup targets using the backend function
    setup_targets(&scanResult, targetIndices, validTargetCount);
    
    // Set up packet callback to receive captured packets
    qDebug() << "ARPSpoofingWorker: Setting packet callback";
    set_packet_callback(packetCallbackHandler);
    qDebug() << "ARPSpoofingWorker: Packet callback set successfully";
    
    qDebug() << "Successfully setup" << validTargetCount << "targets for ARP spoofing";
    return true;
}

void ARPSpoofingWorker::performAsyncCleanup()
{
    cleanupAttempts++;
    
    if (threadsStarted) {
        // Try non-blocking thread termination
        int arp_result = pthread_tryjoin_np(arpThread, NULL);
        int sniff_result = pthread_tryjoin_np(sniffThread, NULL);
        
        if (arp_result == 0 && sniff_result == 0) {
            // Both threads terminated successfully
            threadsStarted = false;
            cleanupTimer->stop();
            cleanupInProgress = false;
            
            // Clear packet callback
            set_packet_callback(nullptr);
            target_count = 0;
            
            emit spoofingStopped();
            emit finished();
            
            qDebug() << "ARPSpoofingWorker: Cleanup completed successfully";
            return;
        }
        
        if (cleanupAttempts >= MAX_CLEANUP_ATTEMPTS) {
            // Force termination as last resort
            qWarning() << "ARPSpoofingWorker: Force terminating threads after" << cleanupAttempts << "attempts";
            
            pthread_cancel(arpThread);
            pthread_cancel(sniffThread);
            
            // Give threads a moment to terminate
            QTimer::singleShot(100, this, [this]() {
                pthread_detach(arpThread);
                pthread_detach(sniffThread);
                threadsStarted = false;
                
                set_packet_callback(nullptr);
                target_count = 0;
                
                cleanupTimer->stop();
                cleanupInProgress = false;
                
                emit spoofingStopped();
                emit finished();
                
                qWarning() << "ARPSpoofingWorker: Forced cleanup completed";
            });
            
            return;
        }
    } else {
        // No threads to clean up
        cleanupTimer->stop();
        cleanupInProgress = false;
        
        emit spoofingStopped();
        emit finished();
    }
    
    qDebug() << "ARPSpoofingWorker: Cleanup attempt" << cleanupAttempts << "of" << MAX_CLEANUP_ATTEMPTS;
}

void ARPSpoofingWorker::cleanupSpoofing()
{
    // This method is now deprecated in favor of performAsyncCleanup
    // Keep it for compatibility but make it non-blocking
    if (threadsStarted) {
        // Just signal for shutdown, don't wait
        pthread_cancel(arpThread);
        pthread_cancel(sniffThread);
        pthread_detach(arpThread);
        pthread_detach(sniffThread);
        threadsStarted = false;
    }
    
    // Clear packet callback
    set_packet_callback(nullptr);
    
    // Reset target count
    target_count = 0;
}

// Static callback function for C backend
void ARPSpoofingWorker::packetCallbackHandler(const unsigned char *packet_data, int packet_len, int target_index)
{
    printf("[DEBUG] ARPSpoofingWorker: Callback received packet, size: %d, target: %d\n", packet_len, target_index);
    
    if (!instance) {
        printf("[DEBUG] ARPSpoofingWorker: No instance available for callback\n");
        return;
    }
    
    // Thread-safe packet queuing
    QMutexLocker locker(&instance->queueMutex);
    QByteArray packetData(reinterpret_cast<const char*>(packet_data), packet_len);
    instance->packetQueue.enqueue(packetData);
    printf("[DEBUG] ARPSpoofingWorker: Packet queued, queue size: %d\n", instance->packetQueue.size());
}



// Handle captured packet from backend (now unused but kept for compatibility)
void ARPSpoofingWorker::handleCapturedPacket(const unsigned char *packet_data, int packet_len)
{
    // This method is now unused - packets are processed via the queue
    qDebug() << "ARPSpoofingWorker: handleCapturedPacket called (should not happen)";
}