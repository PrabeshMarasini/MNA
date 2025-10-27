#include "PacketCaptureController.h"
#include "Utils/DataValidator.h"
#include "Utils/ErrorHandler.h"
#include "Utils/PacketInfoGenerator.h"
#include "Wrappers/ProtocolAnalysisWrapper.h"
#include <QDebug>
#include <QMutexLocker>
#include <QCoreApplication>
#include <QTimeZone>

// PacketCaptureController implementation
PacketCaptureController::PacketCaptureController(const QString &interface, QObject *parent)
    : QObject(parent)
    , networkInterface(interface)
    , captureThread(nullptr)
    , captureWorker(nullptr)
    , capturing(false)
    , spoofingMode(false)
    , packetCount(0)
    , totalBytes(0)
    , statisticsTimer(new QTimer(this))
{
    setupWorker();
    
    // Statistics timer
    connect(statisticsTimer, &QTimer::timeout, this, [this]() {
        emit statisticsUpdated(packetCount, totalBytes);
    });
    statisticsTimer->start(1000); // Update statistics every second
}

PacketCaptureController::~PacketCaptureController() {
    stopCapture();
    cleanupWorker();
}

bool PacketCaptureController::isCapturing() const {
    QMutexLocker locker(&captureMutex);
    return capturing;
}

QString PacketCaptureController::getInterface() const {
    return networkInterface;
}

bool PacketCaptureController::isSpoofingMode() const {
    QMutexLocker locker(&captureMutex);
    return spoofingMode;
}

void PacketCaptureController::startCapture() {
    QMutexLocker locker(&captureMutex);
    
    try {
        
        if (capturing) {
            LOG_WARNING("Capture already in progress");
            return;
        }
        
        if (networkInterface.isEmpty()) {
            QString errorMsg = "No network interface specified";
            LOG_CAPTURE_ERROR(errorMsg, "Interface must be selected before starting capture");
            emit captureError(errorMsg);
            return;
        }
        
        
        if (!captureWorker) {
            setupWorker();
        }
        
        if (!captureWorker) {
            QString errorMsg = "Failed to create capture worker";
            LOG_CAPTURE_ERROR(errorMsg, "Worker thread initialization failed");
            emit captureError(errorMsg);
            return;
        }
    
        capturing = true;
        packetCount = 0;
        totalBytes = 0;
        
        // Set filter if specified
        if (!currentFilter.isEmpty()) {
            QMetaObject::invokeMethod(captureWorker, "setFilter", 
                                     Qt::QueuedConnection,
                                     Q_ARG(QString, currentFilter));
        }
        
        // Set spoofing targets if in spoofing mode
        if (spoofingMode && !this->targetMACs.isEmpty()) {
            captureWorker->spoofingTargets = this->targetMACs;
            captureWorker->spoofingModeActive = true;
        }
        
        // Start capture
        QMetaObject::invokeMethod(captureWorker, "startCapture", Qt::QueuedConnection);
        
        emit captureStatusChanged(true);
        
        LOG_INFO(QString("Started packet capture on interface: %1").arg(networkInterface));
        
    } catch (const std::exception &e) {
        QString errorMsg = QString("Exception during capture start: %1").arg(e.what());
        LOG_CAPTURE_ERROR(errorMsg, "Unexpected error during capture initialization");
        emit captureError(errorMsg);
        capturing = false;
    } catch (...) {
        QString errorMsg = "Unknown exception during capture start";
        LOG_CAPTURE_ERROR(errorMsg, "Unexpected error during capture initialization");
        emit captureError(errorMsg);
        capturing = false;
    }
}

void PacketCaptureController::stopCapture() {
    QMutexLocker locker(&captureMutex);
    
    if (!capturing) {
        return;
    }
    
    capturing = false;
    
    if (captureWorker) {
        QMetaObject::invokeMethod(captureWorker, "stopCapture", Qt::QueuedConnection);
    }
    
    emit captureStatusChanged(false);
    
    qDebug() << "Stopped packet capture. Total packets:" << packetCount << "Total bytes:" << totalBytes;
}

void PacketCaptureController::setPacketFilter(const QString &filter) {
    currentFilter = filter;
    
    if (captureWorker && capturing) {
        QMetaObject::invokeMethod(captureWorker, "setFilter", 
                                 Qt::QueuedConnection,
                                 Q_ARG(QString, filter));
    }
}

void PacketCaptureController::setSpoofingMode(bool enabled, const QList<QString> &targetMACs) {
    QMutexLocker locker(&captureMutex);
    
    spoofingMode = enabled;
    this->targetMACs = targetMACs;
    
    // Store the spoofing targets in the worker directly without using slots
    if (captureWorker) {
        captureWorker->spoofingTargets = targetMACs;
        captureWorker->spoofingModeActive = enabled && !targetMACs.isEmpty();
    }
    
    qDebug() << "PacketCaptureController: Spoofing mode" << (enabled ? "enabled" : "disabled") 
             << "with" << targetMACs.size() << "targets";
}

void PacketCaptureController::processCapturedPacket(const QByteArray &packetData, const struct timeval &timestamp) {
    if (!capturing) {
        return;
    }
    
    try {
        
        PacketInfo packet = createPacketInfo(packetData, timestamp);
        
        
        // Validate packet
        if (!DataValidator::isValidPacketInfo(packet)) {
            qWarning() << "Invalid packet data:" << DataValidator::getLastError();
            return;
        }
        
        // Update statistics
        {
            QMutexLocker locker(&captureMutex);
            packetCount++;
            totalBytes += packet.packetLength;
        }
        
        emit packetCaptured(packet);
        
    } catch (const std::exception &e) {
        qWarning() << "Error processing packet:" << e.what();
    }
}

void PacketCaptureController::handleWorkerError(const QString &error) {
    qWarning() << "Capture worker error:" << error;
    
    {
        QMutexLocker locker(&captureMutex);
        capturing = false;
    }
    
    emit captureError(error);
    emit captureStatusChanged(false);
}

void PacketCaptureController::processCapturedPacketBatch(const QList<QPair<QByteArray, struct timeval>> &packets) {
    if (!capturing || packets.isEmpty()) {
        return;
    }
    
    try {
        QList<PacketInfo> processedPackets;
        
        for (const auto &packetPair : packets) {
            // In spoofing mode, filter packets to only include target devices
            if (spoofingMode && !isTargetPacket(packetPair.first)) {
                continue;
            }
            
            PacketInfo packet = createPacketInfo(packetPair.first, packetPair.second);
            
            // Validate packet
            if (DataValidator::isValidPacketInfo(packet)) {
                processedPackets.append(packet);
                
                // Update statistics
                {
                    QMutexLocker locker(&captureMutex);
                    packetCount++;
                    totalBytes += packet.packetLength;
                }
            }
        }
        
        // Emit batch of processed packets
        if (!processedPackets.isEmpty()) {
            emit packetsBatchCaptured(processedPackets);
        }
        
    } catch (const std::exception &e) {
        qWarning() << "Error processing packet batch:" << e.what();
    }
}

void PacketCaptureController::handleWorkerFinished() {
    qDebug() << "Capture worker finished";
    
    {
        QMutexLocker locker(&captureMutex);
        capturing = false;
    }
    
    emit captureStatusChanged(false);
}

void PacketCaptureController::setupWorker() {
    if (captureThread || captureWorker) {
        cleanupWorker();
    }
    
    captureThread = new QThread(this);
    captureWorker = new PacketCaptureWorker(networkInterface);
    captureWorker->moveToThread(captureThread);
    
    // Connect worker signals
    connect(captureWorker, &PacketCaptureWorker::packetReady,
            this, &PacketCaptureController::processCapturedPacket,
            Qt::QueuedConnection);
    connect(captureWorker, &PacketCaptureWorker::packetsBatchReady,
            this, &PacketCaptureController::processCapturedPacketBatch,
            Qt::QueuedConnection);
    connect(captureWorker, &PacketCaptureWorker::errorOccurred,
            this, &PacketCaptureController::handleWorkerError,
            Qt::QueuedConnection);
    connect(captureWorker, &PacketCaptureWorker::finished,
            this, &PacketCaptureController::handleWorkerFinished,
            Qt::QueuedConnection);
    
    // Thread management
    connect(captureThread, &QThread::started,
            captureWorker, &PacketCaptureWorker::initialize,
            Qt::QueuedConnection);
    connect(captureThread, &QThread::finished,
            captureWorker, &QObject::deleteLater);
    
    captureThread->start();
    
    qDebug() << "Capture worker setup completed for interface:" << networkInterface;
}

void PacketCaptureController::cleanupWorker() {
    if (capturing) {
        stopCapture();
    }
    
    if (captureThread) {
        captureThread->quit();
        if (!captureThread->wait(5000)) {
            qWarning() << "Capture thread did not finish within timeout, terminating";
            captureThread->terminate();
            captureThread->wait(1000);
        }
        captureThread = nullptr;
    }
    
    captureWorker = nullptr; // Will be deleted by thread finished signal
}

bool PacketCaptureController::isTargetPacket(const QByteArray &packetData) const {
    if (!spoofingMode || targetMACs.isEmpty() || packetData.size() < 14) {
        return true; // In normal mode, accept all packets
    }
    
    // Extract source and destination MAC addresses from Ethernet header
    const unsigned char *data = reinterpret_cast<const unsigned char*>(packetData.constData());
    
    // Destination MAC (first 6 bytes)
    QString destMAC = QString("%1:%2:%3:%4:%5:%6")
                     .arg(data[0], 2, 16, QChar('0'))
                     .arg(data[1], 2, 16, QChar('0'))
                     .arg(data[2], 2, 16, QChar('0'))
                     .arg(data[3], 2, 16, QChar('0'))
                     .arg(data[4], 2, 16, QChar('0'))
                     .arg(data[5], 2, 16, QChar('0')).toUpper();
    
    // Source MAC (bytes 6-11)
    QString srcMAC = QString("%1:%2:%3:%4:%5:%6")
                    .arg(data[6], 2, 16, QChar('0'))
                    .arg(data[7], 2, 16, QChar('0'))
                    .arg(data[8], 2, 16, QChar('0'))
                    .arg(data[9], 2, 16, QChar('0'))
                    .arg(data[10], 2, 16, QChar('0'))
                    .arg(data[11], 2, 16, QChar('0')).toUpper();
    
    // Check if either source or destination MAC is in our target list
    for (const QString &targetMAC : targetMACs) {
        QString normalizedTarget = targetMAC.toUpper();
        if (srcMAC == normalizedTarget || destMAC == normalizedTarget) {
            return true;
        }
    }
    
    return false;
}

PacketInfo PacketCaptureController::createPacketInfo(const QByteArray &packetData, const struct timeval &timestamp) {
    PacketInfo packet;
    
    // Set basic packet information
    packet.timestamp = QDateTime::fromSecsSinceEpoch(timestamp.tv_sec, QTimeZone::UTC)
                      .addMSecs(timestamp.tv_usec / 1000);
    packet.packetLength = packetData.size();
    packet.rawData = packetData;
    
    // Set serial number - this will be overridden by PacketModel but needs to be valid for validation
    packet.serialNumber = packetCount + 1;
    
    // Extract basic protocol information using wrapper (lightweight operations)
    packet.sourceIP = ProtocolAnalysisWrapper::extractSourceIP(packetData);
    packet.destinationIP = ProtocolAnalysisWrapper::extractDestinationIP(packetData);
    packet.protocolType = ProtocolAnalysisWrapper::extractProtocolType(packetData);
    
    // Generate more info for the packet
    packet.moreInfo = PacketInfoGenerator::generateMoreInfo(
        packet.protocolType,
        packet.sourceIP,
        packet.destinationIP,
        packet.packetLength,
        packet.rawData
    );
    
    // PERFORMANCE IMPROVEMENT: Don't perform full protocol analysis immediately
    // Analysis will be done lazily when packet is selected
    // analysisResult is now initialized with default constructor
    
    return packet;
}

// PacketCaptureWorker implementation
PacketCaptureWorker::PacketCaptureWorker(const QString &interface)
    : QObject(nullptr) // No parent - will be moved to thread
    , interface(interface)
    , pcapHandle(nullptr)
    , shouldStop(false)
    , spoofingModeActive(false)
    , processTimer(new QTimer(this))
{
    // Initialize error buffer
    memset(errorBuffer, 0, sizeof(errorBuffer));
    
    // Setup packet processing timer
    connect(processTimer, &QTimer::timeout, this, &PacketCaptureWorker::processPackets);
}

PacketCaptureWorker::~PacketCaptureWorker() {
    cleanupPcap();
}

void PacketCaptureWorker::initialize() {
    qDebug() << "Initializing packet capture worker for interface:" << interface;
    
    if (!initializePcap()) {
        QString error = QString("Failed to initialize pcap: %1").arg(errorBuffer);
        emit errorOccurred(error);
        return;
    }
    
    qDebug() << "Packet capture worker initialized successfully";
}

void PacketCaptureWorker::startCapture() {
    try {
        
        if (!pcapHandle) {
            if (!initializePcap()) {
                QString errorMsg = QString("Failed to initialize pcap: %1").arg(errorBuffer);
                printf("[ERROR] %s\n", errorMsg.toUtf8().constData());
                fflush(stdout);
                LOG_CAPTURE_ERROR(errorMsg, QString("Interface: %1").arg(interface));
                emit errorOccurred(errorMsg);
                return;
            }
        }
        
        shouldStop = false;
    
        // Start packet processing timer - increased interval for better performance
        processTimer->start(200); // Process packets every 200ms for high-speed capture
        
        LOG_INFO("Started packet capture worker");
        
    } catch (const std::exception &e) {
        QString errorMsg = QString("Exception in capture worker start: %1").arg(e.what());
        LOG_CAPTURE_ERROR(errorMsg, QString("Interface: %1").arg(interface));
        emit errorOccurred(errorMsg);
    } catch (...) {
        QString errorMsg = "Unknown exception in capture worker start";
        LOG_CAPTURE_ERROR(errorMsg, QString("Interface: %1").arg(interface));
        emit errorOccurred(errorMsg);
    }
}

void PacketCaptureWorker::stopCapture() {
    shouldStop = true;
    processTimer->stop();
    
    qDebug() << "Stopped packet capture worker";
    emit finished();
}

void PacketCaptureWorker::setFilter(const QString &filter) {
    if (!applyFilter(filter)) {
        emit errorOccurred(QString("Failed to apply filter: %1").arg(filter));
    } else {
        qDebug() << "Applied packet filter:" << filter;
    }
}



void PacketCaptureWorker::processPackets() {
    if (!pcapHandle || shouldStop) {
        return;
    }
    
    // Process up to 500 packets per timer tick for better batching
    QList<QPair<QByteArray, struct timeval>> batchedPackets;
    
    for (int i = 0; i < 500 && !shouldStop; ++i) {
        struct pcap_pkthdr *header;
        const u_char *packetData;
        
        int result = pcap_next_ex(pcapHandle, &header, &packetData);
        
        if (result == 1) {
            // Packet captured successfully - add to batch
            QByteArray packet(reinterpret_cast<const char*>(packetData), header->caplen);
            batchedPackets.append(qMakePair(packet, header->ts));
        } else if (result == 0) {
            // Timeout - no packet available
            break;
        } else if (result == -1) {
            // Error occurred
            QString error = QString("Packet capture error: %1").arg(pcap_geterr(pcapHandle));
            emit errorOccurred(error);
            shouldStop = true;
            break;
        } else if (result == -2) {
            // End of file (shouldn't happen in live capture)
            qDebug() << "End of capture file reached";
            shouldStop = true;
            break;
        }
    }
    
    // Emit batched packets if any were captured
    if (!batchedPackets.isEmpty()) {
        emit packetsBatchReady(batchedPackets);
    }
}

bool PacketCaptureWorker::initializePcap() {
    
    if (pcapHandle) {
        cleanupPcap();
    }
    
    
    // Open interface for live capture
    pcapHandle = pcap_open_live(interface.toUtf8().constData(),
                               65536,  // snaplen - capture entire packet
                               1,      // promiscuous mode
                               1,      // timeout in milliseconds
                               errorBuffer);
    
    if (!pcapHandle) {
        qWarning() << "Failed to open interface" << interface << ":" << errorBuffer;
        return false;
    }
    
    
    // Set non-blocking mode
    if (pcap_setnonblock(pcapHandle, 1, errorBuffer) == -1) {
        qWarning() << "Failed to set non-blocking mode:" << errorBuffer;
        // Continue anyway - this is not critical
    }
    
    qDebug() << "Successfully opened interface" << interface << "for packet capture";
    return true;
}

void PacketCaptureWorker::cleanupPcap() {
    if (pcapHandle) {
        pcap_close(pcapHandle);
        pcapHandle = nullptr;
    }
}

bool PacketCaptureWorker::applyFilter(const QString &filter) {
    if (!pcapHandle) {
        return false;
    }
    
    if (filter.isEmpty()) {
        // Clear any existing filter
        return true;
    }
    
    struct bpf_program filterProgram;
    
    // Compile the filter
    if (pcap_compile(pcapHandle, &filterProgram, filter.toUtf8().constData(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
        qWarning() << "Failed to compile filter" << filter << ":" << pcap_geterr(pcapHandle);
        return false;
    }
    
    // Apply the filter
    if (pcap_setfilter(pcapHandle, &filterProgram) == -1) {
        qWarning() << "Failed to apply filter" << filter << ":" << pcap_geterr(pcapHandle);
        pcap_freecode(&filterProgram);
        return false;
    }
    
    pcap_freecode(&filterProgram);
    return true;
}

bool PacketCaptureWorker::isPacketFromTarget(const QByteArray &packetData) const {
    if (!spoofingModeActive || spoofingTargets.isEmpty() || packetData.size() < 14) {
        return true; // In normal mode, accept all packets
    }
    
    // Extract source and destination MAC addresses from Ethernet header
    const unsigned char *data = reinterpret_cast<const unsigned char*>(packetData.constData());
    
    // Destination MAC (first 6 bytes)
    QString destMAC = QString("%1:%2:%3:%4:%5:%6")
                     .arg(data[0], 2, 16, QChar('0'))
                     .arg(data[1], 2, 16, QChar('0'))
                     .arg(data[2], 2, 16, QChar('0'))
                     .arg(data[3], 2, 16, QChar('0'))
                     .arg(data[4], 2, 16, QChar('0'))
                     .arg(data[5], 2, 16, QChar('0')).toUpper();
    
    // Source MAC (bytes 6-11)
    QString srcMAC = QString("%1:%2:%3:%4:%5:%6")
                    .arg(data[6], 2, 16, QChar('0'))
                    .arg(data[7], 2, 16, QChar('0'))
                    .arg(data[8], 2, 16, QChar('0'))
                    .arg(data[9], 2, 16, QChar('0'))
                    .arg(data[10], 2, 16, QChar('0'))
                    .arg(data[11], 2, 16, QChar('0')).toUpper();
    
    // Check if either source or destination MAC is in our target list
    for (const QString &targetMAC : spoofingTargets) {
        QString normalizedTarget = targetMAC.toUpper();
        if (srcMAC == normalizedTarget || destMAC == normalizedTarget) {
            return true;
        }
    }
    
    return false;
}