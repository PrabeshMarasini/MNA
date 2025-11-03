#include "DeviceDiscoveryController.h"
#include <QDebug>
#include <QDir>
#include <QThread>
#include <QMutexLocker>
#include <QMetaObject>

DeviceDiscoveryController::DeviceDiscoveryController(QObject *parent)
    : QObject(parent)
    , discoveryThread(nullptr)
    , discoveryWorker(nullptr)
    , discovering(false)
{
}

DeviceDiscoveryController::~DeviceDiscoveryController()
{
    if (discovering) {
        stopDiscovery();
    }
    cleanupWorker();
}

void DeviceDiscoveryController::startDiscovery(const QString &interface)
{
    QMutexLocker locker(&discoveryMutex);
    
    if (discovering) {
        qWarning() << "Discovery already in progress";
        return;
    }
    
    currentInterface = interface;
    setupWorker();
    
    discovering = true;
    
    // Use Qt's signal-slot mechanism to invoke on worker thread
    QMetaObject::invokeMethod(discoveryWorker, "startDiscovery", 
                             Qt::QueuedConnection, 
                             Q_ARG(QString, interface));
}

void DeviceDiscoveryController::stopDiscovery()
{
    QMutexLocker locker(&discoveryMutex);
    
    if (!discovering) {
        return;
    }
    
    if (discoveryWorker) {
        QMetaObject::invokeMethod(discoveryWorker, "stopDiscovery", Qt::QueuedConnection);
    }
    
    discovering = false;
}

bool DeviceDiscoveryController::isDiscovering() const
{
    QMutexLocker locker(&discoveryMutex);
    return discovering;
}

QString DeviceDiscoveryController::getCurrentInterface() const
{
    QMutexLocker locker(&discoveryMutex);
    return currentInterface;
}

void DeviceDiscoveryController::setupWorker()
{
    cleanupWorker();
    
    discoveryThread = new QThread(this);
    discoveryWorker = new DeviceDiscoveryWorker();
    discoveryWorker->moveToThread(discoveryThread);
    
    // Connect worker signals
    connect(discoveryWorker, &DeviceDiscoveryWorker::deviceFound,
            this, &DeviceDiscoveryController::handleDeviceFound, Qt::QueuedConnection);
    connect(discoveryWorker, &DeviceDiscoveryWorker::discoveryComplete,
            this, &DeviceDiscoveryController::handleDiscoveryComplete, Qt::QueuedConnection);
    connect(discoveryWorker, &DeviceDiscoveryWorker::errorOccurred,
            this, &DeviceDiscoveryController::handleWorkerError, Qt::QueuedConnection);
    connect(discoveryWorker, &DeviceDiscoveryWorker::finished,
            this, &DeviceDiscoveryController::handleWorkerFinished, Qt::QueuedConnection);
    
    // Connect thread management - use Qt::DirectConnection for cleanup
    connect(discoveryWorker, &DeviceDiscoveryWorker::finished, 
            discoveryThread, &QThread::quit, Qt::DirectConnection);
    connect(discoveryThread, &QThread::finished, 
            this, &DeviceDiscoveryController::onThreadFinished, Qt::QueuedConnection);
    
    discoveryThread->start();
}

void DeviceDiscoveryController::cleanupWorker()
{
    if (discoveryWorker) {
        // Disconnect all signals from the worker to prevent dangling connections
        disconnect(discoveryWorker, nullptr, this, nullptr);
    }
    
    if (discoveryThread && discoveryThread->isRunning()) {
        // Stop the worker first
        if (discoveryWorker) {
            QMetaObject::invokeMethod(discoveryWorker, "stopDiscovery", Qt::QueuedConnection);
        }
        
        // Wait for thread to finish
        discoveryThread->quit();
        if (!discoveryThread->wait(5000)) {
            qWarning() << "Thread did not finish gracefully, terminating...";
            discoveryThread->terminate();
            discoveryThread->wait(2000);
        }
    }
    
    // Clean up objects if they still exist
    if (discoveryWorker) {
        discoveryWorker->deleteLater();
        discoveryWorker = nullptr;
    }
    
    if (discoveryThread) {
        discoveryThread->deleteLater();
        discoveryThread = nullptr;
    }
}

void DeviceDiscoveryController::handleDeviceFound(const NetworkDevice &device)
{
    emit deviceDiscovered(device);
}

void DeviceDiscoveryController::handleDiscoveryComplete(int deviceCount)
{
    QMutexLocker locker(&discoveryMutex);
    discovering = false;
    emit discoveryCompleted(deviceCount);
}

void DeviceDiscoveryController::handleWorkerError(const QString &error)
{
    QMutexLocker locker(&discoveryMutex);
    discovering = false;
    emit discoveryError(error);
}

void DeviceDiscoveryController::handleWorkerFinished()
{
    QMutexLocker locker(&discoveryMutex);
    discovering = false;
}

void DeviceDiscoveryController::onThreadFinished()
{
    // This slot is called when the thread has completely finished
    // Safe to clean up the worker and thread objects now
    if (discoveryWorker) {
        discoveryWorker->deleteLater();
        discoveryWorker = nullptr;
    }
    
    if (discoveryThread) {
        discoveryThread->deleteLater();
        discoveryThread = nullptr;
    }
}

// DeviceDiscoveryWorker Implementation

DeviceDiscoveryWorker::DeviceDiscoveryWorker()
    : shouldStop(false)
{
}

DeviceDiscoveryWorker::~DeviceDiscoveryWorker()
{
    shouldStop = true;
}

void DeviceDiscoveryWorker::startDiscovery(const QString &interface)
{
    this->interface = interface;
    shouldStop = false;
    
    qDebug() << "Starting device discovery on interface:" << interface;
    
    // Change to the directory containing lan_scan.sh
    QString originalDir = QDir::currentPath();
    QDir::setCurrent("../src/packetcapture");
    
    scan_result_t scanResult;
    memset(&scanResult, 0, sizeof(scanResult));
    
    int result = run_lan_scan(&scanResult);
    
    // Restore original directory
    QDir::setCurrent(originalDir);
    
    if (result < 0) {
        emit errorOccurred("Failed to run network scan. Make sure lan_scan.sh is executable and arp-scan is installed.");
        emit finished();
        return;
    }
    
    if (shouldStop) {
        emit finished();
        return;
    }
    
    // Convert and emit discovered devices
    int deviceCount = 0;
    QString gatewayIP = QString::fromUtf8(scanResult.gateway_ip);
    
    for (int i = 0; i < scanResult.count && !shouldStop; i++) {
        NetworkDevice device = convertToNetworkDevice(scanResult.devices[i], gatewayIP);
        emit deviceFound(device);
        deviceCount++;
        
        // Small delay to prevent UI flooding
        QThread::msleep(10);
    }
    
    if (!shouldStop) {
        emit discoveryComplete(deviceCount);
    }
    
    emit finished();
}

void DeviceDiscoveryWorker::stopDiscovery()
{
    shouldStop = true;
}

NetworkDevice DeviceDiscoveryWorker::convertToNetworkDevice(const device_t &device, const QString &gatewayIP)
{
    QString ip = QString::fromUtf8(device.ip);
    QString mac = formatMacAddress(device.mac);
    bool isGateway = (ip == gatewayIP) || device.is_gateway;
    
    return NetworkDevice(ip, mac, isGateway);
}

QString DeviceDiscoveryWorker::formatMacAddress(const unsigned char *mac)
{
    return QString("%1:%2:%3:%4:%5:%6")
        .arg(mac[0], 2, 16, QChar('0'))
        .arg(mac[1], 2, 16, QChar('0'))
        .arg(mac[2], 2, 16, QChar('0'))
        .arg(mac[3], 2, 16, QChar('0'))
        .arg(mac[4], 2, 16, QChar('0'))
        .arg(mac[5], 2, 16, QChar('0'))
        .toUpper();
}