#ifndef DEVICEDISCOVERYCONTROLLER_H
#define DEVICEDISCOVERYCONTROLLER_H

#include <QObject>
#include <QThread>
#include <QTimer>
#include <QMutex>
#include <QString>
#include <QStringList>
#include "DeviceSelectionDialog.h"

extern "C" {
    #include "../src/packetcapture/device_scanner.h"
}

class DeviceDiscoveryWorker;

class DeviceDiscoveryController : public QObject
{
    Q_OBJECT

public:
    explicit DeviceDiscoveryController(QObject *parent = nullptr);
    ~DeviceDiscoveryController();
    
    bool isDiscovering() const;
    QString getCurrentInterface() const;

public slots:
    void startDiscovery(const QString &interface);
    void stopDiscovery();

signals:
    void deviceDiscovered(const NetworkDevice &device);
    void discoveryCompleted(int deviceCount);
    void discoveryError(const QString &error);
    void discoveryProgress(int current, int total);

private slots:
    void handleWorkerFinished();
    void handleWorkerError(const QString &error);
    void handleDeviceFound(const NetworkDevice &device);
    void handleDiscoveryComplete(int deviceCount);
    void onThreadFinished();

private:
    void setupWorker();
    void cleanupWorker();
    
    QThread *discoveryThread;
    DeviceDiscoveryWorker *discoveryWorker;
    QString currentInterface;
    bool discovering;
    
    mutable QMutex discoveryMutex;
};

class DeviceDiscoveryWorker : public QObject
{
    Q_OBJECT

public:
    explicit DeviceDiscoveryWorker();
    ~DeviceDiscoveryWorker();

public slots:
    void startDiscovery(const QString &interface);
    void stopDiscovery();

signals:
    void deviceFound(const NetworkDevice &device);
    void discoveryComplete(int deviceCount);
    void errorOccurred(const QString &error);
    void finished();

private:
    NetworkDevice convertToNetworkDevice(const device_t &device, const QString &gatewayIP);
    QString formatMacAddress(const unsigned char *mac);
    
    bool shouldStop;
    QString interface;
};

#endif // DEVICEDISCOVERYCONTROLLER_H