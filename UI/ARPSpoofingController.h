#ifndef ARPSPOOFINGCONTROLLER_H
#define ARPSPOOFINGCONTROLLER_H

#include <QObject>
#include <QThread>
#include <QTimer>
#include <QMutex>
#include <QString>
#include <QStringList>
#include <QQueue>
#include <QByteArray>

extern "C" {
    #include "../src/packetcapture/arp.h"
    #include "../src/packetcapture/device_scanner.h"
}

class ARPSpoofingWorker;

class ARPSpoofingController : public QObject
{
    Q_OBJECT

public:
    explicit ARPSpoofingController(QObject *parent = nullptr);
    ~ARPSpoofingController();
    
    bool isSpoofing() const;
    QStringList getCurrentTargets() const;
    QString getCurrentInterface() const;

public slots:
    void startSpoofing(const QStringList &targetIPs, const QString &interface);
    void stopSpoofing();

signals:
    void spoofingStatusChanged(bool active);
    void spoofingError(const QString &error);
    void targetPacketCaptured(const QByteArray &packetData, const struct timeval &timestamp);
    void spoofingStatistics(int packetsProcessed, int activeTargets);

private slots:
    void handleWorkerFinished();
    void handleWorkerError(const QString &error);
    void handleSpoofingStarted();
    void handleSpoofingStopped();
    void handlePacketCaptured(const QByteArray &packetData, const struct timeval &timestamp);
    void processQueuedPackets();
    void handleStopTimeout();

private:
    void setupWorker();
    void cleanupWorker();
    
    QThread *spoofingThread;
    ARPSpoofingWorker *spoofingWorker;
    QStringList currentTargets;
    QString currentInterface;
    bool spoofing;
    QTimer *packetProcessTimer;
    QTimer *stopTimeoutTimer;
    
    mutable QMutex spoofingMutex;
};

class ARPSpoofingWorker : public QObject
{
    Q_OBJECT
    friend class ARPSpoofingController;

public:
    explicit ARPSpoofingWorker();
    ~ARPSpoofingWorker();

public slots:
    void startSpoofing(const QStringList &targetIPs, const QString &interface);
    void stopSpoofing();
    void handleCapturedPacket(const unsigned char *packet_data, int packet_len);

signals:
    void spoofingStarted();
    void spoofingStopped();
    void packetCaptured(const QByteArray &packetData, const struct timeval &timestamp);
    void errorOccurred(const QString &error);
    void finished();

private slots:
    void performAsyncCleanup();

private:
    bool initializeSpoofing(const QStringList &targetIPs, const QString &interface);
    void cleanupSpoofing();
    bool setupTargetsFromIPs(const QStringList &targetIPs, const QString &interface);
    static void packetCallbackHandler(const unsigned char *packet_data, int packet_len, int target_index);
    
    // Packet queue for thread-safe processing
    QQueue<QByteArray> packetQueue;
    QMutex queueMutex;
    
    bool shouldStop;
    QString interface;
    QStringList targetIPs;
    pthread_t arpThread;
    pthread_t sniffThread;
    bool threadsStarted;
    
    // Async cleanup support
    QTimer *cleanupTimer;
    bool cleanupInProgress;
    int cleanupAttempts;
    static const int MAX_CLEANUP_ATTEMPTS = 10;
    static const int CLEANUP_TIMEOUT_MS = 500;
    
    // Static instance pointer for C callback
    static ARPSpoofingWorker* instance;
};

#endif // ARPSPOOFINGCONTROLLER_H