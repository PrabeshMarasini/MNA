#ifndef PACKETCAPTURECONTROLLER_H
#define PACKETCAPTURECONTROLLER_H

#include <QObject>
#include <QThread>
#include <QTimer>
#include <QMutex>
#include <QQueue>
#include <QString>
#include <QByteArray>
#include "Models/PacketModel.h"

extern "C" {
    #include <pcap.h>
    #include <sys/types.h>
}

class PacketCaptureWorker;

class PacketCaptureController : public QObject
{
    Q_OBJECT

public:
    // Packet sampling modes
    enum SamplingMode {
        NoSampling,         // Capture all packets (default)
        CountBasedSampling, // Sample every Nth packet
        RateBasedSampling   // Sample to maintain target rate
    };
    
    explicit PacketCaptureController(const QString &interface, QObject *parent = nullptr);
    ~PacketCaptureController();
    
    bool isCapturing() const;
    QString getInterface() const;
    bool isSpoofingMode() const;
    void setSpoofingMode(bool enabled, const QList<QString> &targetMACs = QList<QString>());
    PacketInfo createPacketInfo(const QByteArray &packetData, const struct timeval &timestamp);
    
    // Ring buffer configuration
    void setRingBufferEnabled(bool enabled);
    void setRingBufferSize(int size);
    bool isRingBufferEnabled() const;
    int getRingBufferSize() const;
    
    // Packet sampling configuration
    void setSamplingMode(SamplingMode mode);
    void setSamplingRate(int rate);  // For count-based: every Nth packet
    void setTargetRate(int packetsPerSecond);  // For rate-based: target rate
    SamplingMode getSamplingMode() const;
    int getSamplingRate() const;
    int getTargetRate() const;
    
public slots:
    void startCapture();
    void stopCapture();
    void setPacketFilter(const QString &filter);

signals:
    void packetCaptured(const PacketInfo &packet);
    void packetsBatchCaptured(const QList<PacketInfo> &packets);
    void captureError(const QString &error);
    void captureStatusChanged(bool isCapturing);
    void statisticsUpdated(int packetCount, qint64 bytes);
    void backpressureApplied(); // Emitted when capture rate is throttled
    void samplingApplied(); // Emitted when packet sampling is active

private slots:
    void processCapturedPacket(const QByteArray &packetData, const struct timeval &timestamp);
    void processCapturedPacketBatch(const QList<QPair<QByteArray, struct timeval>> &packets);
    void handleWorkerError(const QString &error);
    void handleWorkerFinished();
    void onMemoryLimitExceeded();

private:
    void setupWorker();
    void cleanupWorker();
    bool isTargetPacket(const QByteArray &packetData) const;
    
    QString networkInterface;
    QThread *captureThread;
    PacketCaptureWorker *captureWorker;
    bool capturing;
    QString currentFilter;
    
    // Spoofing mode support
    bool spoofingMode;
    QList<QString> targetMACs;
    
    // Statistics
    int packetCount;
    qint64 totalBytes;
    QTimer *statisticsTimer;
    
    // Ring buffer support
    bool ringBufferEnabled;
    int ringBufferSize;
    
    // Backpressure control
    bool backpressureActive;
    int backpressureDelayMs;
    
    // Packet sampling
    SamplingMode samplingMode;
    int samplingRate;
    int targetRate;
    int sampledPacketCount;
    
    // Thread safety
    mutable QMutex captureMutex;
};

class PacketCaptureWorker : public QObject
{
    Q_OBJECT

public:
    // Packet sampling modes
    enum SamplingMode {
        NoSampling,         // Capture all packets (default)
        CountBasedSampling, // Sample every Nth packet
        RateBasedSampling   // Sample to maintain target rate
    };
    
    explicit PacketCaptureWorker(const QString &interface);
    ~PacketCaptureWorker();

public slots:
    void initialize();
    void startCapture();
    void stopCapture();
    void setFilter(const QString &filter);
    
    // Backpressure control
    void setBackpressureDelay(int delayMs);
    
    // Packet sampling configuration
    void setSamplingMode(SamplingMode mode);
    void setSamplingRate(int rate);
    void setTargetRate(int packetsPerSecond);

signals:
    void packetReady(const QByteArray &packetData, const struct timeval &timestamp);
    void packetsBatchReady(const QList<QPair<QByteArray, struct timeval>> &packets);
    void errorOccurred(const QString &error);
    void finished();

private slots:
    void processPackets();

private:
    static void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
    bool initializePcap();
    void cleanupPcap();
    bool applyFilter(const QString &filter);
    
    QString interface;
    pcap_t *pcapHandle;
    bool shouldStop;
    QString packetFilter;
    
    // Spoofing mode support (public so controller can access)
public:
    QList<QString> spoofingTargets;
    bool spoofingModeActive;
    
private:
    bool isPacketFromTarget(const QByteArray &packetData) const;
    
    // Packet queue for thread-safe processing
    QQueue<QPair<QByteArray, struct timeval>> packetQueue;
    QMutex queueMutex;
    QTimer *processTimer;
    
    // Backpressure control
    int backpressureDelayMs;
    
    // Packet sampling
    SamplingMode samplingMode;
    int samplingRate;
    int targetRate;
    int packetCounter;
    qint64 lastSampleTime;
    
    // Error handling
    char errorBuffer[PCAP_ERRBUF_SIZE];
};




#endif // PACKETCAPTURECONTROLLER_H