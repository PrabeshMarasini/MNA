#ifndef PACKETMODEL_H
#define PACKETMODEL_H

#include <QAbstractTableModel>
#include <QDateTime>
#include <QList>
#include <QByteArray>
#include <QString>
#include <QTimer>

#include "ProtocolTreeModel.h"

// Maximum packets to keep in memory before applying retention policy
static const int MAX_PACKETS_IN_MEMORY = 100000;

// Packet retention modes
enum PacketRetentionMode {
    UnlimitedRetention,     // Keep all packets (current behavior)
    SizeBasedRetention,     // Keep only recent packets based on count
    TimeBasedRetention,     // Keep only recent packets based on time
    RingBufferRetention     // Circular buffer - overwrite oldest packets
};

struct PacketInfo {
    int serialNumber;
    QDateTime timestamp;
    QString sourceIP;
    QString destinationIP;
    int packetLength;
    QString protocolType;
    QString moreInfo;
    QByteArray rawData;
    ProtocolAnalysisResult analysisResult;  // Changed from pointer to value type
    
    // Compression flags
    bool isCompressed;
    QByteArray compressedData;
    
    PacketInfo() : serialNumber(0), packetLength(0), isCompressed(false) {}
    // Default copy constructor and assignment operator are now safe
};

class PacketModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    enum Columns {
        SerialNumber = 0,
        Timestamp,
        SourceIP,
        DestinationIP,
        PacketLength,
        ProtocolType,
        MoreInfo,
        ColumnCount
    };

    explicit PacketModel(QObject *parent = nullptr);
    ~PacketModel();

    // Model interface
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
    
    // Packet management
    void addPacket(const PacketInfo &packet);
    void addPacketsBatch(const QList<PacketInfo> &packets);
    PacketInfo getPacket(int index) const;
    void clearPackets();
    
    // Statistics
    int getPacketCount() const;
    qint64 getTotalBytes() const;
    
    // Memory management
    void setRetentionMode(PacketRetentionMode mode);
    void setMaxPackets(int maxPackets);
    void setMaxAgeMinutes(int maxAgeMinutes);
    PacketRetentionMode getRetentionMode() const;
    int getMaxPackets() const;
    int getMaxAgeMinutes() const;
    
    // Memory optimization
    void setCompressionEnabled(bool enabled);
    bool isCompressionEnabled() const;
    void setCompressionThreshold(int bytes);  // Packets larger than this will be compressed
    int getCompressionThreshold() const;
    
    // Ring buffer operations
    void enableRingBuffer(int bufferSize);
    bool isRingBufferEnabled() const;

signals:
    void packetAdded(int index);
    void packetAdded(const PacketInfo &packet);
    void packetsBatchAdded(int startIndex, int count);
    void statisticsChanged();
    void memoryLimitExceeded();  // Emitted when memory limits are reached

private slots:
    void checkMemoryLimits();

private:
    QList<PacketInfo> packets;
    qint64 totalBytes;
    int nextSerialNumber;
    
    // Memory management
    PacketRetentionMode retentionMode;
    int maxPackets;
    int maxAgeMinutes;
    bool ringBufferEnabled;
    int ringBufferSize;
    
    // Memory optimization
    bool compressionEnabled;
    int compressionThreshold;
    
    QTimer *memoryCheckTimer;
    
    void enforceRetentionPolicy();
    void removeOldPackets();
    void removeExcessPackets();
};

#endif // PACKETMODEL_H