#ifndef PACKETMODEL_H
#define PACKETMODEL_H

#include <QAbstractTableModel>
#include <QDateTime>
#include <QList>
#include <QByteArray>
#include <QString>

#include "ProtocolTreeModel.h"

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
    
    PacketInfo() : serialNumber(0), packetLength(0) {}
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

signals:
    void packetAdded(int index);
    void packetAdded(const PacketInfo &packet);
    void packetsBatchAdded(int startIndex, int count);
    void statisticsChanged();

private:
    QList<PacketInfo> packets;
    qint64 totalBytes;
    int nextSerialNumber;
};

#endif // PACKETMODEL_H