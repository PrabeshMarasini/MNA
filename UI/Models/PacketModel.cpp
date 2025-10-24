#include "PacketModel.h"
#include "ProtocolTreeModel.h"
#include "../Utils/SettingsManager.h"
#include <QDateTime>
#include <QColor>
#include <QFont>

// PacketInfo now uses value semantics - no custom destructor/copy needed

// PacketModel implementation
PacketModel::PacketModel(QObject *parent)
    : QAbstractTableModel(parent)
    , totalBytes(0)
    , nextSerialNumber(1)
{
    // Reserve memory for expected packet count to prevent frequent reallocations
    packets.reserve(100000);
}

PacketModel::~PacketModel() {
    clearPackets();
}

int PacketModel::rowCount(const QModelIndex &parent) const {
    Q_UNUSED(parent)
    return packets.size();
}

int PacketModel::columnCount(const QModelIndex &parent) const {
    Q_UNUSED(parent)
    return ColumnCount;
}

QVariant PacketModel::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || index.row() >= packets.size()) {
        return QVariant();
    }

    const PacketInfo &packet = packets.at(index.row());

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case SerialNumber:
            return packet.serialNumber;
        case Timestamp:
            return packet.timestamp.toString("hh:mm:ss.zzz");
        case SourceIP:
            return packet.sourceIP;
        case DestinationIP:
            return packet.destinationIP;
        case PacketLength:
            return packet.packetLength;
        case ProtocolType:
            return packet.protocolType;
        default:
            return QVariant();
        }
    }
    else if (role == Qt::TextAlignmentRole) {
        switch (index.column()) {
        case SerialNumber:
        case PacketLength:
            return static_cast<int>(Qt::AlignRight | Qt::AlignVCenter);
        case Timestamp:
            return static_cast<int>(Qt::AlignCenter);
        default:
            return static_cast<int>(Qt::AlignLeft | Qt::AlignVCenter);
        }
    }
    else if (role == Qt::BackgroundRole) {
        // Color coding based on protocol type
        if (packet.protocolType.contains("HTTP", Qt::CaseInsensitive)) {
            return QColor(230, 255, 230); // Light green
        } else if (packet.protocolType.contains("HTTPS", Qt::CaseInsensitive) || 
                   packet.protocolType.contains("TLS", Qt::CaseInsensitive)) {
            return QColor(230, 230, 255); // Light blue
        } else if (packet.protocolType.contains("SSH", Qt::CaseInsensitive)) {
            return QColor(255, 230, 230); // Light red
        } else if (packet.protocolType.contains("DNS", Qt::CaseInsensitive)) {
            return QColor(255, 255, 230); // Light yellow
        } else if (packet.protocolType.contains("ARP", Qt::CaseInsensitive)) {
            return QColor(255, 230, 255); // Light magenta
        }
        return QVariant();
    }
    else if (role == Qt::FontRole) {
        QFont font;
        if (packet.protocolType.contains("Error", Qt::CaseInsensitive)) {
            font.setBold(true);
        }
        return font;
    }
    else if (role == Qt::ToolTipRole) {
        QString tooltip = QString("Packet #%1\n"
                                "Time: %2\n"
                                "Source: %3\n"
                                "Destination: %4\n"
                                "Length: %5 bytes\n"
                                "Protocol: %6")
                         .arg(packet.serialNumber)
                         .arg(packet.timestamp.toString("yyyy-MM-dd hh:mm:ss.zzz"))
                         .arg(packet.sourceIP)
                         .arg(packet.destinationIP)
                         .arg(packet.packetLength)
                         .arg(packet.protocolType);
        return tooltip;
    }

    return QVariant();
}

QVariant PacketModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return QVariant();
    }

    switch (section) {
    case SerialNumber:
        return "No.";
    case Timestamp:
        return "Time";
    case SourceIP:
        return "Source";
    case DestinationIP:
        return "Destination";
    case PacketLength:
        return "Length";
    case ProtocolType:
        return "Protocol";
    default:
        return QVariant();
    }
}

void PacketModel::addPacket(const PacketInfo &packet) {
    try {
        beginInsertRows(QModelIndex(), packets.size(), packets.size());
        
        PacketInfo newPacket = packet;
        newPacket.serialNumber = nextSerialNumber++;
        
        packets.append(newPacket);
        totalBytes += packet.packetLength;
        
        endInsertRows();
        
        emit packetAdded(packets.size() - 1);
        emit packetAdded(newPacket);
        // Emit statistics less frequently for performance
        if (packets.size() % 100 == 0) {
            emit statisticsChanged();
        }
        
    } catch (const std::exception &e) {
        // Ensure model is in consistent state
        qWarning() << "PacketModel::addPacket exception:" << e.what();
    } catch (...) {
        qWarning() << "PacketModel::addPacket unknown exception";
    }
}

void PacketModel::addPacketsBatch(const QList<PacketInfo> &newPackets) {
    if (newPackets.isEmpty()) {
        return;
    }
    
    try {
        // Add new packets in batch
        int startRow = packets.size();
        int endRow = startRow + newPackets.size() - 1;
        
        beginInsertRows(QModelIndex(), startRow, endRow);
        
        for (const PacketInfo &packet : newPackets) {
            PacketInfo newPacket = packet;
            newPacket.serialNumber = nextSerialNumber++;
            packets.append(newPacket);
            totalBytes += packet.packetLength;
        }
        
        endInsertRows();
        
        // Emit batch completion signal
        emit packetsBatchAdded(startRow, newPackets.size());
        // Only emit statistics for batch operations to reduce signal overhead
        emit statisticsChanged();
        
    } catch (const std::exception &e) {
        endInsertRows(); // Ensure model is in consistent state
    } catch (...) {
        endInsertRows(); // Ensure model is in consistent state
    }
}

PacketInfo PacketModel::getPacket(int index) const {
    if (index >= 0 && index < packets.size()) {
        return packets.at(index);
    }
    return PacketInfo();
}

void PacketModel::clearPackets() {
    if (packets.isEmpty()) {
        return;
    }
    
    beginResetModel();
    packets.clear();
    totalBytes = 0;
    nextSerialNumber = 1;
    endResetModel();
    
    emit statisticsChanged();
}

int PacketModel::getPacketCount() const {
    return packets.size();
}

qint64 PacketModel::getTotalBytes() const {
    return totalBytes;
}