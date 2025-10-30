#include "PacketModel.h"
#include "ProtocolTreeModel.h"
#include "../Utils/SettingsManager.h"
#include <QDateTime>
#include <QColor>
#include <QFont>
#include <QTimer>
#include <QDebug>

// PacketInfo now uses value semantics - no custom destructor/copy needed

// PacketModel implementation
PacketModel::PacketModel(QObject *parent)
    : QAbstractTableModel(parent)
    , totalBytes(0)
    , nextSerialNumber(1)
    , retentionMode(UnlimitedRetention)
    , maxPackets(MAX_PACKETS_IN_MEMORY)
    , maxAgeMinutes(60)
    , ringBufferEnabled(false)
    , ringBufferSize(MAX_PACKETS_IN_MEMORY)
    , memoryCheckTimer(new QTimer(this))
    , compressionEnabled(false)
    , compressionThreshold(1024)  // Compress packets larger than 1KB
{
    // Reserve memory for expected packet count to prevent frequent reallocations
    packets.reserve(MAX_PACKETS_IN_MEMORY);
    
    // Setup memory check timer
    connect(memoryCheckTimer, &QTimer::timeout, this, &PacketModel::checkMemoryLimits);
    memoryCheckTimer->start(5000); // Check every 5 seconds
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
        case MoreInfo:
            return packet.moreInfo;
        default:
            return QVariant();
        }
    }
    else if (role == Qt::TextAlignmentRole) {
        // Center align all columns for better appearance when resizing
        return static_cast<int>(Qt::AlignCenter);
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
    else if (role == Qt::ForegroundRole) {
        // Special text color for security indicators in More Info column
        if (index.column() == MoreInfo) {
            if (packet.moreInfo.contains("Encrypted", Qt::CaseInsensitive) || 
                packet.moreInfo.contains("TLS", Qt::CaseInsensitive) ||
                packet.moreInfo.contains("SSH", Qt::CaseInsensitive) ||
                packet.moreInfo.contains("HTTPS", Qt::CaseInsensitive)) {
                return QColor(0, 150, 0); // Green for encrypted
            } else if (packet.moreInfo.contains("Unencrypted", Qt::CaseInsensitive) ||
                      packet.moreInfo.contains("Plain Text", Qt::CaseInsensitive) ||
                      packet.moreInfo.contains("Password", Qt::CaseInsensitive)) {
                return QColor(200, 0, 0); // Red for unencrypted/insecure
            }
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
                                "Protocol: %6\n"
                                "Info: %7")
                         .arg(packet.serialNumber)
                         .arg(packet.timestamp.toString("yyyy-MM-dd hh:mm:ss.zzz"))
                         .arg(packet.sourceIP)
                         .arg(packet.destinationIP)
                         .arg(packet.packetLength)
                         .arg(packet.protocolType)
                         .arg(packet.moreInfo);
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
    case MoreInfo:
        return "More Info";
    default:
        return QVariant();
    }
}

void PacketModel::addPacket(const PacketInfo &packet) {
    try {
        // Apply compression if enabled and packet is large enough
        PacketInfo packetToAdd = packet;
        if (compressionEnabled && packet.rawData.size() > compressionThreshold) {
            packetToAdd.compressedData = qCompress(packet.rawData, 6);  // Level 6 compression
            packetToAdd.isCompressed = true;
            packetToAdd.rawData.clear();  // Clear uncompressed data to save memory
        }
        
        // For ring buffer mode, we might need to remove the oldest packet
        if (ringBufferEnabled && packets.size() >= ringBufferSize) {
            beginRemoveRows(QModelIndex(), 0, 0);
            PacketInfo removedPacket = packets.takeFirst();
            totalBytes -= removedPacket.packetLength;
            nextSerialNumber--; // Adjust serial number
            endRemoveRows();
        }
        
        beginInsertRows(QModelIndex(), packets.size(), packets.size());
        
        PacketInfo newPacket = packetToAdd;
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
        
        // Enforce retention policy after adding
        enforceRetentionPolicy();
        
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
        // Apply compression to packets if enabled
        QList<PacketInfo> processedPackets;
        for (const PacketInfo &packet : newPackets) {
            PacketInfo packetToAdd = packet;
            if (compressionEnabled && packet.rawData.size() > compressionThreshold) {
                packetToAdd.compressedData = qCompress(packet.rawData, 6);  // Level 6 compression
                packetToAdd.isCompressed = true;
                packetToAdd.rawData.clear();  // Clear uncompressed data to save memory
            }
            processedPackets.append(packetToAdd);
        }
        
        // For ring buffer mode, we might need to remove old packets
        if (ringBufferEnabled) {
            int totalWillBe = packets.size() + processedPackets.size();
            if (totalWillBe > ringBufferSize) {
                int toRemove = totalWillBe - ringBufferSize;
                if (toRemove > 0 && toRemove <= packets.size()) {
                    beginRemoveRows(QModelIndex(), 0, toRemove - 1);
                    for (int i = 0; i < toRemove; i++) {
                        PacketInfo removedPacket = packets.takeFirst();
                        totalBytes -= removedPacket.packetLength;
                        nextSerialNumber--; // Adjust serial number
                    }
                    endRemoveRows();
                }
            }
        }
        
        // Add new packets in batch
        int startRow = packets.size();
        int endRow = startRow + processedPackets.size() - 1;
        
        beginInsertRows(QModelIndex(), startRow, endRow);
        
        for (const PacketInfo &packet : processedPackets) {
            PacketInfo newPacket = packet;
            newPacket.serialNumber = nextSerialNumber++;
            packets.append(newPacket);
            totalBytes += packet.packetLength;
        }
        
        endInsertRows();
        
        // Emit batch completion signal
        emit packetsBatchAdded(startRow, processedPackets.size());
        // Only emit statistics for batch operations to reduce signal overhead
        emit statisticsChanged();
        
        // Enforce retention policy after adding batch
        enforceRetentionPolicy();
        
    } catch (const std::exception &e) {
        endInsertRows(); // Ensure model is in consistent state
    } catch (...) {
        endInsertRows(); // Ensure model is in consistent state
    }
}

PacketInfo PacketModel::getPacket(int index) const {
    if (index >= 0 && index < packets.size()) {
        PacketInfo packet = packets.at(index);
        
        // Decompress packet data if it's compressed
        if (packet.isCompressed && !packet.compressedData.isEmpty()) {
            packet.rawData = qUncompress(packet.compressedData);
            packet.isCompressed = false;
            packet.compressedData.clear();
        }
        
        return packet;
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

// Memory management methods
void PacketModel::setRetentionMode(PacketRetentionMode mode) {
    retentionMode = mode;
    enforceRetentionPolicy();
}

void PacketModel::setMaxPackets(int maxPackets) {
    this->maxPackets = maxPackets;
    enforceRetentionPolicy();
}

void PacketModel::setMaxAgeMinutes(int maxAgeMinutes) {
    this->maxAgeMinutes = maxAgeMinutes;
    enforceRetentionPolicy();
}

PacketRetentionMode PacketModel::getRetentionMode() const {
    return retentionMode;
}

int PacketModel::getMaxPackets() const {
    return maxPackets;
}

int PacketModel::getMaxAgeMinutes() const {
    return maxAgeMinutes;
}

void PacketModel::enableRingBuffer(int bufferSize) {
    ringBufferEnabled = true;
    ringBufferSize = bufferSize;
    retentionMode = RingBufferRetention;
    enforceRetentionPolicy();
}

bool PacketModel::isRingBufferEnabled() const {
    return ringBufferEnabled;
}

void PacketModel::enforceRetentionPolicy() {
    switch (retentionMode) {
    case SizeBasedRetention:
        removeExcessPackets();
        break;
    case TimeBasedRetention:
        removeOldPackets();
        break;
    case RingBufferRetention:
        // Ring buffer is handled during packet insertion
        break;
    case UnlimitedRetention:
    default:
        // Do nothing
        break;
    }
}

void PacketModel::removeOldPackets() {
    if (packets.isEmpty() || maxAgeMinutes <= 0) {
        return;
    }
    
    QDateTime cutoffTime = QDateTime::currentDateTime().addSecs(-maxAgeMinutes * 60);
    
    int removeCount = 0;
    while (!packets.isEmpty() && packets.first().timestamp < cutoffTime) {
        packets.removeFirst();
        removeCount++;
        nextSerialNumber--; // Adjust serial number
    }
    
    if (removeCount > 0) {
        beginResetModel();
        totalBytes = 0;
        // Recalculate total bytes
        for (const PacketInfo &packet : packets) {
            totalBytes += packet.packetLength;
        }
        endResetModel();
        
        emit statisticsChanged();
    }
}

void PacketModel::removeExcessPackets() {
    if (packets.size() <= maxPackets) {
        return;
    }
    
    int removeCount = packets.size() - maxPackets;
    if (removeCount > 0) {
        beginRemoveRows(QModelIndex(), 0, removeCount - 1);
        for (int i = 0; i < removeCount; i++) {
            PacketInfo removedPacket = packets.takeFirst();
            totalBytes -= removedPacket.packetLength;
            nextSerialNumber--; // Adjust serial number
        }
        endRemoveRows();
        
        emit statisticsChanged();
    }
}

void PacketModel::checkMemoryLimits() {
    // Check if we're approaching memory limits
    if (packets.size() > MAX_PACKETS_IN_MEMORY * 0.9) {
        emit memoryLimitExceeded();
    }
    
    // Automatically enforce time-based retention policy
    if (retentionMode == TimeBasedRetention && maxAgeMinutes > 0) {
        removeOldPackets();
    }
}

// Memory optimization methods
void PacketModel::setCompressionEnabled(bool enabled) {
    compressionEnabled = enabled;
}

bool PacketModel::isCompressionEnabled() const {
    return compressionEnabled;
}

void PacketModel::setCompressionThreshold(int bytes) {
    compressionThreshold = bytes;
}

int PacketModel::getCompressionThreshold() const {
    return compressionThreshold;
}
