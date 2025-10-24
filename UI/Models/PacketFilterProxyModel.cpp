#include "PacketFilterProxyModel.h"
#include "PacketModel.h"
#include <QDebug>

PacketFilterProxyModel::PacketFilterProxyModel(QObject *parent)
    : QSortFilterProxyModel(parent)
    , filterEnabled(false)
{
    // Enable dynamic sorting
    setDynamicSortFilter(true);
    
    // Initialize regex patterns
    ipSrcRegex.setPattern("ip\\.src\\s*==\\s*([\\d\\.]+)");
    ipDstRegex.setPattern("ip\\.dst\\s*==\\s*([\\d\\.]+)");
    tcpPortRegex.setPattern("tcp\\.port\\s*==\\s*(\\d+)");
    udpPortRegex.setPattern("udp\\.port\\s*==\\s*(\\d+)");
    protocolRegex.setPattern("protocol\\s*==\\s*(\\w+)");
}

PacketFilterProxyModel::~PacketFilterProxyModel()
{
}

void PacketFilterProxyModel::setFilter(const PacketFilterWidget::FilterCriteria &criteria)
{
    filterCriteria = criteria;
    filterEnabled = criteria.enabled;
    
    // Trigger re-filtering
    invalidateFilter();
}

void PacketFilterProxyModel::clearFilter()
{
    filterCriteria = PacketFilterWidget::FilterCriteria();
    filterEnabled = false;
    
    // Trigger re-filtering
    invalidateFilter();
}

bool PacketFilterProxyModel::isFilterActive() const
{
    return filterEnabled;
}

bool PacketFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    if (!filterEnabled) {
        return true;
    }
    
    // Get the packet data from the source model
    PacketModel *packetModel = qobject_cast<PacketModel*>(sourceModel());
    if (!packetModel) {
        return true;
    }
    
    PacketInfo packet = packetModel->getPacket(sourceRow);
    
    // Apply quick filters first
    if (!matchesQuickFilter(packet)) {
        return false;
    }
    
    // Apply custom filter if specified
    if (!filterCriteria.customFilter.isEmpty()) {
        return matchesCustomFilter(packet);
    }
    
    return true;
}

bool PacketFilterProxyModel::matchesQuickFilter(const PacketInfo &packet) const
{
    // Source IP filter
    if (!filterCriteria.sourceIP.isEmpty()) {
        if (!packet.sourceIP.contains(filterCriteria.sourceIP, Qt::CaseInsensitive)) {
            return false;
        }
    }
    
    // Destination IP filter
    if (!filterCriteria.destinationIP.isEmpty()) {
        if (!packet.destinationIP.contains(filterCriteria.destinationIP, Qt::CaseInsensitive)) {
            return false;
        }
    }
    
    // Protocol filter
    if (!filterCriteria.protocolType.isEmpty()) {
        if (!packet.protocolType.contains(filterCriteria.protocolType, Qt::CaseInsensitive)) {
            return false;
        }
    }
    
    return true;
}

bool PacketFilterProxyModel::matchesCustomFilter(const PacketInfo &packet) const
{
    QString filter = filterCriteria.customFilter.toLower().trimmed();
    
    if (filter.isEmpty()) {
        return true;
    }
    
    // Simple text search across all packet fields
    QString searchText = filter;
    
    // Check if any field contains the search text
    if (packet.sourceIP.toLower().contains(searchText) ||
        packet.destinationIP.toLower().contains(searchText) ||
        packet.protocolType.toLower().contains(searchText) ||
        QString::number(packet.packetLength).contains(searchText) ||
        QString::number(packet.serialNumber).contains(searchText)) {
        return true;
    }
    
    return false;
}

bool PacketFilterProxyModel::evaluateCustomFilterExpression(const QString &expression, const PacketInfo &packet) const
{
    QString expr = expression;
    
    // Handle logical operators (simple implementation)
    if (expr.contains(" and ")) {
        QStringList parts = expr.split(" and ", Qt::SkipEmptyParts);
        for (const QString &part : parts) {
            if (!evaluateSimpleCondition(part.trimmed(), packet)) {
                return false;
            }
        }
        return true;
    }
    
    if (expr.contains(" or ")) {
        QStringList parts = expr.split(" or ", Qt::SkipEmptyParts);
        for (const QString &part : parts) {
            if (evaluateSimpleCondition(part.trimmed(), packet)) {
                return true;
            }
        }
        return false;
    }
    
    if (expr.startsWith("not ")) {
        return !evaluateSimpleCondition(expr.mid(4).trimmed(), packet);
    }
    
    return evaluateSimpleCondition(expr, packet);
}

bool PacketFilterProxyModel::evaluateSimpleCondition(const QString &condition, const PacketInfo &packet) const
{
    // Parse condition like "ip.src == 192.168.1.1"
    QStringList parts = condition.split("==", Qt::SkipEmptyParts);
    if (parts.size() != 2) {
        return false;
    }
    
    QString field = parts[0].trimmed();
    QString value = parts[1].trimmed();
    
    // Remove quotes if present
    if (value.startsWith('"') && value.endsWith('"')) {
        value = value.mid(1, value.length() - 2);
    }
    
    QString packetValue = extractValue(field, packet);
    
    // Case-insensitive comparison
    return packetValue.contains(value, Qt::CaseInsensitive);
}

QString PacketFilterProxyModel::extractValue(const QString &field, const PacketInfo &packet) const
{
    if (field == "ip.src") {
        return packet.sourceIP;
    } else if (field == "ip.dst") {
        return packet.destinationIP;
    } else if (field == "protocol") {
        return packet.protocolType;
    } else if (field == "tcp.port" || field == "udp.port") {
        // For port filtering, we'd need to parse the raw data or extend PacketInfo
        // For now, return empty string
        return QString();
    } else if (field == "length") {
        return QString::number(packet.packetLength);
    }
    
    return QString();
}