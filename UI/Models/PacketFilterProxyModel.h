#ifndef PACKETFILTERPROXYMODEL_H
#define PACKETFILTERPROXYMODEL_H

#include <QSortFilterProxyModel>
#include <QRegularExpression>
#include "../PacketFilterWidget.h"

class PacketModel;

class PacketFilterProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    explicit PacketFilterProxyModel(QObject *parent = nullptr);
    ~PacketFilterProxyModel();

    void setFilter(const PacketFilterWidget::FilterCriteria &criteria);
    void clearFilter();
    bool isFilterActive() const;

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override;

private:
    bool matchesQuickFilter(const PacketInfo &packet) const;
    bool matchesCustomFilter(const PacketInfo &packet) const;
    bool evaluateCustomFilterExpression(const QString &expression, const PacketInfo &packet) const;
    bool evaluateSimpleCondition(const QString &condition, const PacketInfo &packet) const;
    QString extractValue(const QString &field, const PacketInfo &packet) const;
    
    PacketFilterWidget::FilterCriteria filterCriteria;
    bool filterEnabled;
    
    // Cached regex patterns for performance
    mutable QRegularExpression ipSrcRegex;
    mutable QRegularExpression ipDstRegex;
    mutable QRegularExpression tcpPortRegex;
    mutable QRegularExpression udpPortRegex;
    mutable QRegularExpression protocolRegex;
};

#endif // PACKETFILTERPROXYMODEL_H