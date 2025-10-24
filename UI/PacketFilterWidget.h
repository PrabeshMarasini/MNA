#ifndef PACKETFILTERWIDGET_H
#define PACKETFILTERWIDGET_H

#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include "Models/PacketModel.h"

class PacketFilterWidget : public QWidget
{
    Q_OBJECT

public:
    struct FilterCriteria {
        QString sourceIP;
        QString destinationIP;
        QString protocolType;
        QString customFilter;
        bool enabled;
        
        FilterCriteria() : enabled(false) {}
    };

    explicit PacketFilterWidget(QWidget *parent = nullptr);
    ~PacketFilterWidget();

    FilterCriteria getCurrentFilter() const;
    void setFilter(const FilterCriteria &criteria);
    void clearFilter();
    bool isFilterActive() const;

public slots:
    void onPacketAdded(const PacketInfo &packet);
    void updateAutoComplete();

signals:
    void filterChanged(const FilterCriteria &criteria);
    void filterCleared();

private slots:
    void onFilterTextChanged();
    void onApplyFilter();
    void onClearFilter();

private:
    void setupUI();
    void setupCustomFilter();
    void connectSignals();
    void updateFilterState();
    bool validateFilter(const QString &filter) const;
    
    // UI Components
    QVBoxLayout *mainLayout;
    QHBoxLayout *customFilterLayout;
    
    // Custom filter
    QLineEdit *customFilterEdit;
    QPushButton *clearButton;
    
    // State
    FilterCriteria currentFilter;
    bool filterActive;
};

#endif // PACKETFILTERWIDGET_H