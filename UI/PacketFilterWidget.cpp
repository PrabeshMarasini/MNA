#include "PacketFilterWidget.h"
#include <QRegularExpression>
#include <QMessageBox>
#include <QToolTip>

PacketFilterWidget::PacketFilterWidget(QWidget *parent)
    : QWidget(parent)
    , filterActive(false)
{
    setupUI();
    connectSignals();
    
    // Set initial state
    updateFilterState();
}

PacketFilterWidget::~PacketFilterWidget()
{
}

void PacketFilterWidget::setupUI()
{
    mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(5, 5, 5, 5);
    mainLayout->setSpacing(5);
    
    setupCustomFilter();
    
    setLayout(mainLayout);
}


void PacketFilterWidget::setupCustomFilter()
{
    customFilterLayout = new QHBoxLayout();
    
    customFilterEdit = new QLineEdit(this);
    customFilterEdit->setPlaceholderText("Search packets... (e.g., 192.168.1.1, TCP, HTTP)");
    customFilterEdit->setToolTip("Search for packets by IP address, protocol, or other criteria");
    
    clearButton = new QPushButton("Clear", this);
    clearButton->setMaximumWidth(60);
    
    customFilterLayout->addWidget(customFilterEdit);
    customFilterLayout->addWidget(clearButton);
    
    mainLayout->addLayout(customFilterLayout);
}

void PacketFilterWidget::connectSignals()
{
    connect(customFilterEdit, &QLineEdit::textChanged, this, &PacketFilterWidget::onFilterTextChanged);
    connect(customFilterEdit, &QLineEdit::returnPressed, this, &PacketFilterWidget::onApplyFilter);
    connect(clearButton, &QPushButton::clicked, this, &PacketFilterWidget::onClearFilter);
}



void PacketFilterWidget::onFilterTextChanged()
{
    QString filter = customFilterEdit->text().trimmed();
    
    // Clear any previous styling
    customFilterEdit->setStyleSheet("");
    
    // Update current filter
    currentFilter.customFilter = filter;
    currentFilter.enabled = !filter.isEmpty();
    filterActive = !filter.isEmpty();
    
    // Emit filter change immediately for real-time filtering
    if (filterActive) {
        emit filterChanged(currentFilter);
    } else {
        emit filterCleared();
    }
}

void PacketFilterWidget::onApplyFilter()
{
    QString customFilter = customFilterEdit->text().trimmed();
    
    currentFilter.customFilter = customFilter;
    currentFilter.enabled = !customFilter.isEmpty();
    filterActive = !customFilter.isEmpty();
    
    if (filterActive) {
        emit filterChanged(currentFilter);
    } else {
        emit filterCleared();
    }
}

void PacketFilterWidget::onClearFilter()
{
    customFilterEdit->clear();
    
    currentFilter = FilterCriteria();
    filterActive = false;
    
    emit filterCleared();
}

bool PacketFilterWidget::validateFilter(const QString &filter) const
{
    if (filter.isEmpty()) {
        return true;
    }
    
    // Basic validation for common filter patterns
    QStringList validPatterns = {
        "ip\\.src\\s*==\\s*[\\d\\.]+",
        "ip\\.dst\\s*==\\s*[\\d\\.]+", 
        "tcp\\.port\\s*==\\s*\\d+",
        "udp\\.port\\s*==\\s*\\d+",
        "protocol\\s*==\\s*\\w+",
        "\\w+\\s*(and|or|not)\\s*\\w+"
    };
    
    // Allow combinations with and, or, not
    QString normalizedFilter = filter.toLower();
    
    // Basic syntax check - ensure balanced parentheses
    int openParens = normalizedFilter.count('(');
    int closeParens = normalizedFilter.count(')');
    
    return openParens == closeParens;
}

PacketFilterWidget::FilterCriteria PacketFilterWidget::getCurrentFilter() const
{
    return currentFilter;
}

void PacketFilterWidget::setFilter(const FilterCriteria &criteria)
{
    currentFilter = criteria;
    customFilterEdit->setText(criteria.customFilter);
    updateFilterState();
}

void PacketFilterWidget::clearFilter()
{
    onClearFilter();
}

bool PacketFilterWidget::isFilterActive() const
{
    return filterActive;
}

void PacketFilterWidget::onPacketAdded(const PacketInfo &packet)
{
    // No auto-complete functionality needed for simple search
    Q_UNUSED(packet)
}

void PacketFilterWidget::updateAutoComplete()
{
    // No auto-complete functionality needed for simple search
}

void PacketFilterWidget::updateFilterState()
{
    filterActive = !currentFilter.customFilter.isEmpty();
}