#include "ProtocolTreeModel.h"
#include <QStringList>
#include <QFont>
#include <QColor>

// ProtocolTreeItem implementation
ProtocolTreeItem::ProtocolTreeItem(const QString &name, const QString &value, ProtocolTreeItem *parent)
    : itemName(name), itemValue(value), parent(parent)
{
}

ProtocolTreeItem::~ProtocolTreeItem() {
    qDeleteAll(childItems);
}

void ProtocolTreeItem::appendChild(ProtocolTreeItem *child) {
    childItems.append(child);
}

ProtocolTreeItem *ProtocolTreeItem::child(int row) {
    if (row < 0 || row >= childItems.size()) {
        return nullptr;
    }
    return childItems.at(row);
}

int ProtocolTreeItem::childCount() const {
    return childItems.count();
}

int ProtocolTreeItem::columnCount() const {
    return 2; // Name and Value columns
}

QVariant ProtocolTreeItem::data(int column) const {
    switch (column) {
    case 0:
        return itemName;
    case 1:
        return itemValue;
    default:
        return QVariant();
    }
}

int ProtocolTreeItem::row() const {
    if (parent) {
        return parent->childItems.indexOf(const_cast<ProtocolTreeItem*>(this));
    }
    return 0;
}

ProtocolTreeItem *ProtocolTreeItem::parentItem() {
    return parent;
}

void ProtocolTreeItem::setName(const QString &name) {
    itemName = name;
}

void ProtocolTreeItem::setValue(const QString &value) {
    itemValue = value;
}

QString ProtocolTreeItem::getName() const {
    return itemName;
}

QString ProtocolTreeItem::getValue() const {
    return itemValue;
}

// ProtocolTreeModel implementation
ProtocolTreeModel::ProtocolTreeModel(QObject *parent)
    : QAbstractItemModel(parent)
{
    rootItem = new ProtocolTreeItem("Protocol", "Value");
}

ProtocolTreeModel::~ProtocolTreeModel() {
    delete rootItem;
}

QVariant ProtocolTreeModel::data(const QModelIndex &index, int role) const {
    if (!index.isValid()) {
        return QVariant();
    }

    ProtocolTreeItem *item = static_cast<ProtocolTreeItem*>(index.internalPointer());

    if (role == Qt::DisplayRole) {
        return item->data(index.column());
    }
    else if (role == Qt::FontRole) {
        QFont font;
        // Make protocol layer headers bold
        if (index.column() == 0 && item->childCount() > 0) {
            font.setBold(true);
        }
        return font;
    }
    else if (role == Qt::BackgroundRole) {
        // Color code different protocol layers
        if (item->childCount() > 0) { // This is a protocol layer header
            QString name = item->getName().toLower();
            if (name.contains("ethernet")) {
                return QColor(240, 240, 255); // Light blue
            } else if (name.contains("ip")) {
                return QColor(240, 255, 240); // Light green
            } else if (name.contains("tcp") || name.contains("udp")) {
                return QColor(255, 240, 240); // Light red
            } else if (name.contains("http") || name.contains("application")) {
                return QColor(255, 255, 240); // Light yellow
            }
        }
        return QVariant();
    }
    else if (role == Qt::ToolTipRole) {
        QString tooltip = item->getName();
        if (!item->getValue().isEmpty()) {
            tooltip += ": " + item->getValue();
        }
        return tooltip;
    }

    return QVariant();
}

Qt::ItemFlags ProtocolTreeModel::flags(const QModelIndex &index) const {
    if (!index.isValid()) {
        return Qt::NoItemFlags;
    }

    return QAbstractItemModel::flags(index);
}

QVariant ProtocolTreeModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole) {
        return rootItem->data(section);
    }

    return QVariant();
}

QModelIndex ProtocolTreeModel::index(int row, int column, const QModelIndex &parent) const {
    if (!hasIndex(row, column, parent)) {
        return QModelIndex();
    }

    ProtocolTreeItem *parentItem;

    if (!parent.isValid()) {
        parentItem = rootItem;
    } else {
        parentItem = static_cast<ProtocolTreeItem*>(parent.internalPointer());
    }

    ProtocolTreeItem *childItem = parentItem->child(row);
    if (childItem) {
        return createIndex(row, column, childItem);
    }

    return QModelIndex();
}

QModelIndex ProtocolTreeModel::parent(const QModelIndex &index) const {
    if (!index.isValid()) {
        return QModelIndex();
    }

    ProtocolTreeItem *childItem = static_cast<ProtocolTreeItem*>(index.internalPointer());
    ProtocolTreeItem *parentItem = childItem->parentItem();

    if (parentItem == rootItem) {
        return QModelIndex();
    }

    return createIndex(parentItem->row(), 0, parentItem);
}

int ProtocolTreeModel::rowCount(const QModelIndex &parent) const {
    ProtocolTreeItem *parentItem;
    if (parent.column() > 0) {
        return 0;
    }

    if (!parent.isValid()) {
        parentItem = rootItem;
    } else {
        parentItem = static_cast<ProtocolTreeItem*>(parent.internalPointer());
    }

    return parentItem->childCount();
}

int ProtocolTreeModel::columnCount(const QModelIndex &parent) const {
    if (parent.isValid()) {
        return static_cast<ProtocolTreeItem*>(parent.internalPointer())->columnCount();
    }
    return rootItem->columnCount();
}

void ProtocolTreeModel::setProtocolData(const ProtocolAnalysisResult &result) {
    beginResetModel();
    
    // Clear existing data
    delete rootItem;
    rootItem = new ProtocolTreeItem("Protocol", "Value");
    
    if (result.hasError) {
        ProtocolTreeItem *errorItem = new ProtocolTreeItem("Error", result.errorMessage, rootItem);
        rootItem->appendChild(errorItem);
    } else {
        setupModelData(result);
    }
    
    endResetModel();
}

void ProtocolTreeModel::clear() {
    beginResetModel();
    delete rootItem;
    rootItem = new ProtocolTreeItem("Protocol", "Value");
    endResetModel();
}

void ProtocolTreeModel::setupModelData(const ProtocolAnalysisResult &result) {
    // Add summary if available
    if (!result.summary.isEmpty()) {
        ProtocolTreeItem *summaryItem = new ProtocolTreeItem("Summary", result.summary, rootItem);
        rootItem->appendChild(summaryItem);
    }
    
    // Add protocol layers
    for (const ProtocolLayer &layer : result.layers) {
        addProtocolLayer(layer, rootItem);
    }
    
    // If no layers were added, create a simple text representation
    if (rootItem->childCount() == 0 && !result.summary.isEmpty()) {
        ProtocolTreeItem *dataItem = new ProtocolTreeItem("Packet Data", "Available", rootItem);
        rootItem->appendChild(dataItem);
        
        ProtocolTreeItem *lengthItem = new ProtocolTreeItem("Length", 
                                                           QString::number(result.hexDump.length() / 3), 
                                                           dataItem);
        dataItem->appendChild(lengthItem);
    }
}

void ProtocolTreeModel::addProtocolLayer(const ProtocolLayer &layer, ProtocolTreeItem *parent) {
    ProtocolTreeItem *layerItem = new ProtocolTreeItem(layer.name, "", parent);
    parent->appendChild(layerItem);
    
    // Add fields for this layer
    QMapIterator<QString, QString> fieldIterator(layer.fields);
    while (fieldIterator.hasNext()) {
        fieldIterator.next();
        ProtocolTreeItem *fieldItem = new ProtocolTreeItem(fieldIterator.key(), 
                                                          fieldIterator.value(), 
                                                          layerItem);
        layerItem->appendChild(fieldItem);
    }
    
    // Add sub-layers
    for (const ProtocolLayer &subLayer : layer.subLayers) {
        addProtocolLayer(subLayer, layerItem);
    }
}