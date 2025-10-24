#include "ProtocolTreeView.h"
#include "Models/ProtocolTreeModel.h"
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QScrollBar>
#include <QDebug>

ProtocolTreeView::ProtocolTreeView(QWidget *parent)
    : QTreeView(parent)
    , protocolModel(nullptr)
    , contextMenu(nullptr)
    , copyNameAction(nullptr)
    , copyValueAction(nullptr)
    , copyBothAction(nullptr)
    , expandAllAction(nullptr)
    , collapseAllAction(nullptr)
{
    setupTree();
    setupContextMenu();
}

ProtocolTreeView::~ProtocolTreeView()
{
    // Qt handles cleanup automatically
}

void ProtocolTreeView::setProtocolModel(ProtocolTreeModel *model)
{
    if (protocolModel == model) {
        return;
    }
    
    protocolModel = model;
    setModel(model);
    
    if (model) {
        // Connect to model signals
        connect(selectionModel(), &QItemSelectionModel::currentChanged,
                this, &ProtocolTreeView::onItemClicked);
        
        // Auto-expand important protocol layers
        expandImportantNodes();
        
        qDebug() << "ProtocolTreeView: Model set with protocol data";
    }
}

void ProtocolTreeView::setupTree()
{
    // Configure tree appearance
    setAlternatingRowColors(true);
    setRootIsDecorated(true);
    setItemsExpandable(true);
    setExpandsOnDoubleClick(true);
    setUniformRowHeights(false);
    
    // Configure header
    header()->setStretchLastSection(true);
    header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    header()->setHighlightSections(false);
    
    // Configure scrolling
    setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    
    // Enable smooth scrolling
    verticalScrollBar()->setSingleStep(1);
    horizontalScrollBar()->setSingleStep(1);
    
    // Connect expansion signals
    connect(this, &QTreeView::expanded, this, &ProtocolTreeView::onItemExpanded);
    
    qDebug() << "ProtocolTreeView: Tree setup completed";
}

void ProtocolTreeView::setupContextMenu()
{
    contextMenu = new QMenu(this);
    
    // Copy field name action
    copyNameAction = new QAction("Copy Field Name", this);
    connect(copyNameAction, &QAction::triggered, this, &ProtocolTreeView::onCopyFieldName);
    contextMenu->addAction(copyNameAction);
    
    // Copy field value action
    copyValueAction = new QAction("Copy Field Value", this);
    connect(copyValueAction, &QAction::triggered, this, &ProtocolTreeView::onCopyFieldValue);
    contextMenu->addAction(copyValueAction);
    
    // Copy both action
    copyBothAction = new QAction("Copy Field Name and Value", this);
    connect(copyBothAction, &QAction::triggered, this, &ProtocolTreeView::onCopyBoth);
    contextMenu->addAction(copyBothAction);
    
    contextMenu->addSeparator();
    
    // Expand all action
    expandAllAction = new QAction("Expand All", this);
    connect(expandAllAction, &QAction::triggered, this, &ProtocolTreeView::onExpandAll);
    contextMenu->addAction(expandAllAction);
    
    // Collapse all action
    collapseAllAction = new QAction("Collapse All", this);
    connect(collapseAllAction, &QAction::triggered, this, &ProtocolTreeView::onCollapseAll);
    contextMenu->addAction(collapseAllAction);
    
    qDebug() << "ProtocolTreeView: Context menu setup completed";
}

void ProtocolTreeView::contextMenuEvent(QContextMenuEvent *event)
{
    QModelIndex index = indexAt(event->pos());
    
    if (index.isValid() && protocolModel) {
        currentContextIndex = index;
        
        // Enable/disable actions based on selection
        QString fieldName = protocolModel->data(index, ProtocolTreeModel::FieldNameRole).toString();
        QString fieldValue = protocolModel->data(index, ProtocolTreeModel::FieldValueRole).toString();
        
        copyNameAction->setEnabled(!fieldName.isEmpty());
        copyValueAction->setEnabled(!fieldValue.isEmpty());
        copyBothAction->setEnabled(!fieldName.isEmpty() && !fieldValue.isEmpty());
        
        contextMenu->exec(event->globalPos());
    }
}

void ProtocolTreeView::onItemClicked(const QModelIndex &index)
{
    if (!index.isValid() || !protocolModel) {
        return;
    }
    
    // Get field information
    QString fieldName = protocolModel->data(index, ProtocolTreeModel::FieldNameRole).toString();
    QString fieldValue = protocolModel->data(index, ProtocolTreeModel::FieldValueRole).toString();
    
    // Get byte range information if available
    QVariant startOffsetVar = protocolModel->data(index, ProtocolTreeModel::StartOffsetRole);
    QVariant lengthVar = protocolModel->data(index, ProtocolTreeModel::LengthRole);
    
    if (startOffsetVar.isValid() && lengthVar.isValid()) {
        int startOffset = startOffsetVar.toInt();
        int length = lengthVar.toInt();
        
        if (length > 0) {
            emit bytesHighlighted(startOffset, length);
        }
    }
    
    // Emit field selection signal
    if (!fieldName.isEmpty()) {
        emit fieldSelected(fieldName, fieldValue);
    }
    
    qDebug() << "ProtocolTreeView: Field selected -" << fieldName << ":" << fieldValue;
}

void ProtocolTreeView::onItemExpanded(const QModelIndex &index)
{
    if (!index.isValid()) {
        return;
    }
    
    // Auto-resize columns when items are expanded
    header()->resizeSections(QHeaderView::ResizeToContents);
    
    qDebug() << "ProtocolTreeView: Item expanded";
}

void ProtocolTreeView::onCopyFieldName()
{
    if (!currentContextIndex.isValid() || !protocolModel) {
        return;
    }
    
    QString fieldName = protocolModel->data(currentContextIndex, ProtocolTreeModel::FieldNameRole).toString();
    
    if (!fieldName.isEmpty()) {
        QApplication::clipboard()->setText(fieldName);
        qDebug() << "ProtocolTreeView: Copied field name:" << fieldName;
    }
}

void ProtocolTreeView::onCopyFieldValue()
{
    if (!currentContextIndex.isValid() || !protocolModel) {
        return;
    }
    
    QString fieldValue = protocolModel->data(currentContextIndex, ProtocolTreeModel::FieldValueRole).toString();
    
    if (!fieldValue.isEmpty()) {
        QApplication::clipboard()->setText(fieldValue);
        qDebug() << "ProtocolTreeView: Copied field value:" << fieldValue;
    }
}

void ProtocolTreeView::onCopyBoth()
{
    if (!currentContextIndex.isValid() || !protocolModel) {
        return;
    }
    
    QString fieldName = protocolModel->data(currentContextIndex, ProtocolTreeModel::FieldNameRole).toString();
    QString fieldValue = protocolModel->data(currentContextIndex, ProtocolTreeModel::FieldValueRole).toString();
    
    if (!fieldName.isEmpty() && !fieldValue.isEmpty()) {
        QString combined = QString("%1: %2").arg(fieldName, fieldValue);
        QApplication::clipboard()->setText(combined);
        qDebug() << "ProtocolTreeView: Copied field name and value:" << combined;
    }
}

void ProtocolTreeView::onExpandAll()
{
    expandAll();
    
    // Resize columns after expanding
    header()->resizeSections(QHeaderView::ResizeToContents);
    
    qDebug() << "ProtocolTreeView: Expanded all items";
}

void ProtocolTreeView::onCollapseAll()
{
    collapseAll();
    
    qDebug() << "ProtocolTreeView: Collapsed all items";
}

void ProtocolTreeView::expandImportantNodes()
{
    if (!protocolModel) {
        return;
    }
    
    // Auto-expand the first level (main protocol layers)
    QModelIndex rootIndex = QModelIndex();
    int rowCount = protocolModel->rowCount(rootIndex);
    
    for (int i = 0; i < rowCount; ++i) {
        QModelIndex childIndex = protocolModel->index(i, 0, rootIndex);
        if (childIndex.isValid()) {
            // Expand main protocol layers
            expand(childIndex);
            
            // Check if this is an important protocol layer that should be fully expanded
            QString layerName = protocolModel->data(childIndex, Qt::DisplayRole).toString().toLower();
            
            if (layerName.contains("ethernet") || 
                layerName.contains("ip") || 
                layerName.contains("tcp") || 
                layerName.contains("udp") ||
                layerName.contains("http")) {
                
                // Expand one more level for important protocols
                int childRowCount = protocolModel->rowCount(childIndex);
                for (int j = 0; j < childRowCount && j < 5; ++j) { // Limit to first 5 children
                    QModelIndex grandChildIndex = protocolModel->index(j, 0, childIndex);
                    if (grandChildIndex.isValid()) {
                        expand(grandChildIndex);
                    }
                }
            }
        }
    }
    
    // Resize columns to fit content
    header()->resizeSections(QHeaderView::ResizeToContents);
    
    qDebug() << "ProtocolTreeView: Auto-expanded important protocol nodes";
}