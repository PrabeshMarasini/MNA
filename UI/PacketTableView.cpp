#include "PacketTableView.h"
#include "Models/ProtocolTreeModel.h"
#include "Models/PacketModel.h"
#include <QHeaderView>
#include <QScrollBar>
#include <QApplication>
#include <QClipboard>
#include <QMessageBox>
#include <QFileDialog>
#include <QStandardPaths>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>

PacketTableView::PacketTableView(QWidget *parent)
    : QTableView(parent)
    , packetModel(nullptr)
    , contextMenu(nullptr)
    , copyAction(nullptr)
    , exportAction(nullptr)
    , followStreamAction(nullptr)
    , scrollUpdateTimer(nullptr)
    , autoScrollEnabled(true)
{
    setupTable();
    setupContextMenu();
}

PacketTableView::~PacketTableView()
{
    // Qt handles cleanup of child widgets
}

void PacketTableView::setPacketModel(PacketModel *model)
{
    if (packetModel == model) {
        return;
    }
    
    packetModel = model;
    setModel(model);
    
    if (model) {
        // Connect to model signals for auto-scrolling (throttled)
        connect(model, &PacketModel::rowsInserted, this, &PacketTableView::onRowsInserted);
        connect(model, &PacketModel::packetsBatchAdded, this, &PacketTableView::onPacketsBatchAdded);
        
        // Configure column widths based on content
        resizeColumnsToContents();
        
        // Set minimum column widths
        horizontalHeader()->setMinimumSectionSize(60);
        
        // Configure specific column widths
        setColumnWidth(PacketModel::SerialNumber, 80);
        setColumnWidth(PacketModel::Timestamp, 150);
        setColumnWidth(PacketModel::SourceIP, 120);
        setColumnWidth(PacketModel::DestinationIP, 120);
        setColumnWidth(PacketModel::PacketLength, 80);
        setColumnWidth(PacketModel::ProtocolType, 100);
        setColumnWidth(PacketModel::MoreInfo, 250);
        
        qDebug() << "PacketTableView: Model set with" << model->rowCount() << "packets";
    }
}

void PacketTableView::setModel(QAbstractItemModel *model)
{
    QTableView::setModel(model);
    
    if (model) {
        // Configure column widths for any model type
        resizeColumnsToContents();
        
        // Set minimum column widths
        horizontalHeader()->setMinimumSectionSize(60);
        
        // Configure specific column widths if it's a PacketModel or proxy
        if (model->columnCount() >= PacketModel::ColumnCount) {
            setColumnWidth(PacketModel::SerialNumber, 80);
            setColumnWidth(PacketModel::Timestamp, 150);
            setColumnWidth(PacketModel::SourceIP, 120);
            setColumnWidth(PacketModel::DestinationIP, 120);
            setColumnWidth(PacketModel::PacketLength, 80);
            setColumnWidth(PacketModel::ProtocolType, 100);
            setColumnWidth(PacketModel::MoreInfo, 250);
        }
        
        qDebug() << "PacketTableView: Model set with" << model->rowCount() << "rows";
    }
}

void PacketTableView::setupTable()
{
    // Configure table appearance
    setAlternatingRowColors(true);
    setSelectionBehavior(QAbstractItemView::SelectRows);
    setSelectionMode(QAbstractItemView::SingleSelection);
    setSortingEnabled(true);
    setShowGrid(false);
    
    // Configure headers
    horizontalHeader()->setStretchLastSection(true);
    horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    horizontalHeader()->setHighlightSections(false);
    
    verticalHeader()->setVisible(false);
    verticalHeader()->setDefaultSectionSize(20);
    
    // Configure scrolling
    setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    
    // Enable smooth scrolling
    verticalScrollBar()->setSingleStep(1);
    horizontalScrollBar()->setSingleStep(1);
    
    // Connect double-click signal
    connect(this, &QTableView::doubleClicked, this, &PacketTableView::onItemDoubleClicked);
    
    qDebug() << "PacketTableView: Table setup completed";
}

void PacketTableView::setupContextMenu()
{
    contextMenu = new QMenu(this);
    
    // Copy packet info action
    copyAction = new QAction("Copy Packet Info", this);
    copyAction->setShortcut(QKeySequence::Copy);
    connect(copyAction, &QAction::triggered, this, &PacketTableView::onCopyPacketInfo);
    contextMenu->addAction(copyAction);
    
    contextMenu->addSeparator();
    
    // Export packet action
    exportAction = new QAction("Export Packet...", this);
    connect(exportAction, &QAction::triggered, this, &PacketTableView::onExportPacket);
    contextMenu->addAction(exportAction);
    
    // Follow stream action (placeholder for future implementation)
    followStreamAction = new QAction("Follow Stream", this);
    followStreamAction->setEnabled(false); // Disabled for now
    contextMenu->addAction(followStreamAction);
    
    // Add keyboard shortcut for copy
    addAction(copyAction);
    
    qDebug() << "PacketTableView: Context menu setup completed";
}

void PacketTableView::contextMenuEvent(QContextMenuEvent *event)
{
    QModelIndex index = indexAt(event->pos());
    
    if (index.isValid() && packetModel) {
        // Enable/disable actions based on selection
        copyAction->setEnabled(true);
        exportAction->setEnabled(true);
        
        contextMenu->exec(event->globalPos());
    }
}

void PacketTableView::selectionChanged(const QItemSelection &selected, const QItemSelection &deselected)
{
    QTableView::selectionChanged(selected, deselected);
    
    if (!selected.indexes().isEmpty()) {
        QModelIndex index = selected.indexes().first();
        int packetIndex = index.row();
        
        emit packetSelected(packetIndex);
        
        qDebug() << "PacketTableView: Packet selected at index" << packetIndex;
    }
}

void PacketTableView::onItemDoubleClicked(const QModelIndex &index)
{
    if (index.isValid()) {
        int packetIndex = index.row();
        emit packetDoubleClicked(packetIndex);
        
        qDebug() << "PacketTableView: Packet double-clicked at index" << packetIndex;
    }
}

void PacketTableView::onCopyPacketInfo()
{
    QModelIndexList selectedIndexes = selectionModel()->selectedRows();
    
    if (selectedIndexes.isEmpty() || !packetModel) {
        return;
    }
    
    int row = selectedIndexes.first().row();
    PacketInfo packet = packetModel->getPacket(row);
    
    // Create formatted packet information
    QString packetInfo = QString("Packet #%1\n"
                                "Timestamp: %2\n"
                                "Source IP: %3\n"
                                "Destination IP: %4\n"
                                "Protocol: %5\n"
                                "Length: %6 bytes\n"
                                "More Info: %7\n")
                         .arg(packet.serialNumber)
                         .arg(packet.timestamp.toString("yyyy-MM-dd hh:mm:ss.zzz"))
                         .arg(packet.sourceIP)
                         .arg(packet.destinationIP)
                         .arg(packet.protocolType)
                         .arg(packet.packetLength)
                         .arg(packet.moreInfo);
    
    // Copy to clipboard
    QApplication::clipboard()->setText(packetInfo);
    
    qDebug() << "PacketTableView: Copied packet info to clipboard";
}

void PacketTableView::onExportPacket()
{
    QModelIndexList selectedIndexes = selectionModel()->selectedRows();
    
    if (selectedIndexes.isEmpty() || !packetModel) {
        return;
    }
    
    int row = selectedIndexes.first().row();
    PacketInfo packet = packetModel->getPacket(row);
    
    // Get save location
    QString defaultPath = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    QString fileName = QString("packet_%1.json").arg(packet.serialNumber);
    QString filePath = QFileDialog::getSaveFileName(this,
                                                   "Export Packet",
                                                   defaultPath + "/" + fileName,
                                                   "JSON Files (*.json);;All Files (*)");
    
    if (filePath.isEmpty()) {
        return;
    }
    
    // Create JSON representation
    QJsonObject packetJson;
    packetJson["serialNumber"] = packet.serialNumber;
    packetJson["timestamp"] = packet.timestamp.toString(Qt::ISODate);
    packetJson["sourceIP"] = packet.sourceIP;
    packetJson["destinationIP"] = packet.destinationIP;
    packetJson["protocolType"] = packet.protocolType;
    packetJson["moreInfo"] = packet.moreInfo;
    packetJson["packetLength"] = packet.packetLength;
    packetJson["rawData"] = QString(packet.rawData.toHex());
    
    // Add protocol analysis if available
    if (!packet.analysisResult.summary.isEmpty()) {
        QJsonObject analysisJson;
        analysisJson["summary"] = packet.analysisResult.summary;
        analysisJson["hasError"] = packet.analysisResult.hasError;
        if (packet.analysisResult.hasError) {
            analysisJson["errorMessage"] = packet.analysisResult.errorMessage;
        }
        packetJson["analysis"] = analysisJson;
    }
    
    // Write to file
    QJsonDocument doc(packetJson);
    QFile file(filePath);
    
    if (file.open(QIODevice::WriteOnly)) {
        file.write(doc.toJson());
        file.close();
        
        QMessageBox::information(this, "Export Successful", 
                               QString("Packet exported to:\n%1").arg(filePath));
        
        qDebug() << "PacketTableView: Exported packet to" << filePath;
    } else {
        QMessageBox::warning(this, "Export Failed", 
                           QString("Failed to write to file:\n%1").arg(filePath));
        
        qWarning() << "PacketTableView: Failed to export packet to" << filePath;
    }
}

void PacketTableView::scrollToBottom()
{
    if (packetModel && packetModel->rowCount() > 0) {
        // Auto-scroll to show latest packet
        QTableView::scrollToBottom();
        
        // Select the latest packet if no selection exists
        if (!selectionModel()->hasSelection()) {
            QModelIndex lastIndex = packetModel->index(packetModel->rowCount() - 1, 0);
            selectionModel()->select(lastIndex, QItemSelectionModel::SelectCurrent | QItemSelectionModel::Rows);
        }
    }
}

void PacketTableView::onRowsInserted(const QModelIndex &parent, int first, int last)
{
    Q_UNUSED(parent)
    Q_UNUSED(first)
    Q_UNUSED(last)
    
    // Only auto-scroll if enabled
    if (!autoScrollEnabled) {
        return;
    }
    
    // Schedule a throttled scroll update instead of immediate scrolling
    if (!scrollUpdateTimer) {
        scrollUpdateTimer = new QTimer(this);
        scrollUpdateTimer->setSingleShot(true);
        scrollUpdateTimer->setInterval(200); // 200ms delay for better performance
        connect(scrollUpdateTimer, &QTimer::timeout, this, &PacketTableView::scrollToBottom);
    }
    
    if (!scrollUpdateTimer->isActive()) {
        scrollUpdateTimer->start();
    }
}

void PacketTableView::onPacketsBatchAdded(int startIndex, int count)
{
    Q_UNUSED(startIndex)
    Q_UNUSED(count)
    
    // Only auto-scroll if enabled
    if (!autoScrollEnabled) {
        return;
    }
    
    // For batch additions, we definitely want to scroll but in a throttled manner
    if (!scrollUpdateTimer) {
        scrollUpdateTimer = new QTimer(this);
        scrollUpdateTimer->setSingleShot(true);
        scrollUpdateTimer->setInterval(200);
        connect(scrollUpdateTimer, &QTimer::timeout, this, &PacketTableView::scrollToBottom);
    }
    
    // Always restart the timer for batch updates to ensure we scroll to the latest batch
    scrollUpdateTimer->start();
}

void PacketTableView::setAutoScroll(bool enabled)
{
    autoScrollEnabled = enabled;
    if (!enabled && scrollUpdateTimer && scrollUpdateTimer->isActive()) {
        scrollUpdateTimer->stop();
    }
}