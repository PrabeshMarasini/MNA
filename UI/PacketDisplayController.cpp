#include "PacketDisplayController.h"
#include "PacketTableView.h"
#include "HexView.h"
#include "ProtocolTreeView.h"
#include "Models/PacketModel.h"
#include "Models/ProtocolTreeModel.h"
#include "Wrappers/ProtocolAnalysisWrapper.h"
#include <QDebug>
#include <QTimer>

PacketDisplayController::PacketDisplayController(QObject *parent)
    : QObject(parent)
    , m_packetTable(nullptr)
    , m_hexView(nullptr)
    , m_protocolTree(nullptr)
    , m_packetModel(nullptr)
    , m_protocolModel(nullptr)
    , m_currentSelection(-1)
    , m_currentHighlightStart(-1)
    , m_currentHighlightLength(0)
    , m_delayedUpdateTimer(new QTimer(this))
    , m_pendingUpdateIndex(-1)
    , m_updatePending(false)
    , m_totalSelections(0)
    , m_totalFieldSelections(0)
    , m_totalHighlights(0)
{
    // Configure delayed update timer
    m_delayedUpdateTimer->setSingleShot(true);
    m_delayedUpdateTimer->setInterval(50); // 50ms delay to batch updates
    connect(m_delayedUpdateTimer, &QTimer::timeout, this, &PacketDisplayController::processDelayedUpdate);
    
    qDebug() << "PacketDisplayController: Initialized";
}

PacketDisplayController::~PacketDisplayController()
{
    qDebug() << "PacketDisplayController: Statistics - Selections:" << m_totalSelections
             << "Field selections:" << m_totalFieldSelections
             << "Highlights:" << m_totalHighlights;
}

void PacketDisplayController::setViews(PacketTableView *packetTable, HexView *hexView, ProtocolTreeView *protocolTree)
{
    m_packetTable = packetTable;
    m_hexView = hexView;
    m_protocolTree = protocolTree;
    
    // Connect view signals
    if (m_packetTable) {
        connect(m_packetTable, &PacketTableView::packetSelected,
                this, &PacketDisplayController::onPacketSelected);
    }
    
    if (m_protocolTree) {
        connect(m_protocolTree, &ProtocolTreeView::fieldSelected,
                this, &PacketDisplayController::onProtocolFieldSelected);
        connect(m_protocolTree, &ProtocolTreeView::bytesHighlighted,
                this, &PacketDisplayController::onBytesHighlighted);
    }
    
    qDebug() << "PacketDisplayController: Views connected";
}

void PacketDisplayController::setModels(PacketModel *packetModel, ProtocolTreeModel *protocolModel)
{
    m_packetModel = packetModel;
    m_protocolModel = protocolModel;
    
    // Connect model signals for automatic updates
    if (m_packetModel) {
        connect(m_packetModel, &PacketModel::rowsInserted,
                this, &PacketDisplayController::refreshCurrentSelection);
        connect(m_packetModel, &PacketModel::modelReset,
                this, &PacketDisplayController::clearDisplays);
    }
    
    qDebug() << "PacketDisplayController: Models connected";
}

void PacketDisplayController::onPacketSelected(int packetIndex)
{
    if (!isValidPacketIndex(packetIndex)) {
        clearDisplays();
        return;
    }
    
    // Check if this is the same selection
    if (m_currentSelection == packetIndex) {
        qDebug() << "PacketDisplayController: Same packet already selected:" << packetIndex;
        return;
    }
    
    m_currentSelection = packetIndex;
    m_totalSelections++;
    
    // Clear previous highlights
    m_currentHighlightStart = -1;
    m_currentHighlightLength = 0;
    m_currentFieldName.clear();
    m_currentFieldValue.clear();
    
    // Schedule delayed update to prevent UI flooding during rapid selections
    scheduleDelayedUpdate(packetIndex);
    
    emit selectionChanged(packetIndex);
    
    qDebug() << "PacketDisplayController: Packet selected:" << packetIndex;
}

void PacketDisplayController::onProtocolFieldSelected(const QString &fieldName, const QString &fieldValue)
{
    m_currentFieldName = fieldName;
    m_currentFieldValue = fieldValue;
    m_totalFieldSelections++;
    
    emit fieldSelected(fieldName, fieldValue, m_currentSelection);
    
    qDebug() << "PacketDisplayController: Protocol field selected:" << fieldName << "=" << fieldValue;
}

void PacketDisplayController::onBytesHighlighted(int startOffset, int length)
{
    if (startOffset < 0 || length <= 0) {
        // Clear highlight
        if (m_hexView) {
            m_hexView->clearHighlight();
        }
        m_currentHighlightStart = -1;
        m_currentHighlightLength = 0;
        return;
    }
    
    m_currentHighlightStart = startOffset;
    m_currentHighlightLength = length;
    m_totalHighlights++;
    
    // Update hex view highlighting
    if (m_hexView) {
        m_hexView->highlightBytes(startOffset, length);
    }
    
    emit bytesHighlighted(startOffset, length, m_currentSelection);
    
    qDebug() << "PacketDisplayController: Bytes highlighted:" << startOffset << "length:" << length;
}

void PacketDisplayController::clearDisplays()
{
    m_currentSelection = -1;
    m_currentFieldName.clear();
    m_currentFieldValue.clear();
    m_currentHighlightStart = -1;
    m_currentHighlightLength = 0;
    
    // Clear all views
    if (m_hexView) {
        m_hexView->clear();
    }
    
    if (m_protocolModel) {
        m_protocolModel->clear();
    }
    
    emit selectionChanged(-1);
    
    qDebug() << "PacketDisplayController: Displays cleared";
}

void PacketDisplayController::refreshCurrentSelection()
{
    if (m_currentSelection >= 0 && isValidPacketIndex(m_currentSelection)) {
        // Re-select the current packet to refresh displays
        scheduleDelayedUpdate(m_currentSelection);
        qDebug() << "PacketDisplayController: Refreshed current selection:" << m_currentSelection;
    }
}

void PacketDisplayController::scheduleDelayedUpdate(int packetIndex)
{
    m_pendingUpdateIndex = packetIndex;
    m_updatePending = true;
    
    // Restart timer to batch rapid updates
    m_delayedUpdateTimer->start();
}

void PacketDisplayController::processDelayedUpdate()
{
    if (!m_updatePending || !isValidPacketIndex(m_pendingUpdateIndex)) {
        m_updatePending = false;
        return;
    }
    
    PacketInfo packet = getPacketSafely(m_pendingUpdateIndex);
    
    try {
        // Update hex view
        updateHexView(packet);
        
        // Update protocol tree
        updateProtocolTree(packet);
        
        qDebug() << "PacketDisplayController: Updated displays for packet" << m_pendingUpdateIndex;
        
    } catch (const std::exception &e) {
        QString error = QString("Failed to update displays: %1").arg(e.what());
        qWarning() << "PacketDisplayController:" << error;
        emit displayError(error);
    }
    
    m_updatePending = false;
}

void PacketDisplayController::updateHexView(const PacketInfo &packet)
{
    if (!m_hexView) {
        return;
    }
    
    if (packet.rawData.isEmpty()) {
        m_hexView->clear();
        qDebug() << "PacketDisplayController: Cleared hex view (no data)";
    } else {
        m_hexView->displayPacketData(packet.rawData);
        qDebug() << "PacketDisplayController: Updated hex view with" << packet.rawData.size() << "bytes";
    }
}

void PacketDisplayController::updateProtocolTree(const PacketInfo &packet)
{
    if (!m_protocolModel) {
        return;
    }
    
    // PERFORMANCE IMPROVEMENT: Lazy protocol analysis
    // If analysis hasn't been done yet, do it now (only when user selects the packet)
    PacketInfo mutablePacket = packet; // Create mutable copy
    
    if (mutablePacket.analysisResult.summary.isEmpty()) {
        // Perform analysis now (lazy evaluation)
        mutablePacket.analysisResult = ProtocolAnalysisWrapper::analyzePacket(mutablePacket.rawData);
        
        // Update the packet in the model with the analysis result
        if (m_packetModel) {
            // Note: This would require adding a method to update analysis in PacketModel
            // For now, we'll just use the local analysis
        }
        
        qDebug() << "PacketDisplayController: Performed lazy protocol analysis for packet";
    }
    
    if (!mutablePacket.analysisResult.hasError && !mutablePacket.analysisResult.summary.isEmpty()) {
        m_protocolModel->setProtocolData(mutablePacket.analysisResult);
        qDebug() << "PacketDisplayController: Updated protocol tree with" 
                 << mutablePacket.analysisResult.layers.size() << "layers";
    } else {
        m_protocolModel->clear();
        if (mutablePacket.analysisResult.hasError) {
            qWarning() << "PacketDisplayController: Protocol analysis error:" 
                       << mutablePacket.analysisResult.errorMessage;
        } else {
            qDebug() << "PacketDisplayController: Cleared protocol tree (no analysis)";
        }
    }
}

bool PacketDisplayController::isValidPacketIndex(int index) const
{
    return m_packetModel && index >= 0 && index < m_packetModel->rowCount();
}

PacketInfo PacketDisplayController::getPacketSafely(int index) const
{
    if (!isValidPacketIndex(index)) {
        qWarning() << "PacketDisplayController: Invalid packet index:" << index;
        return PacketInfo(); // Return empty packet info
    }
    
    try {
        return m_packetModel->getPacket(index);
    } catch (const std::exception &e) {
        qWarning() << "PacketDisplayController: Error getting packet at index" << index << ":" << e.what();
        return PacketInfo();
    }
}