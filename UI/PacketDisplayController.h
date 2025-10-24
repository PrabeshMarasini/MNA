#ifndef PACKETDISPLAYCONTROLLER_H
#define PACKETDISPLAYCONTROLLER_H

#include <QObject>
#include <QModelIndex>
#include <QTimer>

class PacketModel;
class ProtocolTreeModel;
class HexView;
class ProtocolTreeView;
class PacketTableView;
struct PacketInfo;
struct ProtocolAnalysisResult;

/**
 * @brief Controller class for coordinating packet display across multiple views
 * 
 * This class manages the coordination between the packet table, hex view, and protocol tree
 * to ensure synchronized updates when packets are selected or data changes.
 */
class PacketDisplayController : public QObject
{
    Q_OBJECT

public:
    explicit PacketDisplayController(QObject *parent = nullptr);
    ~PacketDisplayController();

    /**
     * @brief Set the views to be coordinated
     */
    void setViews(PacketTableView *packetTable, HexView *hexView, ProtocolTreeView *protocolTree);

    /**
     * @brief Set the models used by the views
     */
    void setModels(PacketModel *packetModel, ProtocolTreeModel *protocolModel);

    /**
     * @brief Get the currently selected packet index
     */
    int getCurrentSelection() const { return m_currentSelection; }

    /**
     * @brief Check if a packet is currently selected
     */
    bool hasSelection() const { return m_currentSelection >= 0; }

public slots:
    /**
     * @brief Handle packet selection from the table view
     */
    void onPacketSelected(int packetIndex);

    /**
     * @brief Handle protocol field selection for byte highlighting
     */
    void onProtocolFieldSelected(const QString &fieldName, const QString &fieldValue);

    /**
     * @brief Handle byte range highlighting from protocol tree
     */
    void onBytesHighlighted(int startOffset, int length);

    /**
     * @brief Clear all displays
     */
    void clearDisplays();

    /**
     * @brief Refresh the current selection (useful after model updates)
     */
    void refreshCurrentSelection();

signals:
    /**
     * @brief Emitted when packet selection changes
     */
    void selectionChanged(int packetIndex);

    /**
     * @brief Emitted when a protocol field is selected
     */
    void fieldSelected(const QString &fieldName, const QString &fieldValue, int packetIndex);

    /**
     * @brief Emitted when bytes are highlighted
     */
    void bytesHighlighted(int startOffset, int length, int packetIndex);

    /**
     * @brief Emitted when display update fails
     */
    void displayError(const QString &error);

private slots:
    /**
     * @brief Handle delayed updates to prevent UI flooding
     */
    void processDelayedUpdate();

private:
    /**
     * @brief Update hex view with packet data
     */
    void updateHexView(const PacketInfo &packet);

    /**
     * @brief Update protocol tree with analysis results
     */
    void updateProtocolTree(const PacketInfo &packet);

    /**
     * @brief Validate packet index
     */
    bool isValidPacketIndex(int index) const;

    /**
     * @brief Get packet info safely
     */
    PacketInfo getPacketSafely(int index) const;

    /**
     * @brief Schedule delayed update to prevent UI flooding
     */
    void scheduleDelayedUpdate(int packetIndex);

    // View references
    PacketTableView *m_packetTable;
    HexView *m_hexView;
    ProtocolTreeView *m_protocolTree;

    // Model references
    PacketModel *m_packetModel;
    ProtocolTreeModel *m_protocolModel;

    // State
    int m_currentSelection;
    QString m_currentFieldName;
    QString m_currentFieldValue;
    int m_currentHighlightStart;
    int m_currentHighlightLength;

    // Update management
    QTimer *m_delayedUpdateTimer;
    int m_pendingUpdateIndex;
    bool m_updatePending;

    // Statistics
    int m_totalSelections;
    int m_totalFieldSelections;
    int m_totalHighlights;
};

#endif // PACKETDISPLAYCONTROLLER_H