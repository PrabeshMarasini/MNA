#ifndef PACKETTABLEVIEW_H
#define PACKETTABLEVIEW_H

#include <QTableView>
#include <QHeaderView>
#include <QContextMenuEvent>
#include <QMenu>
#include <QAction>
#include <QTimer>
#include <QScrollBar>

class PacketModel;

class PacketTableView : public QTableView
{
    Q_OBJECT

public:
    explicit PacketTableView(QWidget *parent = nullptr);
    ~PacketTableView();
    
    void setPacketModel(PacketModel *model);
    void setModel(QAbstractItemModel *model) override;

public slots:
    void scrollToBottom();
    void setAutoScroll(bool enabled);
    
    // Virtual scrolling methods
    void setVirtualScrollingEnabled(bool enabled);
    bool isVirtualScrollingEnabled() const;

signals:
    void packetSelected(int packetIndex);
    void packetDoubleClicked(int packetIndex);

protected:
    void contextMenuEvent(QContextMenuEvent *event) override;
    void selectionChanged(const QItemSelection &selected, const QItemSelection &deselected) override;
    void wheelEvent(QWheelEvent *event) override;  // For virtual scrolling
    void resizeEvent(QResizeEvent *event) override;  // For virtual scrolling

private slots:
    void onItemDoubleClicked(const QModelIndex &index);
    void onCopyPacketInfo();
    void onExportPacket();
    void onRowsInserted(const QModelIndex &parent, int first, int last);
    void onPacketsBatchAdded(int startIndex, int count);
    void onVerticalScrollChanged(int value);  // For virtual scrolling
    void updateVisibleRows();  // For virtual scrolling

private:
    void setupTable();
    void setupContextMenu();
    void updateRowHeights();  // For virtual scrolling
    
    PacketModel *packetModel;
    QMenu *contextMenu;
    QAction *copyAction;
    QAction *exportAction;
    QAction *followStreamAction;
    QTimer *scrollUpdateTimer;
    bool autoScrollEnabled;
    
    // Virtual scrolling
    bool virtualScrollingEnabled;
    int visibleRowCount;
    int firstVisibleRow;
    QTimer *viewportUpdateTimer;
};

#endif // PACKETTABLEVIEW_H