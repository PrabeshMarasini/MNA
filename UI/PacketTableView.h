#ifndef PACKETTABLEVIEW_H
#define PACKETTABLEVIEW_H

#include <QTableView>
#include <QHeaderView>
#include <QContextMenuEvent>
#include <QMenu>
#include <QAction>
#include <QTimer>

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

signals:
    void packetSelected(int packetIndex);
    void packetDoubleClicked(int packetIndex);

protected:
    void contextMenuEvent(QContextMenuEvent *event) override;
    void selectionChanged(const QItemSelection &selected, const QItemSelection &deselected) override;

private slots:
    void onItemDoubleClicked(const QModelIndex &index);
    void onCopyPacketInfo();
    void onExportPacket();
    void onRowsInserted(const QModelIndex &parent, int first, int last);
    void onPacketsBatchAdded(int startIndex, int count);

private:
    void setupTable();
    void setupContextMenu();
    
    PacketModel *packetModel;
    QMenu *contextMenu;
    QAction *copyAction;
    QAction *exportAction;
    QAction *followStreamAction;
    QTimer *scrollUpdateTimer;
    bool autoScrollEnabled;
};

#endif // PACKETTABLEVIEW_H