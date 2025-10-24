#ifndef PROTOCOLTREEVIEW_H
#define PROTOCOLTREEVIEW_H

#include <QTreeView>
#include <QHeaderView>
#include <QContextMenuEvent>
#include <QMenu>
#include <QAction>
#include <QModelIndex>

class ProtocolTreeModel;

class ProtocolTreeView : public QTreeView
{
    Q_OBJECT

public:
    explicit ProtocolTreeView(QWidget *parent = nullptr);
    ~ProtocolTreeView();
    
    void setProtocolModel(ProtocolTreeModel *model);

signals:
    void fieldSelected(const QString &fieldName, const QString &fieldValue);
    void bytesHighlighted(int startOffset, int length);

protected:
    void contextMenuEvent(QContextMenuEvent *event) override;

private slots:
    void onItemClicked(const QModelIndex &index);
    void onItemExpanded(const QModelIndex &index);
    void onCopyFieldName();
    void onCopyFieldValue();
    void onCopyBoth();
    void onExpandAll();
    void onCollapseAll();

private:
    void setupTree();
    void setupContextMenu();
    void expandImportantNodes();
    
    ProtocolTreeModel *protocolModel;
    QMenu *contextMenu;
    QAction *copyNameAction;
    QAction *copyValueAction;
    QAction *copyBothAction;
    QAction *expandAllAction;
    QAction *collapseAllAction;
    
    QModelIndex currentContextIndex;
};

#endif // PROTOCOLTREEVIEW_H