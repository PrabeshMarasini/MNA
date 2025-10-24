#ifndef PROTOCOLTREEMODEL_H
#define PROTOCOLTREEMODEL_H

#include <QAbstractItemModel>
#include <QModelIndex>
#include <QVariant>
#include <QString>
#include <QMap>
#include <QList>

struct ProtocolLayer {
    QString name;
    QMap<QString, QString> fields;
    QList<ProtocolLayer> subLayers;
    
    ProtocolLayer() = default;
    ProtocolLayer(const QString &layerName) : name(layerName) {}
};

struct ProtocolAnalysisResult {
    QString summary;
    QList<ProtocolLayer> layers;
    QString hexDump;
    bool hasError;
    QString errorMessage;
    
    ProtocolAnalysisResult() : hasError(false) {}
};

class ProtocolTreeItem
{
public:
    explicit ProtocolTreeItem(const QString &name, const QString &value = QString(), ProtocolTreeItem *parent = nullptr);
    ~ProtocolTreeItem();

    void appendChild(ProtocolTreeItem *child);
    ProtocolTreeItem *child(int row);
    int childCount() const;
    int columnCount() const;
    QVariant data(int column) const;
    int row() const;
    ProtocolTreeItem *parentItem();
    
    void setName(const QString &name);
    void setValue(const QString &value);
    QString getName() const;
    QString getValue() const;

private:
    QList<ProtocolTreeItem*> childItems;
    QString itemName;
    QString itemValue;
    ProtocolTreeItem *parent;
};

class ProtocolTreeModel : public QAbstractItemModel
{
    Q_OBJECT

public:
    enum ItemDataRole {
        FieldNameRole = Qt::UserRole + 1,
        FieldValueRole,
        StartOffsetRole,
        LengthRole
    };

    explicit ProtocolTreeModel(QObject *parent = nullptr);
    ~ProtocolTreeModel();

    // Model interface
    QVariant data(const QModelIndex &index, int role) const override;
    Qt::ItemFlags flags(const QModelIndex &index) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
    QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const override;
    QModelIndex parent(const QModelIndex &index) const override;
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;

    // Protocol data management
    void setProtocolData(const ProtocolAnalysisResult &result);
    void clear();

private:
    void setupModelData(const ProtocolAnalysisResult &result);
    void addProtocolLayer(const ProtocolLayer &layer, ProtocolTreeItem *parent);
    
    ProtocolTreeItem *rootItem;
};

#endif // PROTOCOLTREEMODEL_H