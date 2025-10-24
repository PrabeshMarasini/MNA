#ifndef NETWORKINTERFACEDIALOG_H
#define NETWORKINTERFACEDIALOG_H

#include <QDialog>
#include <QTableView>
#include <QPushButton>
#include <QLabel>
#include <QCheckBox>
#include <QTextEdit>
#include <QProgressBar>
#include <QTimer>
#include <QStandardItemModel>
#include <QSortFilterProxyModel>

class NetworkInterfaceManager;
struct InterfaceInfo;

class NetworkInterfaceDialog : public QDialog
{
    Q_OBJECT

public:
    explicit NetworkInterfaceDialog(QWidget *parent = nullptr);
    ~NetworkInterfaceDialog();
    
    QString getSelectedInterface() const;

private slots:
    void refreshInterfaceList();
    void onInterfaceSelected();
    void onInterfaceDoubleClicked(const QModelIndex &index);
    void onRefreshClicked();
    void onSelectClicked();
    void onTestClicked();
    void onFilterChanged();
    void handleError(const QString &error);
    void checkPrivileges();

private:
    void setupUI();
    void setupModel();
    void connectSignals();
    void updateInterfaceDetails(const QString &interface);
    void updateButtonStates();
    void autoSelectBestInterface();
    QString getHelpText() const;
    
    // UI Components
    QLabel *instructionLabel;
    QLabel *privilegeStatusLabel;
    QTableView *interfaceTable;
    QCheckBox *showAllCheckBox;

    QPushButton *refreshButton;
    QPushButton *selectButton;
    QPushButton *cancelButton;
    QPushButton *testButton;
    QTextEdit *interfaceDetailsText;
    QTextEdit *helpText;
    QProgressBar *progressBar;
    
    // Data and models
    NetworkInterfaceManager *interfaceManager;
    QStandardItemModel *interfaceModel;
    QSortFilterProxyModel *proxyModel;
    QString selectedInterface;
    
    // Timers
    QTimer *refreshTimer;
    QTimer *privilegeCheckTimer;
};

#endif // NETWORKINTERFACEDIALOG_H