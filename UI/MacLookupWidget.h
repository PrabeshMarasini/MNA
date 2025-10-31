#ifndef MACLOOKUPWIDGET_H
#define MACLOOKUPWIDGET_H

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <QLineEdit>
#include <QComboBox>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThread>
#include <QTimer>
#include <QProcess>
#include <QHeaderView>
#include <QGroupBox>
#include <QTabWidget>

class MacLookupWorker;
class LanScanWorker;

class MacLookupWidget : public QWidget
{
    Q_OBJECT

public:
    explicit MacLookupWidget(QWidget *parent = nullptr);
    ~MacLookupWidget();

private slots:
    void lookupMacAddress();
    void scanLanDevices();
    void clearResults();
    void onMacLookupResult(const QString &mac, const QString &vendor);
    void onMacLookupError(const QString &error);
    void onDeviceFound(const QString &ip, const QString &mac);
    void onVendorFound(const QString &mac, const QString &vendor);
    void onLanScanCompleted(int deviceCount);
    void onLanScanError(const QString &error);
    void onTableItemDoubleClicked(QTableWidgetItem *item);

private:
    void setupUI();
    void updateButtonStates();
    void addResultToTable(const QString &mac, const QString &vendor, const QString &ip = "");
    bool validateMacAddress(const QString &mac);
    void resetResults();

    // UI Components
    QVBoxLayout *m_mainLayout;
    QTabWidget *m_tabWidget;
    
    // Manual lookup tab
    QWidget *m_manualTab;
    QGridLayout *m_manualLayout;
    QLabel *m_macLabel;
    QLineEdit *m_macEdit;
    QPushButton *m_lookupButton;
    QPushButton *m_clearButton;
    
    // LAN scan tab
    QWidget *m_scanTab;
    QVBoxLayout *m_scanLayout;
    QPushButton *m_scanButton;
    QProgressBar *m_progressBar;
    QLabel *m_statusLabel;
    
    // Results table (shared)
    QTableWidget *m_resultsTable;
    
    // Worker threads
    QThread *m_macWorkerThread;
    MacLookupWorker *m_macWorker;
    QThread *m_scanWorkerThread;
    LanScanWorker *m_scanWorker;
    
    bool m_lookupInProgress;
    bool m_scanInProgress;
    int m_foundDevices;
};

// Worker class for MAC address lookup
class MacLookupWorker : public QObject
{
    Q_OBJECT

public:
    explicit MacLookupWorker(QObject *parent = nullptr);

public slots:
    void lookupMac(const QString &macAddress);
    void cancelLookup();

private slots:
    void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onProcessError(QProcess::ProcessError error);

signals:
    void macLookupResult(const QString &mac, const QString &vendor);
    void macLookupError(const QString &error);

private:
    bool m_cancelled;
    QProcess *m_process;
};

// Worker class for LAN device discovery and MAC lookup
class LanScanWorker : public QObject
{
    Q_OBJECT

public:
    explicit LanScanWorker(QObject *parent = nullptr);

public slots:
    void scanLanDevices();
    void cancelScan();

private slots:
    void onLanScanFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onLanScanError(QProcess::ProcessError error);
    void onMacLookupFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onMacLookupError(QProcess::ProcessError error);

signals:
    void deviceFound(const QString &ip, const QString &mac);
    void vendorFound(const QString &mac, const QString &vendor);
    void scanCompleted(int deviceCount);
    void scanError(const QString &error);

private:
    void parseLanScanOutput(const QString &output);
    void lookupNextMac();
    
    bool m_cancelled;
    QProcess *m_lanScanProcess;
    QProcess *m_macLookupProcess;
    
    struct DeviceInfo {
        QString ip;
        QString mac;
        QString vendor;
    };
    
    QList<DeviceInfo> m_devices;
    int m_currentLookupIndex;
    int m_totalDevices;
};

#endif // MACLOOKUPWIDGET_H