#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSplitter>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QToolBar>
#include <QAction>
#include <QStatusBar>
#include <QLabel>
#include <QTimer>
#include <QModelIndex>
#include <sys/time.h>
#include "Models/PacketModel.h"
#include "PacketFilterWidget.h"
#include "TimeZoneSettings.h"


class PacketTableView;
class HexView;
class ProtocolTreeView;
class PacketCaptureController;
class PacketDisplayController;
class PacketModel;
class ProtocolTreeModel;
class PacketFilterProxyModel;
class PacketParserWorker;
class DeviceSelectionDialog;
class ARPSpoofingController;
class SpeedTestWidget;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(const QString &interface, QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onStartCapture();
    void onStopCapture();
    void onNewPacketCaptured(const PacketInfo &packet);
    void onNewPacketsBatchCaptured(const QList<PacketInfo> &packets);
    void onCaptureError(const QString &error);
    void onCaptureStatusChanged(bool isCapturing);
    void onSelectionChanged(int packetIndex);
    void onFieldSelected(const QString &fieldName, const QString &fieldValue, int packetIndex);
    void onBytesHighlighted(int startOffset, int length, int packetIndex);
    void onDisplayError(const QString &error);
    void updateStatistics();
    void performThrottledUIUpdate();
    
    // Error handling slots
    void onCriticalError(const QString &message);
    void onCriticalMemory();
    void resetCaptureController();
    void resetApplicationState();
    
    // Memory and performance management slots
    void onMemoryLimitExceeded();
    void onBackpressureApplied();
    void onSamplingApplied();
    
    // Settings management slots
    void onSettingChanged(const QString &key, const QVariant &value);
    void saveWindowSettings();
    void restoreWindowSettings();
    
    // Filter slots
    void onFilterChanged(const PacketFilterWidget::FilterCriteria &criteria);
    void onFilterCleared();
    
    // Device selection and ARP spoofing slots
    void onDeviceSelectionRequested();
    void onSpoofingStarted(const QList<QString> &targetIPs, const QString &interface);
    void onSpoofingStopped();
    void onSpoofingTargetPacketCaptured(const QByteArray &packetData, const struct timeval &timestamp);
    
    // Export functionality
    void onExportPackets();
    
    // Speed test functionality
    void onSpeedTestRequested();
    
    // Latency test functionality
    void onLatencyTestRequested();
    
    // Port scanner functionality
    void onPortScanRequested();
    
    // MAC address lookup functionality
    void onMacLookupRequested();
    
    // DNS lookup functionality
    void onDnsLookupRequested();
    
    // Traceroute functionality
    void onTracerouteRequested();
    
    // Settings functionality
    void onTimeSettingsRequested();


protected:
    void closeEvent(QCloseEvent *event) override;

private:
    void setupUI();
    void setupToolBar();
    void setupStatusBar();
    void setupSplitters();
    void setupMenuBar();
    void connectSignals();
    QList<QString> getTargetMACsFromIPs(const QList<QString> &targetIPs);
    
    // Export helper methods
    void exportToJson(const QString &fileName);
    void exportToPcap(const QString &fileName);
    
    // UI Components
    QWidget *centralWidget;
    QSplitter *mainSplitter;
    QSplitter *bottomSplitter;
    
    PacketTableView *packetTable;
    HexView *hexView;
    ProtocolTreeView *protocolView;
    PacketFilterWidget *filterWidget;
    
    // Toolbar and actions
    QToolBar *mainToolBar;
    QAction *startCaptureAction;
    QAction *stopCaptureAction;
    QAction *clearPacketsAction;
    QAction *savePacketsAction;
    QAction *deviceSelectionAction;

    QAction *exitAction;
    
    // Status bar
    QLabel *interfaceLabel;
    QLabel *captureStatusLabel;
    QLabel *packetCountLabel;
    QLabel *bytesCountLabel;
    QLabel *spoofingStatusLabel;

    QTimer *statisticsTimer;
    QTimer *uiUpdateTimer;
    
    // Controllers and models
    PacketCaptureController *captureController;
    PacketDisplayController *displayController;
    PacketModel *packetModel;
    ProtocolTreeModel *protocolModel;
    PacketFilterProxyModel *filterProxyModel;
    
    // Device selection dialog and ARP spoofing
    DeviceSelectionDialog *deviceSelectionDialog;
    ARPSpoofingController *arpSpoofingController;
    
    // State
    QString networkInterface;
    bool isCapturing;
    int packetCount;
    qint64 totalBytes;
    bool spoofingActive;
    QList<QString> spoofedTargets;
    
    // Settings
    TimeZoneMode currentTimeZoneMode;
    QTimeZone customTimeZone;
};

#endif // MAINWINDOW_H