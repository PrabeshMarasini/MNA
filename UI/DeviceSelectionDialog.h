#ifndef DEVICESELECTIONDIALOG_H
#define DEVICESELECTIONDIALOG_H

#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QComboBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QCheckBox>
#include <QProgressBar>
#include <QStatusBar>
#include <QGroupBox>
#include <QHeaderView>
#include <QTimer>
#include <sys/time.h>

class DeviceDiscoveryController;
class ARPSpoofingController;

struct NetworkDevice {
    QString ipAddress;
    QString macAddress;
    bool isGateway;
    bool isSelected;
    
    NetworkDevice() : isGateway(false), isSelected(false) {}
    NetworkDevice(const QString &ip, const QString &mac, bool gateway = false) 
        : ipAddress(ip), macAddress(mac), isGateway(gateway), isSelected(false) {}
};

class DeviceSelectionDialog : public QDialog
{
    Q_OBJECT

public:
    explicit DeviceSelectionDialog(QWidget *parent = nullptr);
    ~DeviceSelectionDialog();
    
    QList<QString> getSelectedDeviceIPs() const;
    QString getSelectedInterface() const;
    bool isSpoofingActive() const;
    QList<QString> getMACsForIPs(const QList<QString> &targetIPs) const;
    ARPSpoofingController* getSpoofingController() const;

public slots:
    void startDeviceDiscovery();
    void stopSpoofing();

signals:
    void spoofingStarted(const QList<QString> &targetIPs, const QString &interface);
    void spoofingStopped();
    void deviceSelectionChanged();
    void spoofedPacketCaptured(const QByteArray &packetData, const struct timeval &timestamp);

private slots:
    void onScanButtonClicked();
    void onSelectAllClicked();
    void onSelectNoneClicked();
    void onStartSpoofingClicked();
    void onStopSpoofingClicked();
    void onDeviceDiscovered(const NetworkDevice &device);
    void onDiscoveryCompleted(int deviceCount);
    void onDiscoveryError(const QString &error);
    void onSpoofingStatusChanged(bool active);
    void onSpoofingError(const QString &error);
    void onDeviceSelectionToggled();
    void updateSelectionCount();

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    void setupUI();
    void setupDeviceTable();
    void setupControlButtons();
    void setupStatusArea();
    void populateInterfaces();
    void clearDeviceList();
    void addDeviceToTable(const NetworkDevice &device);
    void updateButtonStates();
    void setDiscoveryInProgress(bool inProgress);
    
    // UI Components
    QVBoxLayout *mainLayout;
    QGroupBox *interfaceGroup;
    QComboBox *interfaceCombo;
    QPushButton *scanButton;
    
    QGroupBox *deviceGroup;
    QTableWidget *deviceTable;
    QPushButton *selectAllButton;
    QPushButton *selectNoneButton;
    QLabel *selectionCountLabel;
    
    QGroupBox *controlGroup;
    QPushButton *startSpoofingButton;
    QPushButton *stopSpoofingButton;
    QPushButton *closeButton;
    
    QProgressBar *progressBar;
    QLabel *statusLabel;
    
    // Controllers
    DeviceDiscoveryController *discoveryController;
    ARPSpoofingController *spoofingController;
    
    // State
    QList<NetworkDevice> discoveredDevices;
    QString currentInterface;
    bool spoofingActive;
    bool discoveryInProgress;
    
    // Table columns
    enum DeviceTableColumns {
        SelectColumn = 0,
        IPColumn,
        MACColumn,
        TypeColumn,
        ColumnCount
    };
};

#endif // DEVICESELECTIONDIALOG_H