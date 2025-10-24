#ifndef NETWORKINTERFACEMANAGER_H
#define NETWORKINTERFACEMANAGER_H

#include <QString>
#include <QStringList>
#include <QObject>
#include <QTimer>
#include <QNetworkInterface>
#include <QNetworkAddressEntry>

extern "C" {
    #include <pcap.h>
    #include <sys/types.h>
}

struct InterfaceInfo {
    QString name;
    QString description;
    QString addresses;
    bool isUp;
    bool isLoopback;
    bool canCapture;
    QString errorMessage;
    
    InterfaceInfo() : isUp(false), isLoopback(false), canCapture(false) {}
};

class NetworkInterfaceManager : public QObject
{
    Q_OBJECT

public:
    explicit NetworkInterfaceManager(QObject *parent = nullptr);
    ~NetworkInterfaceManager();
    
    // Interface discovery
    QStringList getAvailableInterfaces();
    QList<InterfaceInfo> getDetailedInterfaceList();
    InterfaceInfo getInterfaceInfo(const QString &interface);
    
    // Interface validation
    bool isInterfaceValid(const QString &interface);
    bool canCaptureOnInterface(const QString &interface);
    bool isInterfaceUp(const QString &interface);
    
    // Interface selection helpers
    QString getDefaultInterface();
    QString getBestCaptureInterface();
    QStringList getActiveInterfaces();
    QStringList getNonLoopbackInterfaces();
    
    // Interface descriptions
    QString getInterfaceDescription(const QString &interface);
    QString getInterfaceAddresses(const QString &interface);
    QString getInterfaceType(const QString &interface);
    
    // Error handling
    QString getLastError() const;
    bool hasError() const;
    
    // Refresh functionality
    void refreshInterfaceList();
    void startAutoRefresh(int intervalMs = 5000);
    void stopAutoRefresh();

signals:
    void interfaceListChanged();
    void interfaceStatusChanged(const QString &interface, bool isUp);
    void errorOccurred(const QString &error);

private slots:
    void onRefreshTimer();

private:
    // pcap interface management
    pcap_if_t* getAllDevices();
    void freeDeviceList(pcap_if_t *devices);
    bool testInterfaceCapture(const QString &interface);
    
    // Interface address formatting
    QString formatAddressList(const QList<QNetworkAddressEntry> &addresses);
    QNetworkInterface findQtInterface(const QString &name);
    
    // Internal state
    QList<InterfaceInfo> cachedInterfaces;
    QString lastError;
    QTimer *refreshTimer;
    bool autoRefreshEnabled;
    
    // Helper methods
    void setError(const QString &error);
    void clearError();
    bool isPrivilegedUser();
    QString getInterfaceTypeFromName(const QString &name);
};

// Utility functions for interface management
class InterfaceUtils
{
public:
    static bool requiresPrivileges();
    static QString getPrivilegeInstructions();
    static bool isWirelessInterface(const QString &interface);
    static bool isEthernetInterface(const QString &interface);
    static QString formatInterfaceName(const QString &interface);
    static QString getInterfaceIcon(const QString &interface);
    
private:
    static QStringList getWirelessPrefixes();
    static QStringList getEthernetPrefixes();
};

#endif // NETWORKINTERFACEMANAGER_H