#include "NetworkInterfaceManager.h"
#include "ErrorHandler.h"
#include <QDebug>
#include <QNetworkInterface>
#include <QNetworkAddressEntry>
#include <QProcess>
#include <unistd.h>

NetworkInterfaceManager::NetworkInterfaceManager(QObject *parent)
    : QObject(parent)
    , refreshTimer(new QTimer(this))
    , autoRefreshEnabled(false)
{
    connect(refreshTimer, &QTimer::timeout, this, &NetworkInterfaceManager::onRefreshTimer);
    refreshInterfaceList();
}

NetworkInterfaceManager::~NetworkInterfaceManager() {
    stopAutoRefresh();
}

QStringList NetworkInterfaceManager::getAvailableInterfaces() {
    QStringList interfaces;
    
    pcap_if_t *alldevs = getAllDevices();
    if (!alldevs) {
        return interfaces;
    }
    
    for (pcap_if_t *device = alldevs; device != nullptr; device = device->next) {
        if (device->name) {
            QString interfaceName = QString::fromUtf8(device->name);
            interfaces.append(interfaceName);
        }
    }
    
    freeDeviceList(alldevs);
    return interfaces;
}

QList<InterfaceInfo> NetworkInterfaceManager::getDetailedInterfaceList() {
    QList<InterfaceInfo> interfaces;
    
    try {
        pcap_if_t *alldevs = getAllDevices();
        if (!alldevs) {
            QString errorMsg = "Failed to enumerate network interfaces";
            setError(errorMsg);
            LOG_NETWORK_ERROR(errorMsg, "Check if libpcap is properly installed and you have sufficient privileges");
            return interfaces;
        }
    
    for (pcap_if_t *device = alldevs; device != nullptr; device = device->next) {
        if (!device->name) continue;
        
        InterfaceInfo info;
        info.name = QString::fromUtf8(device->name);
        
        // Get description
        if (device->description) {
            info.description = QString::fromUtf8(device->description);
        } else {
            info.description = QString("Interface %1").arg(info.name);
        }
        
        // Check if interface is up (use PCAP_IF_UP if available, otherwise assume up)
        #ifdef PCAP_IF_DOWN
        info.isUp = !(device->flags & PCAP_IF_DOWN);
        #else
        info.isUp = true; // Assume up if flag not available
        #endif
        
        // Check if it's loopback
        info.isLoopback = (device->flags & PCAP_IF_LOOPBACK);
        
        // Get addresses from Qt network interface
        QNetworkInterface qtInterface = findQtInterface(info.name);
        if (qtInterface.isValid()) {
            info.addresses = formatAddressList(qtInterface.addressEntries());
            info.isUp = info.isUp && (qtInterface.flags() & QNetworkInterface::IsUp);
        }
        
        // Test if we can capture on this interface
        info.canCapture = testInterfaceCapture(info.name);
        
        interfaces.append(info);
    }
    
        freeDeviceList(alldevs);
        cachedInterfaces = interfaces;
        
        if (interfaces.isEmpty()) {
            LOG_NETWORK_ERROR("No network interfaces found", "This may indicate a system configuration issue");
        } else {
            LOG_INFO(QString("Found %1 network interfaces").arg(interfaces.size()));
        }
        
        return interfaces;
        
    } catch (const std::exception &e) {
        QString errorMsg = QString("Exception while enumerating interfaces: %1").arg(e.what());
        setError(errorMsg);
        LOG_NETWORK_ERROR(errorMsg, "Unexpected error during interface enumeration");
        return interfaces;
    } catch (...) {
        QString errorMsg = "Unknown exception while enumerating interfaces";
        setError(errorMsg);
        LOG_NETWORK_ERROR(errorMsg, "Unexpected error during interface enumeration");
        return interfaces;
    }
}

InterfaceInfo NetworkInterfaceManager::getInterfaceInfo(const QString &interface) {
    // First check cached interfaces
    for (const InterfaceInfo &info : cachedInterfaces) {
        if (info.name == interface) {
            return info;
        }
    }
    
    // If not found in cache, refresh and try again
    getDetailedInterfaceList();
    for (const InterfaceInfo &info : cachedInterfaces) {
        if (info.name == interface) {
            return info;
        }
    }
    
    // Return empty info if not found
    InterfaceInfo emptyInfo;
    emptyInfo.name = interface;
    emptyInfo.description = "Interface not found";
    emptyInfo.errorMessage = "Interface not available";
    return emptyInfo;
}

bool NetworkInterfaceManager::isInterfaceValid(const QString &interface) {
    if (interface.isEmpty()) {
        return false;
    }
    
    QStringList availableInterfaces = getAvailableInterfaces();
    return availableInterfaces.contains(interface);
}

bool NetworkInterfaceManager::canCaptureOnInterface(const QString &interface) {
    return testInterfaceCapture(interface);
}

bool NetworkInterfaceManager::isInterfaceUp(const QString &interface) {
    InterfaceInfo info = getInterfaceInfo(interface);
    return info.isUp;
}

QString NetworkInterfaceManager::getDefaultInterface() {
    char *defaultDevice = nullptr;
    char errorBuffer[PCAP_ERRBUF_SIZE];
    
    defaultDevice = pcap_lookupdev(errorBuffer);
    if (defaultDevice) {
        return QString::fromUtf8(defaultDevice);
    }
    
    // Fallback: return best capture interface
    return getBestCaptureInterface();
}

QString NetworkInterfaceManager::getBestCaptureInterface() {
    QList<InterfaceInfo> interfaces = getDetailedInterfaceList();
    
    // Priority order:
    // 1. Non-loopback, up, can capture
    // 2. Non-loopback, can capture
    // 3. Any interface that can capture
    // 4. First available interface
    
    QString bestInterface;
    
    // First pass: non-loopback, up, can capture
    for (const InterfaceInfo &info : interfaces) {
        if (!info.isLoopback && info.isUp && info.canCapture) {
            return info.name;
        }
    }
    
    // Second pass: non-loopback, can capture
    for (const InterfaceInfo &info : interfaces) {
        if (!info.isLoopback && info.canCapture) {
            return info.name;
        }
    }
    
    // Third pass: any interface that can capture
    for (const InterfaceInfo &info : interfaces) {
        if (info.canCapture) {
            return info.name;
        }
    }
    
    // Last resort: first available interface
    if (!interfaces.isEmpty()) {
        return interfaces.first().name;
    }
    
    return QString();
}

QStringList NetworkInterfaceManager::getActiveInterfaces() {
    QStringList activeInterfaces;
    QList<InterfaceInfo> interfaces = getDetailedInterfaceList();
    
    for (const InterfaceInfo &info : interfaces) {
        if (info.isUp && !info.isLoopback) {
            activeInterfaces.append(info.name);
        }
    }
    
    return activeInterfaces;
}

QStringList NetworkInterfaceManager::getNonLoopbackInterfaces() {
    QStringList nonLoopbackInterfaces;
    QList<InterfaceInfo> interfaces = getDetailedInterfaceList();
    
    for (const InterfaceInfo &info : interfaces) {
        if (!info.isLoopback) {
            nonLoopbackInterfaces.append(info.name);
        }
    }
    
    return nonLoopbackInterfaces;
}

QString NetworkInterfaceManager::getInterfaceDescription(const QString &interface) {
    InterfaceInfo info = getInterfaceInfo(interface);
    return info.description;
}

QString NetworkInterfaceManager::getInterfaceAddresses(const QString &interface) {
    InterfaceInfo info = getInterfaceInfo(interface);
    return info.addresses;
}

QString NetworkInterfaceManager::getInterfaceType(const QString &interface) {
    return getInterfaceTypeFromName(interface);
}

QString NetworkInterfaceManager::getLastError() const {
    return lastError;
}

bool NetworkInterfaceManager::hasError() const {
    return !lastError.isEmpty();
}

void NetworkInterfaceManager::refreshInterfaceList() {
    clearError();
    QList<InterfaceInfo> oldInterfaces = cachedInterfaces;
    QList<InterfaceInfo> newInterfaces = getDetailedInterfaceList();
    
    // Check for changes
    bool hasChanges = (oldInterfaces.size() != newInterfaces.size());
    
    if (!hasChanges) {
        for (int i = 0; i < oldInterfaces.size(); ++i) {
            if (oldInterfaces[i].name != newInterfaces[i].name ||
                oldInterfaces[i].isUp != newInterfaces[i].isUp) {
                hasChanges = true;
                break;
            }
        }
    }
    
    if (hasChanges) {
        emit interfaceListChanged();
        
        // Check for status changes
        for (const InterfaceInfo &newInfo : newInterfaces) {
            for (const InterfaceInfo &oldInfo : oldInterfaces) {
                if (newInfo.name == oldInfo.name && newInfo.isUp != oldInfo.isUp) {
                    emit interfaceStatusChanged(newInfo.name, newInfo.isUp);
                }
            }
        }
    }
}

void NetworkInterfaceManager::startAutoRefresh(int intervalMs) {
    autoRefreshEnabled = true;
    refreshTimer->start(intervalMs);
}

void NetworkInterfaceManager::stopAutoRefresh() {
    autoRefreshEnabled = false;
    refreshTimer->stop();
}

void NetworkInterfaceManager::onRefreshTimer() {
    if (autoRefreshEnabled) {
        refreshInterfaceList();
    }
}

pcap_if_t* NetworkInterfaceManager::getAllDevices() {
    pcap_if_t *alldevs = nullptr;
    char errorBuffer[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&alldevs, errorBuffer) == -1) {
        setError(QString("Error finding devices: %1").arg(errorBuffer));
        return nullptr;
    }
    
    return alldevs;
}

void NetworkInterfaceManager::freeDeviceList(pcap_if_t *devices) {
    if (devices) {
        pcap_freealldevs(devices);
    }
}

bool NetworkInterfaceManager::testInterfaceCapture(const QString &interface) {
    if (interface.isEmpty()) {
        return false;
    }
    
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface.toUtf8().constData(), 
                                   65536, // snaplen
                                   0,     // promisc
                                   1,     // timeout_ms
                                   errorBuffer);
    
    if (handle) {
        pcap_close(handle);
        return true;
    }
    
    return false;
}

QNetworkInterface NetworkInterfaceManager::findQtInterface(const QString &name) {
    QList<QNetworkInterface> interfaces = QNetworkInterface::allInterfaces();
    
    for (const QNetworkInterface &iface : interfaces) {
        if (iface.name() == name) {
            return iface;
        }
    }
    
    return QNetworkInterface();
}

QString NetworkInterfaceManager::formatAddressList(const QList<QNetworkAddressEntry> &addresses) {
    QStringList addressStrings;
    
    for (const QNetworkAddressEntry &entry : addresses) {
        QHostAddress addr = entry.ip();
        if (!addr.isNull() && !addr.isLoopback()) {
            addressStrings.append(addr.toString());
        }
    }
    
    return addressStrings.join(", ");
}

void NetworkInterfaceManager::setError(const QString &error) {
    lastError = error;
    emit errorOccurred(error);
}

void NetworkInterfaceManager::clearError() {
    lastError.clear();
}

bool NetworkInterfaceManager::isPrivilegedUser() {
    return geteuid() == 0;
}

QString NetworkInterfaceManager::getInterfaceTypeFromName(const QString &name) {
    if (InterfaceUtils::isWirelessInterface(name)) {
        return "Wireless";
    } else if (InterfaceUtils::isEthernetInterface(name)) {
        return "Ethernet";
    } else if (name.startsWith("lo")) {
        return "Loopback";
    } else if (name.startsWith("tun") || name.startsWith("tap")) {
        return "Tunnel";
    } else if (name.startsWith("br")) {
        return "Bridge";
    } else if (name.startsWith("docker") || name.startsWith("veth")) {
        return "Virtual";
    }
    
    return "Unknown";
}

// InterfaceUtils implementation
bool InterfaceUtils::requiresPrivileges() {
    return geteuid() != 0;
}

QString InterfaceUtils::getPrivilegeInstructions() {
    return "Packet capture requires root privileges. Please run the application with sudo:\n"
           "sudo ./PacketCaptureGUI\n\n"
           "Or set up capabilities for the executable:\n"
           "sudo setcap cap_net_raw,cap_net_admin=eip ./PacketCaptureGUI";
}

bool InterfaceUtils::isWirelessInterface(const QString &interface) {
    QStringList wirelessPrefixes = getWirelessPrefixes();
    
    for (const QString &prefix : wirelessPrefixes) {
        if (interface.startsWith(prefix)) {
            return true;
        }
    }
    
    return false;
}

bool InterfaceUtils::isEthernetInterface(const QString &interface) {
    QStringList ethernetPrefixes = getEthernetPrefixes();
    
    for (const QString &prefix : ethernetPrefixes) {
        if (interface.startsWith(prefix)) {
            return true;
        }
    }
    
    return false;
}

QString InterfaceUtils::formatInterfaceName(const QString &interface) {
    if (interface.length() > 15) {
        return interface.left(12) + "...";
    }
    return interface;
}

QString InterfaceUtils::getInterfaceIcon(const QString &interface) {
    if (isWirelessInterface(interface)) {
        return "📶"; // Wireless signal icon
    } else if (isEthernetInterface(interface)) {
        return "🔌"; // Ethernet plug icon
    } else if (interface.startsWith("lo")) {
        return "🔄"; // Loopback icon
    } else if (interface.startsWith("tun") || interface.startsWith("tap")) {
        return "🚇"; // Tunnel icon
    } else if (interface.startsWith("docker") || interface.startsWith("veth")) {
        return "📦"; // Container icon
    }
    
    return "🌐"; // Generic network icon
}

QStringList InterfaceUtils::getWirelessPrefixes() {
    return {"wlan", "wlp", "wifi", "ath", "ra", "wl"};
}

QStringList InterfaceUtils::getEthernetPrefixes() {
    return {"eth", "enp", "eno", "ens", "em", "p"};
}