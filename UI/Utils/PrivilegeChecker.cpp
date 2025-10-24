#include "PrivilegeChecker.h"
#include <QProcess>
#include <QDebug>
#include <QFileInfo>
#include <QCoreApplication>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

extern "C" {
    #include <pcap.h>
}

QString PrivilegeChecker::lastError;

PrivilegeChecker::PrivilegeChecker(QObject *parent)
    : QObject(parent)
{
}

bool PrivilegeChecker::hasPacketCapturePrivileges() {
    // Check if running as root
    if (isRunningAsRoot()) {
        return true;
    }
    
    // Check if has capabilities
    if (hasCapabilities()) {
        return true;
    }
    
    // Test actual pcap access
    return testPcapAccess();
}

bool PrivilegeChecker::isRunningAsRoot() {
    return geteuid() == 0;
}

bool PrivilegeChecker::hasCapabilities() {
    // Check for CAP_NET_RAW and CAP_NET_ADMIN capabilities
    return checkCapability("cap_net_raw") && checkCapability("cap_net_admin");
}

bool PrivilegeChecker::requestPrivileges() {
    if (hasPacketCapturePrivileges()) {
        return true;
    }
    
    setError("Insufficient privileges for packet capture");
    return false;
}

QString PrivilegeChecker::getPrivilegeInstructions() {
    QString instructions;
    
    if (isRunningAsRoot()) {
        instructions = "Running with root privileges - packet capture should work.";
    } else {
        instructions = "Packet capture requires elevated privileges.\n\n";
        instructions += "Option 1: Run with sudo\n";
        instructions += "  sudo ./PacketCaptureGUI\n\n";
        instructions += "Option 2: Set capabilities (recommended)\n";
        instructions += getCapabilityInstructions();
        instructions += "\n\nOption 3: Add user to pcap group (if available)\n";
        instructions += "  sudo usermod -a -G pcap " + getCurrentUser();
    }
    
    return instructions;
}

QString PrivilegeChecker::getCapabilityInstructions() {
    QString executable = QCoreApplication::applicationFilePath();
    
    return QString("  sudo setcap cap_net_raw,cap_net_admin=eip %1\n"
                  "  # Then run without sudo:\n"
                  "  %1").arg(executable);
}

bool PrivilegeChecker::canAccessInterface(const QString &interface) {
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
    
    setError(QString("Cannot access interface %1: %2").arg(interface, errorBuffer));
    return false;
}

QString PrivilegeChecker::testInterfaceAccess(const QString &interface) {
    if (canAccessInterface(interface)) {
        return QString("Interface %1 is accessible").arg(interface);
    } else {
        return QString("Interface %1 is not accessible: %2").arg(interface, getLastError());
    }
}

QString PrivilegeChecker::getCurrentUser() {
    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    
    if (pw) {
        return QString::fromUtf8(pw->pw_name);
    }
    
    return QString::number(uid);
}

QString PrivilegeChecker::getEffectiveUser() {
    uid_t euid = geteuid();
    struct passwd *pw = getpwuid(euid);
    
    if (pw) {
        return QString::fromUtf8(pw->pw_name);
    }
    
    return QString::number(euid);
}

QStringList PrivilegeChecker::getGroups() {
    QStringList groups;
    
    int ngroups = getgroups(0, nullptr);
    if (ngroups > 0) {
        gid_t *groupList = new gid_t[ngroups];
        if (getgroups(ngroups, groupList) != -1) {
            for (int i = 0; i < ngroups; ++i) {
                struct group *gr = getgrgid(groupList[i]);
                if (gr) {
                    groups.append(QString::fromUtf8(gr->gr_name));
                }
            }
        }
        delete[] groupList;
    }
    
    return groups;
}

QString PrivilegeChecker::getLastError() {
    return lastError;
}

void PrivilegeChecker::setError(const QString &error) {
    lastError = error;
}

bool PrivilegeChecker::testPcapAccess() {
    char errorBuffer[PCAP_ERRBUF_SIZE];
    
    // Try to find devices
    pcap_if_t *alldevs = nullptr;
    if (pcap_findalldevs(&alldevs, errorBuffer) == -1) {
        setError(QString("Cannot enumerate interfaces: %1").arg(errorBuffer));
        return false;
    }
    
    bool canAccess = false;
    
    // Try to open the first available interface
    for (pcap_if_t *device = alldevs; device != nullptr; device = device->next) {
        if (device->name) {
            pcap_t *handle = pcap_open_live(device->name,
                                           65536, // snaplen
                                           0,     // promisc
                                           1,     // timeout_ms
                                           errorBuffer);
            
            if (handle) {
                pcap_close(handle);
                canAccess = true;
                break;
            }
        }
    }
    
    pcap_freealldevs(alldevs);
    
    if (!canAccess) {
        setError("Cannot open any network interface for packet capture");
    }
    
    return canAccess;
}

bool PrivilegeChecker::checkCapability(const QString &capability) {
    QProcess process;
    process.start("getcap", QStringList() << QCoreApplication::applicationFilePath());
    process.waitForFinished(3000);
    
    if (process.exitCode() == 0) {
        QString output = process.readAllStandardOutput();
        return output.contains(capability, Qt::CaseInsensitive);
    }
    
    return false;
}