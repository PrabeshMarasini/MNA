#ifndef PRIVILEGECHECKER_H
#define PRIVILEGECHECKER_H

#include <QString>
#include <QObject>

class PrivilegeChecker : public QObject
{
    Q_OBJECT

public:
    explicit PrivilegeChecker(QObject *parent = nullptr);
    
    // Privilege checking
    static bool hasPacketCapturePrivileges();
    static bool isRunningAsRoot();
    static bool hasCapabilities();
    
    // Privilege elevation
    static bool requestPrivileges();
    static QString getPrivilegeInstructions();
    static QString getCapabilityInstructions();
    
    // Interface access testing
    static bool canAccessInterface(const QString &interface);
    static QString testInterfaceAccess(const QString &interface);
    
    // System information
    static QString getCurrentUser();
    static QString getEffectiveUser();
    static QStringList getGroups();
    
    // Error handling
    static QString getLastError();

private:
    static QString lastError;
    static void setError(const QString &error);
    static bool testPcapAccess();
    static bool checkCapability(const QString &capability);
};

#endif // PRIVILEGECHECKER_H