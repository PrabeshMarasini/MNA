#ifndef DATAVALIDATOR_H
#define DATAVALIDATOR_H

#include <QString>
#include <QByteArray>
#include <QDateTime>
#include "../Models/PacketModel.h"
#include "../Models/ProtocolTreeModel.h"

class DataValidator
{
public:
    // Packet validation
    static bool isValidPacketInfo(const PacketInfo &packet);
    static bool isValidIPAddress(const QString &ip);
    static bool isValidProtocolType(const QString &protocol);
    static bool isValidPacketLength(int length);
    static bool isValidTimestamp(const QDateTime &timestamp);
    
    // Data sanitization
    static QString sanitizeIPAddress(const QString &ip);
    static QString sanitizeProtocolType(const QString &protocol);
    static QByteArray sanitizeRawData(const QByteArray &data, int maxSize = 65535);
    
    // Protocol analysis validation
    static bool isValidProtocolAnalysisResult(const ProtocolAnalysisResult &result);
    static bool isValidProtocolLayer(const ProtocolLayer &layer);
    
    // Network interface validation
    static bool isValidInterfaceName(const QString &interface);
    
    // Error messages
    static QString getLastError();
    
private:
    static QString lastError;
    static void setError(const QString &error);
    
    // IP address validation helpers
    static bool isValidIPv4(const QString &ip);
    static bool isValidIPv6(const QString &ip);
    static bool isValidMacAddress(const QString &mac);
};

#endif // DATAVALIDATOR_H