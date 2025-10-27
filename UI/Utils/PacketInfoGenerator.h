#ifndef PACKETINFOGENERATOR_H
#define PACKETINFOGENERATOR_H

#include <QString>
#include <QByteArray>

class PacketInfoGenerator
{
public:
    static QString generateMoreInfo(const QString &protocolType, 
                                   const QString &sourceIP, 
                                   const QString &destinationIP,
                                   int packetLength,
                                   const QByteArray &rawData);

private:
    static QString generateTcpInfo(const QByteArray &rawData, const QString &sourceIP, const QString &destinationIP);
    static QString generateHttpInfo(const QByteArray &rawData);
    static QString generateDnsInfo(const QByteArray &rawData);
    static QString generateSshInfo(const QByteArray &rawData);
    static QString generateTlsInfo(const QByteArray &rawData);
    static QString generateDhcpInfo(const QByteArray &rawData);
    static QString generateArpInfo(const QByteArray &rawData);
    static QString generateIcmpInfo(const QByteArray &rawData);
    static QString generateFtpInfo(const QByteArray &rawData);
    static QString generateSmtpInfo(const QByteArray &rawData);
    
    static QString extractTcpFlags(const QByteArray &tcpHeader);
    static QString extractHttpMethod(const QByteArray &httpData);
    static QString extractHttpStatus(const QByteArray &httpData);
    static QString extractDnsQuery(const QByteArray &dnsData);
    static bool isEncryptedProtocol(const QString &protocolType);
};

#endif // PACKETINFOGENERATOR_H