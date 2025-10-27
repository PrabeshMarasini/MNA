#include "PacketInfoGenerator.h"
#include <QRegularExpression>
#include <QStringList>

QString PacketInfoGenerator::generateMoreInfo(const QString &protocolType, 
                                             const QString &sourceIP, 
                                             const QString &destinationIP,
                                             int packetLength,
                                             const QByteArray &rawData)
{
    QString info;
    
    // Protocol-specific information
    if (protocolType.contains("TCP", Qt::CaseInsensitive)) {
        info = generateTcpInfo(rawData, sourceIP, destinationIP);
    }
    else if (protocolType.contains("HTTP", Qt::CaseInsensitive) && !protocolType.contains("HTTPS", Qt::CaseInsensitive)) {
        info = generateHttpInfo(rawData);
        if (info.isEmpty()) {
            info = "HTTP Traffic";
        }
    }
    else if (protocolType.contains("HTTPS", Qt::CaseInsensitive) || protocolType.contains("TLS", Qt::CaseInsensitive)) {
        info = generateTlsInfo(rawData);
        if (info.isEmpty()) {
            info = "HTTPS/TLS Traffic";
        }
    }
    else if (protocolType.contains("DNS", Qt::CaseInsensitive)) {
        info = generateDnsInfo(rawData);
    }
    else if (protocolType.contains("SSH", Qt::CaseInsensitive)) {
        info = generateSshInfo(rawData);
        if (info.isEmpty()) {
            info = "SSH Encrypted Traffic";
        }
    }
    else if (protocolType.contains("DHCP", Qt::CaseInsensitive)) {
        info = generateDhcpInfo(rawData);
    }
    else if (protocolType.contains("ARP", Qt::CaseInsensitive)) {
        info = generateArpInfo(rawData);
    }
    else if (protocolType.contains("ICMP", Qt::CaseInsensitive)) {
        info = generateIcmpInfo(rawData);
    }
    else if (protocolType.contains("FTP", Qt::CaseInsensitive)) {
        info = generateFtpInfo(rawData);
        if (info.isEmpty()) {
            info = "FTP Unencrypted";
        }
    }
    else if (protocolType.contains("SMTP", Qt::CaseInsensitive)) {
        info = generateSmtpInfo(rawData);
        if (info.isEmpty()) {
            info = "SMTP Mail Transfer";
        }
    }
    else if (protocolType.contains("UDP", Qt::CaseInsensitive)) {
        info = QString("UDP %1 → %2").arg(sourceIP, destinationIP);
    }
    
    // Add security indicators
    if (info.isEmpty()) {
        if (isEncryptedProtocol(protocolType)) {
            info = QString("%1 Encrypted").arg(protocolType);
        } else {
            info = QString("%1 Plain Text").arg(protocolType);
        }
    }
    
    // Add packet size info for large packets
    if (packetLength > 1400) {
        info += QString(" [%1 bytes]").arg(packetLength);
    } else if (packetLength == 0) {
        info += " [Keep-alive]";
    }
    
    return info;
}

QString PacketInfoGenerator::generateTcpInfo(const QByteArray &rawData, const QString &sourceIP, const QString &destinationIP)
{
    if (rawData.size() < 54) return QString(); // Ethernet + IP + TCP minimum
    
    // Skip Ethernet (14) and IP (20) headers to get to TCP
    int tcpOffset = 34;
    if (rawData.size() < tcpOffset + 20) return QString();
    
    const unsigned char *tcpHeader = reinterpret_cast<const unsigned char*>(rawData.data() + tcpOffset);
    
    // Extract TCP flags (byte 13 of TCP header)
    unsigned char flags = tcpHeader[13];
    QString flagStr = extractTcpFlags(QByteArray(reinterpret_cast<const char*>(&flags), 1));
    
    // Extract ports (bytes 0-1 source, 2-3 destination)
    unsigned short srcPort = (tcpHeader[0] << 8) | tcpHeader[1];
    unsigned short dstPort = (tcpHeader[2] << 8) | tcpHeader[3];
    
    // Extract sequence and ack numbers
    unsigned int seqNum = (tcpHeader[4] << 24) | (tcpHeader[5] << 16) | (tcpHeader[6] << 8) | tcpHeader[7];
    unsigned int ackNum = (tcpHeader[8] << 24) | (tcpHeader[9] << 16) | (tcpHeader[10] << 8) | tcpHeader[11];
    
    QString info;
    
    // Determine connection state and create appropriate message
    if (flags & 0x02) { // SYN
        if (flags & 0x10) { // ACK
            info = QString("SYN+ACK %1:%2 → %3:%4").arg(sourceIP).arg(srcPort).arg(destinationIP).arg(dstPort);
        } else {
            info = QString("SYN %1:%2 → %3:%4").arg(sourceIP).arg(srcPort).arg(destinationIP).arg(dstPort);
        }
    }
    else if (flags & 0x01) { // FIN
        info = QString("FIN %1:%2 → %3:%4").arg(sourceIP).arg(srcPort).arg(destinationIP).arg(dstPort);
    }
    else if (flags & 0x04) { // RST
        info = QString("RST %1:%2 → %3:%4 [Connection Reset]").arg(sourceIP).arg(srcPort).arg(destinationIP).arg(dstPort);
    }
    else if (flags & 0x08) { // PSH
        info = QString("PSH+ACK %1:%2 → %3:%4 [Data]").arg(sourceIP).arg(srcPort).arg(destinationIP).arg(dstPort);
    }
    else if (flags & 0x10) { // ACK only
        info = QString("ACK %1:%2 → %3:%4").arg(sourceIP).arg(srcPort).arg(destinationIP).arg(dstPort);
    }
    
    // Add sequence info for data packets
    if ((flags & 0x08) || (flags & 0x18)) { // PSH or PSH+ACK
        info += QString(" Seq=%1").arg(seqNum);
    }
    
    // Check for well-known ports and add application hints
    if (srcPort == 80 || dstPort == 80) {
        info += " [HTTP]";
    } else if (srcPort == 443 || dstPort == 443) {
        info += " [HTTPS]";
    } else if (srcPort == 22 || dstPort == 22) {
        info += " [SSH]";
    } else if (srcPort == 21 || dstPort == 21) {
        info += " [FTP]";
    } else if (srcPort == 25 || dstPort == 25) {
        info += " [SMTP]";
    }
    
    return info;
}

QString PacketInfoGenerator::generateHttpInfo(const QByteArray &rawData)
{
    // Look for HTTP data in the packet
    QString data = QString::fromLatin1(rawData);
    
    // Check for HTTP request methods
    if (data.contains("GET ")) {
        QRegularExpression re("GET\\s+([^\\s]+)\\s+HTTP");
        QRegularExpressionMatch match = re.match(data);
        if (match.hasMatch()) {
            return QString("HTTP GET %1").arg(match.captured(1));
        }
        return "HTTP GET Request";
    }
    else if (data.contains("POST ")) {
        QRegularExpression re("POST\\s+([^\\s]+)\\s+HTTP");
        QRegularExpressionMatch match = re.match(data);
        if (match.hasMatch()) {
            return QString("HTTP POST %1").arg(match.captured(1));
        }
        return "HTTP POST Request";
    }
    else if (data.contains("HTTP/1.1 ") || data.contains("HTTP/1.0 ")) {
        QRegularExpression re("HTTP/[0-9.]+\\s+(\\d+)\\s+([^\\r\\n]+)");
        QRegularExpressionMatch match = re.match(data);
        if (match.hasMatch()) {
            QString status = match.captured(1);
            QString reason = match.captured(2);
            return QString("HTTP %1 %2").arg(status, reason);
        }
        return "HTTP Response";
    }
    
    return QString();
}

QString PacketInfoGenerator::generateDnsInfo(const QByteArray &rawData)
{
    if (rawData.size() < 42) return QString(); // Ethernet + IP + UDP + DNS minimum
    
    // Skip to DNS header (Ethernet 14 + IP 20 + UDP 8 = 42)
    int dnsOffset = 42;
    if (rawData.size() < dnsOffset + 12) return QString();
    
    const unsigned char *dnsHeader = reinterpret_cast<const unsigned char*>(rawData.data() + dnsOffset);
    
    // Extract DNS flags
    unsigned short flags = (dnsHeader[2] << 8) | dnsHeader[3];
    bool isResponse = (flags & 0x8000) != 0;
    unsigned short opcode = (flags >> 11) & 0x0F;
    unsigned short rcode = flags & 0x0F;
    
    // Extract question count
    unsigned short qdcount = (dnsHeader[4] << 8) | dnsHeader[5];
    unsigned short ancount = (dnsHeader[6] << 8) | dnsHeader[7];
    
    QString info;
    
    if (isResponse) {
        if (rcode == 0) {
            info = QString("DNS Response: %1 answer(s)").arg(ancount);
        } else if (rcode == 3) {
            info = "DNS Response: NXDOMAIN (Name not found)";
        } else {
            info = QString("DNS Response: Error (RCODE=%1)").arg(rcode);
        }
    } else {
        if (opcode == 0) {
            info = QString("DNS Query: %1 question(s)").arg(qdcount);
        } else {
            info = QString("DNS Query: Opcode %1").arg(opcode);
        }
    }
    
    return info;
}

QString PacketInfoGenerator::generateSshInfo(const QByteArray &rawData)
{
    QString data = QString::fromLatin1(rawData);
    
    // Look for SSH version string
    if (data.contains("SSH-")) {
        QRegularExpression re("SSH-([0-9.]+)-([^\\r\\n]+)");
        QRegularExpressionMatch match = re.match(data);
        if (match.hasMatch()) {
            return QString("SSH Version: %1 (%2)").arg(match.captured(1), match.captured(2));
        }
        return "SSH Protocol Exchange";
    }
    
    return QString();
}

QString PacketInfoGenerator::generateTlsInfo(const QByteArray &rawData)
{
    if (rawData.size() < 60) return QString(); // Minimum for TLS over TCP
    
    // Look for TLS record header (after Ethernet + IP + TCP headers)
    // This is a simplified check - real implementation would need proper offset calculation
    for (int i = 40; i < rawData.size() - 5; i++) {
        unsigned char recordType = rawData[i];
        unsigned char majorVersion = rawData[i + 1];
        unsigned char minorVersion = rawData[i + 2];
        
        if (recordType == 0x16 && majorVersion == 0x03) { // Handshake record, TLS
            if (minorVersion == 0x01) return "TLS 1.0 Handshake";
            if (minorVersion == 0x02) return "TLS 1.1 Handshake";
            if (minorVersion == 0x03) return "TLS 1.2 Handshake";
            if (minorVersion == 0x04) return "TLS 1.3 Handshake";
            return "TLS Handshake";
        }
        else if (recordType == 0x17 && majorVersion == 0x03) { // Application data
            return "TLS Application Data (Encrypted)";
        }
        else if (recordType == 0x15 && majorVersion == 0x03) { // Alert
            return "TLS Alert";
        }
    }
    
    return QString();
}

QString PacketInfoGenerator::generateDhcpInfo(const QByteArray &rawData)
{
    if (rawData.size() < 282) return QString(); // Minimum DHCP packet size
    
    // DHCP starts after Ethernet + IP + UDP (42 bytes)
    int dhcpOffset = 42;
    if (rawData.size() < dhcpOffset + 240) return QString();
    
    const unsigned char *dhcpHeader = reinterpret_cast<const unsigned char*>(rawData.data() + dhcpOffset);
    
    unsigned char op = dhcpHeader[0]; // 1 = request, 2 = reply
    
    // Look for DHCP message type option (option 53)
    for (int i = dhcpOffset + 240; i < rawData.size() - 3; i++) {
        if (rawData[i] == 53 && rawData[i + 1] == 1) { // Option 53, length 1
            unsigned char msgType = rawData[i + 2];
            switch (msgType) {
                case 1: return "DHCP Discover";
                case 2: return "DHCP Offer";
                case 3: return "DHCP Request";
                case 4: return "DHCP Decline";
                case 5: return "DHCP ACK";
                case 6: return "DHCP NAK";
                case 7: return "DHCP Release";
                case 8: return "DHCP Inform";
                default: return QString("DHCP Message Type %1").arg(msgType);
            }
        }
    }
    
    return op == 1 ? "DHCP Request" : "DHCP Reply";
}

QString PacketInfoGenerator::generateArpInfo(const QByteArray &rawData)
{
    if (rawData.size() < 42) return QString(); // Minimum ARP packet
    
    // ARP starts after Ethernet header (14 bytes)
    const unsigned char *arpHeader = reinterpret_cast<const unsigned char*>(rawData.data() + 14);
    
    unsigned short opcode = (arpHeader[6] << 8) | arpHeader[7];
    
    // Extract IP addresses (assuming IPv4)
    QString senderIP = QString("%1.%2.%3.%4")
        .arg(arpHeader[14]).arg(arpHeader[15]).arg(arpHeader[16]).arg(arpHeader[17]);
    QString targetIP = QString("%1.%2.%3.%4")
        .arg(arpHeader[24]).arg(arpHeader[25]).arg(arpHeader[26]).arg(arpHeader[27]);
    
    if (opcode == 1) { // ARP Request
        return QString("ARP Request: Who has %1? Tell %2").arg(targetIP, senderIP);
    } else if (opcode == 2) { // ARP Reply
        return QString("ARP Reply: %1 is at %2:%3:%4:%5:%6:%7")
            .arg(senderIP)
            .arg(arpHeader[8], 2, 16, QChar('0'))
            .arg(arpHeader[9], 2, 16, QChar('0'))
            .arg(arpHeader[10], 2, 16, QChar('0'))
            .arg(arpHeader[11], 2, 16, QChar('0'))
            .arg(arpHeader[12], 2, 16, QChar('0'))
            .arg(arpHeader[13], 2, 16, QChar('0'));
    }
    
    return QString("ARP Opcode %1").arg(opcode);
}

QString PacketInfoGenerator::generateIcmpInfo(const QByteArray &rawData)
{
    if (rawData.size() < 42) return QString(); // Minimum ICMP packet
    
    // ICMP starts after Ethernet + IP headers (34 bytes minimum)
    const unsigned char *icmpHeader = reinterpret_cast<const unsigned char*>(rawData.data() + 34);
    
    unsigned char type = icmpHeader[0];
    unsigned char code = icmpHeader[1];
    
    switch (type) {
        case 0: return "ICMP Echo Reply (Ping Reply)";
        case 3: 
            switch (code) {
                case 0: return "ICMP Destination Network Unreachable";
                case 1: return "ICMP Destination Host Unreachable";
                case 2: return "ICMP Destination Protocol Unreachable";
                case 3: return "ICMP Destination Port Unreachable";
                default: return QString("ICMP Destination Unreachable (Code %1)").arg(code);
            }
        case 8: return "ICMP Echo Request (Ping)";
        case 11: return "ICMP Time Exceeded";
        default: return QString("ICMP Type %1 Code %2").arg(type).arg(code);
    }
}

QString PacketInfoGenerator::generateFtpInfo(const QByteArray &rawData)
{
    QString data = QString::fromLatin1(rawData);
    
    // FTP commands
    if (data.contains("USER ")) return "FTP USER Command";
    if (data.contains("PASS ")) return "FTP PASS Command (Password!)";
    if (data.contains("LIST")) return "FTP LIST Command";
    if (data.contains("RETR ")) return "FTP File Download";
    if (data.contains("STOR ")) return "FTP File Upload";
    
    // FTP responses
    QRegularExpression re("^(\\d{3})\\s+(.+)");
    QRegularExpressionMatch match = re.match(data);
    if (match.hasMatch()) {
        return QString("FTP Response: %1 %2").arg(match.captured(1), match.captured(2));
    }
    
    return QString();
}

QString PacketInfoGenerator::generateSmtpInfo(const QByteArray &rawData)
{
    QString data = QString::fromLatin1(rawData);
    
    // SMTP commands
    if (data.contains("HELO ")) return "SMTP HELO";
    if (data.contains("EHLO ")) return "SMTP EHLO";
    if (data.contains("MAIL FROM:")) return "SMTP Mail From";
    if (data.contains("RCPT TO:")) return "SMTP Recipient";
    if (data.contains("DATA")) return "SMTP Data Transfer";
    if (data.contains("QUIT")) return "SMTP Quit";
    
    // SMTP responses
    QRegularExpression re("^(\\d{3})\\s+(.+)");
    QRegularExpressionMatch match = re.match(data);
    if (match.hasMatch()) {
        QString code = match.captured(1);
        if (code.startsWith("2")) return QString("SMTP OK: %1").arg(code);
        if (code.startsWith("4")) return QString("SMTP Temp Error: %1").arg(code);
        if (code.startsWith("5")) return QString("SMTP Error: %1").arg(code);
        return QString("SMTP Response: %1").arg(code);
    }
    
    return QString();
}

QString PacketInfoGenerator::extractTcpFlags(const QByteArray &tcpHeader)
{
    if (tcpHeader.isEmpty()) return QString();
    
    unsigned char flags = tcpHeader[0];
    QStringList flagList;
    
    if (flags & 0x01) flagList << "FIN";
    if (flags & 0x02) flagList << "SYN";
    if (flags & 0x04) flagList << "RST";
    if (flags & 0x08) flagList << "PSH";
    if (flags & 0x10) flagList << "ACK";
    if (flags & 0x20) flagList << "URG";
    
    return flagList.join("+");
}

bool PacketInfoGenerator::isEncryptedProtocol(const QString &protocolType)
{
    QStringList encryptedProtocols = {
        "HTTPS", "TLS", "SSL", "SSH", "SFTP", "FTPS", "IMAPS", "POP3S", "SMTPS"
    };
    
    for (const QString &encrypted : encryptedProtocols) {
        if (protocolType.contains(encrypted, Qt::CaseInsensitive)) {
            return true;
        }
    }
    
    return false;
}