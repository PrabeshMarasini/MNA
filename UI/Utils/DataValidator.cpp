#include "DataValidator.h"
#include <QRegularExpression>
#include <QHostAddress>

QString DataValidator::lastError;

bool DataValidator::isValidPacketInfo(const PacketInfo &packet) {
    if (packet.serialNumber <= 0) {
        setError("Invalid serial number");
        return false;
    }
    
    if (!isValidTimestamp(packet.timestamp)) {
        setError("Invalid timestamp");
        return false;
    }
    
    if (!isValidIPAddress(packet.sourceIP)) {
        setError("Invalid source IP address");
        return false;
    }
    
    if (!isValidIPAddress(packet.destinationIP)) {
        setError("Invalid destination IP address");
        return false;
    }
    
    if (!isValidPacketLength(packet.packetLength)) {
        setError("Invalid packet length");
        return false;
    }
    
    if (!isValidProtocolType(packet.protocolType)) {
        setError("Invalid protocol type");
        return false;
    }
    
    if (packet.rawData.isEmpty()) {
        setError("Empty raw data");
        return false;
    }
    
    return true;
}

bool DataValidator::isValidIPAddress(const QString &ip) {
    if (ip.isEmpty()) {
        return false;
    }
    
    // Try to parse as IPv4 or IPv6
    QHostAddress address(ip);
    return !address.isNull();
}

bool DataValidator::isValidProtocolType(const QString &protocol) {
    if (protocol.isEmpty()) {
        return false;
    }
    
    // List of known protocol types
    QStringList validProtocols = {
        "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "SSH", "FTP", "SMTP", 
        "DNS", "DHCP", "ARP", "QUIC", "TLS", "IMAP", "POP3", "SNMP",
        "IPv4", "IPv6", "ICMPv6", "NTP", "TFTP", "Telnet", "SIP"
    };
    
    // Check if protocol matches any known type (case insensitive)
    for (const QString &validProtocol : validProtocols) {
        if (protocol.contains(validProtocol, Qt::CaseInsensitive)) {
            return true;
        }
    }
    
    // Allow unknown protocols but they should be reasonable strings
    QRegularExpression protocolRegex("^[A-Za-z0-9\\-_/\\s]+$");
    return protocolRegex.match(protocol).hasMatch() && protocol.length() <= 50;
}

bool DataValidator::isValidPacketLength(int length) {
    // Minimum Ethernet frame size is 64 bytes, maximum is 1518 bytes
    // But we allow larger packets for jumbo frames and smaller for fragments
    return length > 0 && length <= 65535;
}

bool DataValidator::isValidTimestamp(const QDateTime &timestamp) {
    if (!timestamp.isValid()) {
        return false;
    }
    
    // Timestamp should not be in the future (with some tolerance)
    QDateTime now = QDateTime::currentDateTime();
    QDateTime maxFuture = now.addSecs(60); // 1 minute tolerance
    
    // Timestamp should not be too old (more than 1 year)
    QDateTime minPast = now.addYears(-1);
    
    return timestamp >= minPast && timestamp <= maxFuture;
}

QString DataValidator::sanitizeIPAddress(const QString &ip) {
    QString sanitized = ip.trimmed();
    
    // Remove any invalid characters
    QRegularExpression validChars("[^0-9a-fA-F:.\\[\\]]");
    sanitized.remove(validChars);
    
    // Validate and return
    if (isValidIPAddress(sanitized)) {
        return sanitized;
    }
    
    return "Invalid IP";
}

QString DataValidator::sanitizeProtocolType(const QString &protocol) {
    QString sanitized = protocol.trimmed();
    
    // Remove any potentially dangerous characters
    QRegularExpression dangerousChars("[<>\"'&;]");
    sanitized.remove(dangerousChars);
    
    // Limit length
    if (sanitized.length() > 50) {
        sanitized = sanitized.left(50);
    }
    
    return sanitized.isEmpty() ? "Unknown" : sanitized;
}

QByteArray DataValidator::sanitizeRawData(const QByteArray &data, int maxSize) {
    if (data.size() <= maxSize) {
        return data;
    }
    
    // Truncate if too large
    return data.left(maxSize);
}

bool DataValidator::isValidProtocolAnalysisResult(const ProtocolAnalysisResult &result) {
    if (result.hasError && result.errorMessage.isEmpty()) {
        setError("Error flag set but no error message provided");
        return false;
    }
    
    if (!result.hasError && result.layers.isEmpty() && result.summary.isEmpty()) {
        setError("No protocol data available");
        return false;
    }
    
    // Validate each layer
    for (const ProtocolLayer &layer : result.layers) {
        if (!isValidProtocolLayer(layer)) {
            return false;
        }
    }
    
    return true;
}

bool DataValidator::isValidProtocolLayer(const ProtocolLayer &layer) {
    if (layer.name.isEmpty()) {
        setError("Protocol layer has empty name");
        return false;
    }
    
    // Layer name should be reasonable
    if (layer.name.length() > 100) {
        setError("Protocol layer name too long");
        return false;
    }
    
    // Validate fields
    QMapIterator<QString, QString> it(layer.fields);
    while (it.hasNext()) {
        it.next();
        if (it.key().isEmpty()) {
            setError("Protocol field has empty name");
            return false;
        }
        if (it.key().length() > 100 || it.value().length() > 500) {
            setError("Protocol field name or value too long");
            return false;
        }
    }
    
    return true;
}

bool DataValidator::isValidInterfaceName(const QString &interface) {
    if (interface.isEmpty()) {
        return false;
    }
    
    // Interface names should be reasonable
    QRegularExpression interfaceRegex("^[a-zA-Z0-9\\-_\\.]+$");
    return interfaceRegex.match(interface).hasMatch() && 
           interface.length() <= 50;
}

QString DataValidator::getLastError() {
    return lastError;
}

void DataValidator::setError(const QString &error) {
    lastError = error;
}

bool DataValidator::isValidIPv4(const QString &ip) {
    QRegularExpression ipv4Regex("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
    return ipv4Regex.match(ip).hasMatch();
}

bool DataValidator::isValidIPv6(const QString &ip) {
    // Use Qt's built-in IPv6 validation
    QHostAddress address(ip);
    return address.protocol() == QAbstractSocket::IPv6Protocol;
}

bool DataValidator::isValidMacAddress(const QString &mac) {
    QRegularExpression macRegex("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");
    return macRegex.match(mac).hasMatch();
}