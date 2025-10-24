#include "ProtocolAnalysisWrapper.h"
#include "../Utils/NetworkInterfaceManager.h"
#include <QDebug>
#include <QProcess>
#include <QTemporaryFile>
#include <QTextStream>
#include <QRegularExpression>
#include <QHostAddress>
#include <QDateTime>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

// Output redirection helper class
class StdoutRedirector {
private:
    int originalStdout;
    int pipefd[2];
    QString capturedOutput;
    
public:
    StdoutRedirector() : originalStdout(-1) {
        if (pipe(pipefd) == -1) {
            qWarning() << "Failed to create pipe for stdout redirection";
            return;
        }
        
        // Make read end non-blocking
        int flags = fcntl(pipefd[0], F_GETFL);
        fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
    }
    
    ~StdoutRedirector() {
        restore();
        if (pipefd[0] != -1) close(pipefd[0]);
        if (pipefd[1] != -1) close(pipefd[1]);
    }
    
    bool redirect() {
        if (pipefd[1] == -1) return false;
        
        // Save original stdout
        originalStdout = dup(STDOUT_FILENO);
        if (originalStdout == -1) {
            qWarning() << "Failed to duplicate stdout";
            return false;
        }
        
        // Redirect stdout to pipe
        if (dup2(pipefd[1], STDOUT_FILENO) == -1) {
            qWarning() << "Failed to redirect stdout";
            close(originalStdout);
            originalStdout = -1;
            return false;
        }
        
        return true;
    }
    
    void restore() {
        if (originalStdout != -1) {
            // Flush any remaining output
            fflush(stdout);
            
            // Restore original stdout
            dup2(originalStdout, STDOUT_FILENO);
            close(originalStdout);
            originalStdout = -1;
        }
    }
    
    QString readOutput() {
        if (pipefd[0] == -1) return QString();
        
        char buffer[4096];
        QString output;
        
        // Read all available data from pipe
        while (true) {
            ssize_t bytesRead = read(pipefd[0], buffer, sizeof(buffer) - 1);
            if (bytesRead <= 0) {
                break; // No more data or error
            }
            
            buffer[bytesRead] = '\0';
            output += QString::fromUtf8(buffer);
        }
        
        return output;
    }
};

ProtocolAnalysisResult ProtocolAnalysisWrapper::analyzePacket(const QByteArray &packetData) {
    ProtocolAnalysisResult result;
    
    
    if (packetData.isEmpty()) {
        result.hasError = true;
        result.errorMessage = "Empty packet data";
        return result;
    }
    
    try {
        
        // Create stdout redirector
        StdoutRedirector redirector;
        
        // Redirect stdout to capture printf output
        if (!redirector.redirect()) {
            qWarning() << "Failed to redirect stdout, falling back to basic analysis";
            result.hasError = true;
            result.errorMessage = "Failed to capture protocol analysis output";
        } else {
            
            // Call the C library function - output will go to our pipe
            const u_char *data = reinterpret_cast<const u_char*>(packetData.constData());
            identify_protocol(data, packetData.size());
            
            
            // Flush stdout to ensure all output is written
            fflush(stdout);
            
            // Restore stdout and read captured output
            redirector.restore();
            QString capturedOutput = redirector.readOutput();
            
            
            // Parse the captured output
            if (!capturedOutput.isEmpty()) {
                result = parseProtocolOutput(capturedOutput);
            } else {
                qWarning() << "No output captured from protocol analysis";
                result.hasError = true;
                result.errorMessage = "No protocol analysis output captured";
            }
        }
        
        // Generate hex dump regardless of analysis success
        result.hexDump = generateHexDump(packetData);
        
        // Extract summary information
        result.summary = extractProtocolSummary(packetData);
        
        // If analysis failed but we have basic info, mark as partial success
        if (result.hasError && !result.summary.isEmpty()) {
            result.hasError = false;
            result.errorMessage.clear();
            
            // Create a basic protocol layer from summary
            if (result.layers.isEmpty()) {
                ProtocolLayer basicLayer("Basic Analysis");
                basicLayer.fields["Summary"] = result.summary;
                basicLayer.fields["Source IP"] = extractSourceIP(packetData);
                basicLayer.fields["Destination IP"] = extractDestinationIP(packetData);
                basicLayer.fields["Protocol"] = extractProtocolType(packetData);
                basicLayer.fields["Packet Length"] = QString::number(packetData.size());
                result.layers.append(basicLayer);
            }
        }
        
    } catch (const std::exception &e) {
        result.hasError = true;
        result.errorMessage = QString("Analysis error: %1").arg(e.what());
        
        // Still provide basic information
        result.hexDump = generateHexDump(packetData);
        result.summary = extractProtocolSummary(packetData);
    }
    
    return result;
}

QString ProtocolAnalysisWrapper::generateHexDump(const QByteArray &data) {
    QString hexDump;
    QTextStream stream(&hexDump);
    
    const int bytesPerLine = 16;
    const u_char *bytes = reinterpret_cast<const u_char*>(data.constData());
    
    for (int i = 0; i < data.size(); i += bytesPerLine) {
        // Offset
        stream << QString("%1  ").arg(i, 4, 16, QChar('0'));
        
        // Hex bytes
        for (int j = 0; j < bytesPerLine; j++) {
            if (i + j < data.size()) {
                stream << QString("%1 ").arg(bytes[i + j], 2, 16, QChar('0'));
            } else {
                stream << "   ";
            }
        }
        
        stream << " ";
        
        // ASCII representation
        for (int j = 0; j < bytesPerLine && i + j < data.size(); j++) {
            u_char ch = bytes[i + j];
            stream << (isprint(ch) ? QChar(ch) : QChar('.'));
        }
        
        stream << "\n";
    }
    
    return hexDump;
}

QString ProtocolAnalysisWrapper::extractProtocolSummary(const QByteArray &packetData) {
    if (packetData.size() < (int)sizeof(struct ethhdr)) {
        return "Invalid packet - too short";
    }
    
    const struct ethhdr *eth = reinterpret_cast<const struct ethhdr*>(packetData.constData());
    uint16_t ethType = ntohs(eth->h_proto);
    
    QString summary;
    
    switch (ethType) {
        case ETH_P_IP: {
            if (packetData.size() < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr))) {
                return "IPv4 packet - truncated";
            }
            
            const struct iphdr *ip = reinterpret_cast<const struct iphdr*>(
                packetData.constData() + sizeof(struct ethhdr));
            
            QString srcIP = ipToString(ip->saddr);
            QString dstIP = ipToString(ip->daddr);
            
            switch (ip->protocol) {
                case IPPROTO_TCP: {
                    if (packetData.size() >= (int)(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))) {
                        const struct tcphdr *tcp = reinterpret_cast<const struct tcphdr*>(
                            packetData.constData() + sizeof(struct ethhdr) + (ip->ihl * 4));
                        
                        uint16_t srcPort = ntohs(tcp->source);
                        uint16_t dstPort = ntohs(tcp->dest);
                        
                        summary = QString("TCP %1:%2 → %3:%4").arg(srcIP).arg(srcPort).arg(dstIP).arg(dstPort);
                        
                        // Add application protocol if known
                        if (srcPort == 80 || dstPort == 80) {
                            summary += " (HTTP)";
                        } else if (srcPort == 443 || dstPort == 443) {
                            summary += " (HTTPS)";
                        } else if (srcPort == 22 || dstPort == 22) {
                            summary += " (SSH)";
                        }
                    } else {
                        summary = QString("TCP %1 → %2").arg(srcIP, dstIP);
                    }
                    break;
                }
                case IPPROTO_UDP: {
                    if (packetData.size() >= (int)(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))) {
                        const struct udphdr *udp = reinterpret_cast<const struct udphdr*>(
                            packetData.constData() + sizeof(struct ethhdr) + (ip->ihl * 4));
                        
                        uint16_t srcPort = ntohs(udp->source);
                        uint16_t dstPort = ntohs(udp->dest);
                        
                        summary = QString("UDP %1:%2 → %3:%4").arg(srcIP).arg(srcPort).arg(dstIP).arg(dstPort);
                        
                        // Add application protocol if known
                        if (srcPort == 53 || dstPort == 53) {
                            summary += " (DNS)";
                        } else if ((srcPort == 67 && dstPort == 68) || (srcPort == 68 && dstPort == 67)) {
                            summary += " (DHCP)";
                        }
                    } else {
                        summary = QString("UDP %1 → %2").arg(srcIP, dstIP);
                    }
                    break;
                }
                case IPPROTO_ICMP:
                    summary = QString("ICMP %1 → %2").arg(srcIP, dstIP);
                    break;
                default:
                    summary = QString("IPv4 %1 → %2 (Protocol %3)").arg(srcIP, dstIP).arg(ip->protocol);
                    break;
            }
            break;
        }
        case ETH_P_IPV6:
            summary = "IPv6 packet";
            break;
        case ETH_P_ARP:
            summary = "ARP packet";
            break;
        default:
            summary = QString("Ethernet packet (Type 0x%1)").arg(ethType, 4, 16, QChar('0'));
            break;
    }
    
    return summary;
}

QString ProtocolAnalysisWrapper::extractSourceIP(const QByteArray &packetData) {
    if (packetData.size() < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr))) {
        return "Unknown";
    }
    
    const struct ethhdr *eth = reinterpret_cast<const struct ethhdr*>(packetData.constData());
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return "Non-IPv4";
    }
    
    const struct iphdr *ip = reinterpret_cast<const struct iphdr*>(
        packetData.constData() + sizeof(struct ethhdr));
    
    return ipToString(ip->saddr);
}

QString ProtocolAnalysisWrapper::extractDestinationIP(const QByteArray &packetData) {
    if (packetData.size() < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr))) {
        return "Unknown";
    }
    
    const struct ethhdr *eth = reinterpret_cast<const struct ethhdr*>(packetData.constData());
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return "Non-IPv4";
    }
    
    const struct iphdr *ip = reinterpret_cast<const struct iphdr*>(
        packetData.constData() + sizeof(struct ethhdr));
    
    return ipToString(ip->daddr);
}

QString ProtocolAnalysisWrapper::extractProtocolType(const QByteArray &packetData) {
    if (packetData.size() < (int)sizeof(struct ethhdr)) {
        return "Unknown";
    }
    
    const struct ethhdr *eth = reinterpret_cast<const struct ethhdr*>(packetData.constData());
    uint16_t ethType = ntohs(eth->h_proto);
    
    switch (ethType) {
        case ETH_P_IP: {
            if (packetData.size() < (int)(sizeof(struct ethhdr) + sizeof(struct iphdr))) {
                return "IPv4";
            }
            
            const struct iphdr *ip = reinterpret_cast<const struct iphdr*>(
                packetData.constData() + sizeof(struct ethhdr));
            
            switch (ip->protocol) {
                case IPPROTO_TCP: {
                    // Try to identify application protocol
                    if (packetData.size() >= (int)(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))) {
                        const struct tcphdr *tcp = reinterpret_cast<const struct tcphdr*>(
                            packetData.constData() + sizeof(struct ethhdr) + (ip->ihl * 4));
                        
                        uint16_t srcPort = ntohs(tcp->source);
                        uint16_t dstPort = ntohs(tcp->dest);
                        
                        if (srcPort == 80 || dstPort == 80) return "HTTP";
                        if (srcPort == 443 || dstPort == 443) return "HTTPS";
                        if (srcPort == 22 || dstPort == 22) return "SSH";
                        if (srcPort == 21 || dstPort == 21) return "FTP";
                        if (srcPort == 25 || dstPort == 25) return "SMTP";
                    }
                    return "TCP";
                }
                case IPPROTO_UDP: {
                    // Try to identify application protocol
                    if (packetData.size() >= (int)(sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))) {
                        const struct udphdr *udp = reinterpret_cast<const struct udphdr*>(
                            packetData.constData() + sizeof(struct ethhdr) + (ip->ihl * 4));
                        
                        uint16_t srcPort = ntohs(udp->source);
                        uint16_t dstPort = ntohs(udp->dest);
                        
                        if (srcPort == 53 || dstPort == 53) return "DNS";
                        if ((srcPort == 67 && dstPort == 68) || (srcPort == 68 && dstPort == 67)) return "DHCP";
                        if (srcPort == 123 || dstPort == 123) return "NTP";
                    }
                    return "UDP";
                }
                case IPPROTO_ICMP:
                    return "ICMP";
                default:
                    return QString("IPv4 Protocol %1").arg(ip->protocol);
            }
        }
        case ETH_P_IPV6:
            return "IPv6";
        case ETH_P_ARP:
            return "ARP";
        default:
            return QString("Ethernet 0x%1").arg(ethType, 4, 16, QChar('0'));
    }
}

ProtocolAnalysisResult ProtocolAnalysisWrapper::parseProtocolOutput(const QString &output) {
    ProtocolAnalysisResult result;
    
    if (output.isEmpty()) {
        result.hasError = true;
        result.errorMessage = "No analysis output received";
        return result;
    }
    
    // Parse the output from the C library
    // This is a simplified parser - in a real implementation, you might want
    // to modify the C library to output structured data (JSON, XML, etc.)
    
    QStringList lines = output.split('\n', Qt::SkipEmptyParts);
    ProtocolLayer currentLayer;
    bool inLayer = false;
    
    for (const QString &line : lines) {
        QString trimmedLine = line.trimmed();
        
        if (trimmedLine.startsWith("===") && trimmedLine.endsWith("===")) {
            // This is a protocol layer header
            if (inLayer && !currentLayer.name.isEmpty()) {
                result.layers.append(currentLayer);
            }
            
            // Extract layer name
            QString layerName = trimmedLine;
            layerName.remove("===");
            layerName = layerName.trimmed();
            
            currentLayer = ProtocolLayer(layerName);
            inLayer = true;
        }
        else if (inLayer && trimmedLine.contains(":")) {
            // This looks like a field: value pair
            int colonIndex = trimmedLine.indexOf(':');
            if (colonIndex > 0) {
                QString fieldName = trimmedLine.left(colonIndex).trimmed();
                QString fieldValue = trimmedLine.mid(colonIndex + 1).trimmed();
                
                if (!fieldName.isEmpty()) {
                    currentLayer.fields[fieldName] = fieldValue;
                }
            }
        }
        else if (!trimmedLine.isEmpty() && !trimmedLine.startsWith("=")) {
            // General information - add to current layer or create a general info layer
            if (!inLayer) {
                currentLayer = ProtocolLayer("General Information");
                inLayer = true;
            }
            
            // Try to extract key-value pairs from general text
            if (trimmedLine.contains(":")) {
                int colonIndex = trimmedLine.indexOf(':');
                QString key = trimmedLine.left(colonIndex).trimmed();
                QString value = trimmedLine.mid(colonIndex + 1).trimmed();
                currentLayer.fields[key] = value;
            } else {
                // Add as a general info field
                currentLayer.fields[QString("Info %1").arg(currentLayer.fields.size() + 1)] = trimmedLine;
            }
        }
    }
    
    // Add the last layer
    if (inLayer && !currentLayer.name.isEmpty()) {
        result.layers.append(currentLayer);
    }
    
    // If no layers were parsed, create a simple text layer
    if (result.layers.isEmpty()) {
        ProtocolLayer textLayer("Raw Output");
        textLayer.fields["Content"] = output;
        result.layers.append(textLayer);
    }
    
    result.hasError = false;
    return result;
}

QString ProtocolAnalysisWrapper::ipToString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return QString(inet_ntoa(addr));
}

QString ProtocolAnalysisWrapper::formatTimestamp(const struct timeval &tv) {
    QDateTime dateTime = QDateTime::fromSecsSinceEpoch(tv.tv_sec);
    return dateTime.toString("hh:mm:ss.zzz");
}

QString ProtocolAnalysisWrapper::formatMacAddress(const u_char *mac) {
    return QString("%1:%2:%3:%4:%5:%6")
        .arg(mac[0], 2, 16, QChar('0'))
        .arg(mac[1], 2, 16, QChar('0'))
        .arg(mac[2], 2, 16, QChar('0'))
        .arg(mac[3], 2, 16, QChar('0'))
        .arg(mac[4], 2, 16, QChar('0'))
        .arg(mac[5], 2, 16, QChar('0'));
}

// NetworkInterfaceManager is now implemented in Utils/NetworkInterfaceManager.cpp