#ifndef PROTOCOLANALYSISWRAPPER_H
#define PROTOCOLANALYSISWRAPPER_H

#include <QString>
#include <QByteArray>
#include "../Models/ProtocolTreeModel.h"

extern "C" {
    #include "protocol.h"
    #include <pcap.h>
    #include <sys/types.h>
}

class ProtocolAnalysisWrapper
{
public:
    static ProtocolAnalysisResult analyzePacket(const QByteArray &packetData);
    static QString generateHexDump(const QByteArray &data);
    static QString extractProtocolSummary(const QByteArray &packetData);
    static QString extractSourceIP(const QByteArray &packetData);
    static QString extractDestinationIP(const QByteArray &packetData);
    static QString extractProtocolType(const QByteArray &packetData);
    
private:
    static ProtocolAnalysisResult parseProtocolOutput(const QString &output);
    static void captureProtocolOutput(void (*analysisFunction)(const u_char*, int), 
                                    const u_char *data, int len, QString &output);
    static ProtocolLayer parseEthernetLayer(const u_char *packet, int len);
    static ProtocolLayer parseIPLayer(const u_char *packet, int len);
    static ProtocolLayer parseTransportLayer(const u_char *packet, int len);
    static ProtocolLayer parseApplicationLayer(const u_char *packet, int len);
    
    // Helper functions for packet parsing
    static QString ipToString(uint32_t ip);
    static QString formatTimestamp(const struct timeval &tv);
    static QString formatMacAddress(const u_char *mac);
};

// Forward declaration - NetworkInterfaceManager is now in Utils/
class NetworkInterfaceManager;

#endif // PROTOCOLANALYSISWRAPPER_H