# Protocol Analysis Wrapper

This directory contains the C library integration wrapper that bridges the existing C-based packet capture and protocol analysis code with the Qt GUI application.

## ProtocolAnalysisWrapper

The main wrapper class that provides Qt-friendly interfaces to the existing C protocol analysis functions.

### Key Features

- **Packet Analysis**: Integrates with `identify_protocol()` from `protocol.c`
- **Hex Dump Generation**: Creates formatted hexadecimal dumps of packet data
- **Protocol Extraction**: Extracts protocol type, source/destination IPs, and summary information
- **Error Handling**: Provides robust error handling and validation
- **Output Parsing**: Converts C library text output to structured Qt data

### Main Functions

```cpp
// Analyze a complete packet using existing C library functions
ProtocolAnalysisResult analyzePacket(const QByteArray &packetData);

// Generate formatted hex dump
QString generateHexDump(const QByteArray &data);

// Extract specific packet information
QString extractProtocolSummary(const QByteArray &packetData);
QString extractSourceIP(const QByteArray &packetData);
QString extractDestinationIP(const QByteArray &packetData);
QString extractProtocolType(const QByteArray &packetData);
```

### Integration Approach

The wrapper uses several strategies to integrate with the existing C code:

1. **Direct Function Calls**: Calls existing C functions like `identify_protocol()`
2. **Output Capture**: Captures printf output from C functions (simplified approach)
3. **Manual Parsing**: Directly parses packet headers for reliable data extraction
4. **Error Handling**: Wraps C operations in try-catch blocks

### Protocol Support

Supports all protocols implemented in the existing C library:
- **Network Layer**: IPv4, IPv6, ARP, ICMP
- **Transport Layer**: TCP, UDP
- **Application Layer**: HTTP, HTTPS, SSH, FTP, SMTP, DNS, DHCP, QUIC, SNMP, IMAP

## NetworkInterfaceManager

Manages network interface enumeration and validation using libpcap.

### Features

- **Interface Discovery**: Uses `pcap_findalldevs()` to enumerate interfaces
- **Interface Validation**: Validates interface names and availability
- **Default Interface**: Provides default interface selection
- **Interface Descriptions**: Retrieves human-readable interface descriptions

### Usage

```cpp
// Get all available interfaces
QStringList interfaces = NetworkInterfaceManager::getAvailableInterfaces();

// Validate an interface
bool isValid = NetworkInterfaceManager::isInterfaceValid("eth0");

// Get default interface
QString defaultIface = NetworkInterfaceManager::getDefaultInterface();
```

## Data Structures

### ProtocolAnalysisResult
```cpp
struct ProtocolAnalysisResult {
    QString summary;                    // Brief packet description
    QList<ProtocolLayer> layers;       // Hierarchical protocol layers
    QString hexDump;                    // Formatted hex dump
    bool hasError;                      // Error flag
    QString errorMessage;               // Error description
};
```

### ProtocolLayer
```cpp
struct ProtocolLayer {
    QString name;                       // Layer name (e.g., "Ethernet II")
    QMap<QString, QString> fields;      // Field name-value pairs
    QList<ProtocolLayer> subLayers;     // Nested layers
};
```

## Testing

Comprehensive test suite includes:

### Unit Tests (`test_wrapper.cpp`)
- Hex dump generation
- Protocol type extraction
- IP address extraction
- Network interface management
- Error handling

### Integration Tests (`test_integration.cpp`)
- Real packet analysis with C library
- Multiple protocol types
- Error scenarios
- Performance testing

### Sample Data (`sample_packets.h`)
- Pre-built test packets for various protocols
- Expected results for validation
- Malformed packet test cases

## Build Integration

The wrapper is integrated into the CMake build system:

```cmake
# Links with existing C library
target_link_libraries(PacketCaptureGUI
    packetcapture_backend
    ${PCAP_LIBRARIES}
)
```

## Performance Considerations

- **Memory Management**: Proper cleanup of packet data and analysis results
- **Thread Safety**: Designed for use in multi-threaded Qt applications
- **Caching**: Minimal caching to avoid memory bloat during long captures
- **Error Recovery**: Graceful handling of malformed or truncated packets

## Future Improvements

1. **Structured Output**: Modify C library to output JSON/XML instead of text
2. **Shared Memory**: Use shared memory for high-performance packet passing
3. **Plugin Architecture**: Support for dynamically loaded protocol analyzers
4. **Streaming Analysis**: Support for real-time streaming packet analysis

## Dependencies

- **Qt6 Core**: For Qt data types and utilities
- **libpcap**: For network interface management
- **Existing C Libraries**: All protocol analyzers in `src/protocols/`
- **Standard C Libraries**: For network header structures

## Error Handling

The wrapper provides comprehensive error handling:

- **Input Validation**: Validates packet data before analysis
- **C Library Errors**: Catches and converts C library errors
- **Memory Errors**: Handles allocation failures gracefully
- **Network Errors**: Manages interface access errors
- **Protocol Errors**: Handles malformed or unknown protocols