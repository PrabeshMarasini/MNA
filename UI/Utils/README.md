# Utility Classes

This directory contains utility classes that provide common functionality for the Packet Capture GUI.

## NetworkInterfaceManager

Comprehensive network interface management with Qt integration and real-time monitoring.

### Features

- **Interface Discovery**: Enumerates all available network interfaces using libpcap
- **Detailed Information**: Provides interface descriptions, addresses, and status
- **Interface Validation**: Validates interface availability and capture capability
- **Smart Selection**: Provides best interface selection algorithms
- **Real-time Monitoring**: Auto-refresh with change notifications
- **Qt Integration**: Integrates with Qt's QNetworkInterface for additional information

### Key Methods

```cpp
// Basic interface management
QStringList getAvailableInterfaces();
QList<InterfaceInfo> getDetailedInterfaceList();
bool isInterfaceValid(const QString &interface);

// Smart interface selection
QString getDefaultInterface();
QString getBestCaptureInterface();
QStringList getActiveInterfaces();

// Real-time monitoring
void startAutoRefresh(int intervalMs = 5000);
void stopAutoRefresh();

// Signals
void interfaceListChanged();
void interfaceStatusChanged(const QString &interface, bool isUp);
```

### InterfaceInfo Structure

```cpp
struct InterfaceInfo {
    QString name;           // Interface name (e.g., "eth0")
    QString description;    // Human-readable description
    QString addresses;      // IP addresses (comma-separated)
    bool isUp;             // Interface is up and running
    bool isLoopback;       // Is loopback interface
    bool canCapture;       // Can capture packets on this interface
    QString errorMessage;   // Error message if any
};
```

## PrivilegeChecker

Handles privilege detection and management for packet capture operations.

### Features

- **Privilege Detection**: Detects root privileges, capabilities, and pcap access
- **Interface Testing**: Tests actual packet capture capability on interfaces
- **User Information**: Provides current user and group information
- **Instructions**: Generates platform-specific privilege elevation instructions
- **Error Handling**: Comprehensive error reporting for privilege issues

### Key Methods

```cpp
// Privilege checking
static bool hasPacketCapturePrivileges();
static bool isRunningAsRoot();
static bool hasCapabilities();

// Interface access testing
static bool canAccessInterface(const QString &interface);
static QString testInterfaceAccess(const QString &interface);

// Instructions and help
static QString getPrivilegeInstructions();
static QString getCapabilityInstructions();

// User information
static QString getCurrentUser();
static QStringList getGroups();
```

### Privilege Elevation Options

1. **Run as Root**: `sudo ./PacketCaptureGUI`
2. **Set Capabilities**: `sudo setcap cap_net_raw,cap_net_admin=eip ./PacketCaptureGUI`
3. **Add to pcap Group**: `sudo usermod -a -G pcap username`

## DataValidator

Provides validation and sanitization for all data structures used in the application.

### Features

- **Packet Validation**: Validates PacketInfo structures
- **Network Validation**: IP address, protocol type, interface name validation
- **Data Sanitization**: Cleans and limits data to prevent issues
- **Protocol Validation**: Validates protocol analysis results
- **Error Reporting**: Detailed error messages for validation failures

### Key Methods

```cpp
// Packet validation
static bool isValidPacketInfo(const PacketInfo &packet);
static bool isValidIPAddress(const QString &ip);
static bool isValidProtocolType(const QString &protocol);

// Data sanitization
static QString sanitizeIPAddress(const QString &ip);
static QString sanitizeProtocolType(const QString &protocol);
static QByteArray sanitizeRawData(const QByteArray &data, int maxSize = 65535);

// Protocol validation
static bool isValidProtocolAnalysisResult(const ProtocolAnalysisResult &result);
static bool isValidInterfaceName(const QString &interface);
```

## InterfaceUtils

Static utility functions for interface type detection and formatting.

### Features

- **Interface Type Detection**: Identifies wireless, ethernet, loopback, etc.
- **Name Formatting**: Formats interface names for display
- **Icon Assignment**: Provides appropriate icons for different interface types
- **Platform Compatibility**: Works across different Linux distributions

### Key Methods

```cpp
// Interface type detection
static bool isWirelessInterface(const QString &interface);
static bool isEthernetInterface(const QString &interface);

// Formatting and display
static QString formatInterfaceName(const QString &interface);
static QString getInterfaceIcon(const QString &interface);

// Privilege helpers
static bool requiresPrivileges();
static QString getPrivilegeInstructions();
```

### Interface Type Detection

The utility recognizes common interface naming patterns:

- **Wireless**: `wlan*`, `wlp*`, `wifi*`, `ath*`, `ra*`, `wl*`
- **Ethernet**: `eth*`, `enp*`, `eno*`, `ens*`, `em*`, `p*`
- **Loopback**: `lo*`
- **Tunnel**: `tun*`, `tap*`
- **Bridge**: `br*`
- **Virtual**: `docker*`, `veth*`

## Error Handling

All utility classes provide comprehensive error handling:

### Error Reporting Pattern

```cpp
// Check for errors
if (manager->hasError()) {
    QString error = manager->getLastError();
    // Handle error
}

// Or use signals
connect(manager, &NetworkInterfaceManager::errorOccurred,
        this, &MyClass::handleError);
```

### Common Error Scenarios

1. **Permission Denied**: User lacks privileges for packet capture
2. **Interface Not Found**: Specified interface doesn't exist
3. **Interface Down**: Interface exists but is not active
4. **Capture Failed**: Cannot open interface for packet capture
5. **System Error**: Low-level system or library errors

## Threading Considerations

- **NetworkInterfaceManager**: Thread-safe with Qt signals for cross-thread communication
- **PrivilegeChecker**: Static methods are thread-safe
- **DataValidator**: Static methods are thread-safe
- **Auto-refresh**: Uses QTimer for safe periodic updates

## Platform Support

### Linux
- Full support for all features
- Uses standard Linux interface naming
- Supports capabilities and group-based permissions

### Future Platforms
- **macOS**: Planned support with platform-specific adaptations
- **Windows**: Planned support with WinPcap/Npcap integration

## Dependencies

- **Qt6 Core**: Basic Qt functionality
- **Qt6 Network**: QNetworkInterface integration
- **libpcap**: Network interface enumeration and packet capture
- **POSIX**: User/group information and privilege checking

## Testing

Comprehensive test suites for all utility classes:

- **test_interface_manager.cpp**: NetworkInterfaceManager functionality
- **test_privilege_checker.cpp**: Privilege detection and interface access
- **test_models.cpp**: DataValidator integration testing

### Running Tests

```bash
cd build
make test_interface_manager test_privilege_checker
./test_interface_manager
./test_privilege_checker
```

## Performance

- **Interface Enumeration**: Cached with configurable refresh intervals
- **Privilege Checking**: Cached results to avoid repeated system calls
- **Memory Management**: Proper cleanup of libpcap resources
- **Signal Efficiency**: Only emits signals when actual changes occur