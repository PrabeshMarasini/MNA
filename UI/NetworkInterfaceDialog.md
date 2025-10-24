# Network Interface Selection Dialog

The NetworkInterfaceDialog provides a comprehensive interface for users to select a network interface for packet capture operations.

## Features

### Visual Interface Selection
- **Table View**: Displays interfaces in a sortable, filterable table
- **Color Coding**: Visual indicators for interface suitability
  - 🟢 Green: Ideal for packet capture (up, can capture, non-loopback)
  - 🟡 Yellow: Usable but with limitations (can capture but down/loopback)
  - 🔴 Red: Not suitable for packet capture
- **Icons**: Interface type indicators (📶 WiFi, 🔌 Ethernet, 🔄 Loopback, etc.)

### Interface Information
- **Basic Details**: Name, description, type, status
- **Network Information**: IP addresses, interface state
- **Capture Capability**: Real-time testing of packet capture ability
- **Recommendations**: Smart suggestions based on interface characteristics

### Smart Features
- **Auto-Selection**: Automatically selects the best available interface
- **Real-time Updates**: Monitors interface changes every 5 seconds
- **Privilege Checking**: Displays current privilege status and instructions
- **Interface Testing**: Test packet capture capability before selection

### Filtering and Search
- **Show All Toggle**: Option to display loopback and virtual interfaces
- **Sortable Columns**: Click column headers to sort by any attribute
- **Visual Filtering**: Color-coded rows for quick identification

## User Interface Layout

### Main Window (800x600)
```
┌─────────────────────────────────────────────────────────────┐
│ Select Network Interface                                    │
├─────────────────────────────────────────────────────────────┤
│ Select a network interface for packet capture:             │
│ ✅ Packet capture privileges: OK                           │
├─────────────────────────────────────────────────────────────┤
│ ┌─Interface List─────────┐ ┌─Details & Help──────────────┐ │
│ │ □ Show all  [Refresh]  │ │ Interface Details           │ │
│ │ ┌─────────────────────┐ │ │ ┌─────────────────────────┐ │ │
│ │ │Interface│Desc│Type │ │ │ │ Selected: eth0          │ │ │
│ │ │📶 wlan0 │WiFi│Up   │ │ │ │ Status: Up              │ │ │
│ │ │🔌 eth0  │Eth │Up   │ │ │ │ Can Capture: Yes        │ │ │
│ │ │🔄 lo    │Loop│Up   │ │ │ │ Recommendation: Good    │ │ │
│ │ └─────────────────────┘ │ │ └─────────────────────────┘ │ │
│ └───────────────────────── │ │ Help & Instructions         │ │
│                            │ │ ┌─────────────────────────┐ │ │
│                            │ │ │ • Green = Ideal         │ │ │
│                            │ │ │ • Yellow = Limited      │ │ │
│                            │ │ │ • Red = Not suitable    │ │ │
│                            │ │ │ • Double-click to select│ │ │
│                            │ │ └─────────────────────────┘ │ │
│                            └─────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│ [Test Interface]                    [Select] [Cancel]      │
└─────────────────────────────────────────────────────────────┘
```

## Interface Selection Logic

### Priority Algorithm
1. **Ideal Interfaces**: Non-loopback, up, can capture
2. **Good Interfaces**: Non-loopback, can capture (may be down)
3. **Limited Interfaces**: Any interface that can capture
4. **Fallback**: First available interface

### Color Coding System
- **Light Green Background**: Best choice (up, can capture, non-loopback)
- **Light Yellow Background**: Good choice (can capture, may be down)
- **Light Gray Background**: Loopback interface
- **Light Red Background**: Cannot capture packets

## Privilege Management

### Privilege Detection
- **Root Access**: Automatically detected
- **Capabilities**: Checks for CAP_NET_RAW and CAP_NET_ADMIN
- **Real Testing**: Actually attempts to open interfaces

### Privilege Instructions
Provides platform-specific instructions for gaining packet capture privileges:

1. **Run as Root**: `sudo ./PacketCaptureGUI`
2. **Set Capabilities**: `sudo setcap cap_net_raw,cap_net_admin=eip ./PacketCaptureGUI`
3. **Group Membership**: `sudo usermod -a -G pcap username`

## Interface Testing

### Test Functionality
- **Real Capture Test**: Actually attempts to open the interface with libpcap
- **Permission Verification**: Tests current user's access to the interface
- **Error Reporting**: Provides detailed error messages for failures

### Test Results
- **Success**: "Interface eth0 is accessible"
- **Permission Error**: "Cannot access interface eth0: Permission denied"
- **Interface Error**: "Cannot access interface eth0: No such device"

## Error Handling

### Graceful Degradation
- **No Interfaces**: Shows empty list with helpful message
- **Permission Denied**: Shows privilege instructions
- **Interface Errors**: Displays specific error messages
- **Network Changes**: Automatically refreshes interface list

### User Feedback
- **Progress Indicators**: Shows progress during refresh and testing
- **Status Messages**: Real-time privilege and interface status
- **Error Display**: Clear error messages in interface details

## Integration Points

### NetworkInterfaceManager Integration
```cpp
// Get detailed interface information
QList<InterfaceInfo> interfaces = interfaceManager->getDetailedInterfaceList();

// Auto-select best interface
QString bestInterface = interfaceManager->getBestCaptureInterface();

// Monitor interface changes
connect(interfaceManager, &NetworkInterfaceManager::interfaceListChanged,
        this, &NetworkInterfaceDialog::refreshInterfaceList);
```

### PrivilegeChecker Integration
```cpp
// Check current privileges
bool hasPrivileges = PrivilegeChecker::hasPacketCapturePrivileges();

// Test specific interface
QString testResult = PrivilegeChecker::testInterfaceAccess(interface);

// Get privilege instructions
QString instructions = PrivilegeChecker::getPrivilegeInstructions();
```

## Usage Examples

### Basic Usage
```cpp
NetworkInterfaceDialog dialog;
if (dialog.exec() == QDialog::Accepted) {
    QString selectedInterface = dialog.getSelectedInterface();
    // Use selectedInterface for packet capture
}
```

### With Parent Window
```cpp
NetworkInterfaceDialog dialog(parentWindow);
dialog.setWindowTitle("Custom Title");
if (dialog.exec() == QDialog::Accepted) {
    QString interface = dialog.getSelectedInterface();
    startPacketCapture(interface);
}
```

## Keyboard Shortcuts

- **Enter/Return**: Select current interface (if valid)
- **Escape**: Cancel dialog
- **F5**: Refresh interface list
- **Space**: Toggle "Show all interfaces" checkbox
- **Up/Down Arrows**: Navigate interface list

## Accessibility Features

- **Keyboard Navigation**: Full keyboard support for all controls
- **Screen Reader Support**: Proper labels and descriptions
- **High Contrast**: Color coding works with high contrast themes
- **Tooltips**: Helpful tooltips on all interactive elements

## Performance Considerations

- **Lazy Loading**: Interface details loaded on selection
- **Caching**: Interface information cached for 5 seconds
- **Background Updates**: Non-blocking interface monitoring
- **Efficient Filtering**: Fast table filtering and sorting

## Platform Compatibility

### Linux
- Full support for all interface types
- Proper privilege detection and instructions
- Real-time interface monitoring

### Future Platforms
- **macOS**: Planned support with platform-specific adaptations
- **Windows**: Planned support with WinPcap/Npcap integration

## Testing

### Automated Tests
- **Dialog Creation**: Verifies UI component creation
- **Interface Selection**: Tests selection logic and auto-selection
- **User Interaction**: Simulates button clicks and table interaction
- **Privilege Checking**: Validates privilege detection
- **Error Handling**: Tests error scenarios

### Manual Testing
- **Demo Application**: `demo_interface_dialog` for interactive testing
- **Visual Verification**: Check color coding and layout
- **Privilege Testing**: Test with different privilege levels
- **Interface Changes**: Test with network interface changes

### Running Tests
```bash
cd build
make test_interface_dialog demo_interface_dialog
./test_interface_dialog          # Automated tests
./demo_interface_dialog          # Interactive demo
```

## Customization Options

### Styling
- **Color Themes**: Customizable color coding
- **Icons**: Replaceable interface type icons
- **Fonts**: Configurable font sizes and families

### Behavior
- **Auto-refresh Interval**: Configurable refresh timing
- **Default Filters**: Customizable default filter settings
- **Selection Criteria**: Adjustable interface selection priority

### Localization
- **Multi-language Support**: All text strings are translatable
- **Cultural Adaptations**: Interface conventions for different regions
- **Help Text**: Localizable help and instruction text