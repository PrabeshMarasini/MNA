# Packet Capture GUI

A Qt-based graphical user interface for network packet capture and analysis, similar to Wireshark.

## Features

- **Network Interface Selection**: Choose from available network interfaces
- **Real-time Packet Capture**: Live packet capture using libpcap
- **Three-Panel Layout**: 
  - Packet list with sortable columns
  - Hexadecimal dump view
  - Protocol analysis tree
- **Protocol Analysis**: Supports multiple protocols including:
  - TCP, UDP, HTTP, HTTPS, SSH, FTP, SMTP, IMAP
  - DNS, DHCP, ARP, QUIC, SNMP
  - IPv4, IPv6, ICMP
- **Resizable Panels**: Drag separators to customize layout
- **Export Capabilities**: Save captured packets for analysis

## Requirements

- Qt 6.x
- libpcap development libraries
- CMake 3.16 or higher
- C++17 compatible compiler
- Root/administrator privileges for packet capture

## Building

### Linux/macOS

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install qt6-base-dev libpcap-dev cmake build-essential

# Install dependencies (macOS with Homebrew)
brew install qt6 libpcap cmake

# Build
mkdir build
cd build
cmake ..
make

# Run
sudo ./PacketCaptureGUI
```

### Dependencies

- **Qt6**: Core and Widgets modules
- **libpcap**: Packet capture library
- **CMake**: Build system
- **Existing C libraries**: Protocol analyzers in src/protocols/

## Usage

1. **Start Application**: Run with sudo/administrator privileges
2. **Select Interface**: Choose network interface from the dialog
3. **Start Capture**: Click the start button to begin capturing packets
4. **Analyze Packets**: 
   - Click on packets in the list to view details
   - Examine hex dump in bottom-left panel
   - View protocol analysis in bottom-right panel
5. **Stop Capture**: Click stop button when finished

## Architecture

The application follows MVC pattern:
- **Model**: PacketModel, ProtocolTreeModel for data management
- **View**: Qt widgets for UI components
- **Controller**: PacketCaptureController for capture operations

## Integration

The GUI integrates with existing C-based packet capture libraries:
- `src/packetcapture/protocol.c` - Core protocol identification
- `src/protocols/` - Individual protocol analyzers
- Uses existing pcap integration and analysis functions

## Security Notes

- Requires elevated privileges for packet capture
- Only captures packets from selected interface
- No data is transmitted or stored externally
- Raw packet data is handled securely in memory