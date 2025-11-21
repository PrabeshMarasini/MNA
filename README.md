# Multi-Network Analyzer (MNA)

MNA is a comprehensive network analysis and packet capture tool that combines real-time packet inspection with advanced network diagnostic utilities. Built with a robust C backend and modern Qt6 GUI, it provides Wireshark-like packet analysis capabilities alongside integrated network tools including speed testing, port scanning, DNS lookup, traceroute, and network device discovery.

## ⚠️ Important Warning

**This tool includes ARP spoofing capabilities for network analysis purposes. Use only in controlled environments where you have explicit permission. This project is intended for educational and research purposes only. Users are responsible for complying with all applicable laws and regulations.**

## Installation (Linux Systems)

### Prerequisites

#### Required Libraries
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install qt6-base-dev libpcap-dev cmake build-essential libcurl4-openssl-dev pkg-config

# CentOS/RHEL/Fedora
sudo dnf install qt6-qtbase-devel libpcap-devel cmake gcc-c++ libcurl-devel pkgconfig

# Arch Linux
sudo pacman -S qt6-base libpcap cmake gcc curl pkgconf
```

#### System Requirements
- Qt 6.x (Core, Widgets, Network modules)
- libpcap development libraries
- CMake 3.16 or higher
- C++17 compatible compiler
- libcurl development libraries
- Root/administrator privileges for packet capture

### Compilation

```bash
# Clone the repository
git clone <repository-url>
cd MNA

# Create build directory
mkdir build
cd build

# Configure and build
cmake ..
make -j$(nproc)

# Optional: Build individual tools
make speedtest_tool latency_tool portscan_tool dns_tool mac_tool traceroute_tool
```

### Running the Application

```bash
# Run with root privileges (required for packet capture)
sudo ./PacketCaptureGUI

# Or set capabilities (alternative to root)
sudo setcap cap_net_raw,cap_net_admin=eip ./PacketCaptureGUI
./PacketCaptureGUI

# Run individual command-line tools
./speedtest_tool
./portscan_tool <hostname>
./dns_tool <hostname>
./traceroute_tool <hostname>
```

## Core Features

### 1. Network Interface Selection
- **Intelligent Interface Detection**: Automatically discovers and validates available network interfaces
- **Privilege Management**: Built-in privilege checking with detailed instructions for proper setup
- **Real-time Interface Monitoring**: Monitors interface status changes and provides recommendations
- **Multi-interface Support**: Supports Ethernet, WiFi, loopback, and virtual interfaces

### 2. Real-time Packet Capture & Analysis
- **Live Packet Capture**: Real-time packet capture using libpcap with configurable filters
- **Protocol Analysis**: Comprehensive protocol dissection supporting 15+ protocols:
  - **Network Layer**: IPv4, IPv6, ARP, ICMP
  - **Transport Layer**: TCP, UDP
  - **Application Layer**: HTTP, HTTPS, SSH, FTP, SMTP, DNS, DHCP, QUIC, SNMP, IMAP
- **Three-Panel Interface**: 
  - Packet list with sortable columns and filtering
  - Hexadecimal dump viewer with byte highlighting
  - Hierarchical protocol tree with field details
- **Advanced Filtering**: Packet filtering with BPF (Berkeley Packet Filter) syntax
- **Memory Management**: Configurable packet retention policies and compression

### 3. Six Integrated Network Utilities

#### 3.1 Internet Speed Test
- **Download/Upload Testing**: Measures internet connection speed using multiple test servers
- **Multi-server Support**: Tests against Cachefly, Tele2, and ThinkBroadband servers
- **Real-time Progress**: Live speed monitoring with graphical progress indicators

#### 3.2 Network Latency Testing
- **Multi-protocol Latency**: Tests DNS, UDP, and HTTPS latency
- **Statistical Analysis**: Provides min, max, average, and standard deviation metrics
- **Target Flexibility**: Supports custom hostnames and IP addresses

#### 3.3 Port Scanner
- **Comprehensive Port Scanning**: TCP port scanning with service identification
- **Scan Modes**: Common ports, custom ranges, and full port scans
- **Service Detection**: Automatic service name resolution for discovered open ports
- **Results Export**: Tabular results with port status and service information

#### 3.4 DNS Lookup Tool
- **Multi-record Support**: A, AAAA, MX, NS, TXT, and other DNS record types
- **Reverse DNS**: IP-to-hostname resolution capabilities
- **Performance Metrics**: Query time measurement and DNS server identification
- **Detailed Results**: Comprehensive DNS information with TTL values

#### 3.5 MAC Address Lookup
- **Vendor Identification**: Hardware vendor lookup using MAC address databases
- **API Integration**: Uses multiple online databases for accurate vendor information
- **Batch Processing**: Support for multiple MAC address lookups

#### 3.6 Network Traceroute
- **Path Discovery**: Traces network path to destination with hop-by-hop analysis
- **Hostname Resolution**: Automatic hostname resolution for each hop
- **Performance Analysis**: Response time measurement for each network hop
- **Visual Representation**: Tabular display of complete network path

### 4. Export Capabilities
- **Multiple Formats**: Export captured packets in JSON and PCAP formats
- **PCAP Compatibility**: Full Wireshark compatibility for exported packet captures
- **Selective Export**: Export filtered packet subsets or complete capture sessions
- **Metadata Preservation**: Maintains timestamps, protocol information, and analysis results

### 5. LAN Device Discovery
- **Network Scanning**: Comprehensive LAN device discovery using ARP and ping techniques
- **Device Information**: MAC addresses, IP addresses, and hostname resolution
- **Gateway Detection**: Automatic network gateway identification
- **Real-time Updates**: Live device status monitoring and change detection

### 6. ARP Spoofing & Man-in-the-Middle Analysis
- **Target Selection**: Multi-target ARP spoofing with device selection interface
- **Packet Interception**: Capture and analyze traffic from spoofed devices
- **Traffic Analysis**: Real-time analysis of intercepted network communications
- **Session Management**: Start/stop spoofing sessions with proper cleanup
- **Safety Features**: Built-in safeguards and controlled environment warnings

## Advanced Features

### Performance Optimization
- **Multi-threading**: Separate threads for capture, analysis, and UI operations
- **Memory Management**: Intelligent memory usage with configurable limits and cleanup
- **Packet Sampling**: Configurable packet sampling to handle high-traffic networks
- **Ring Buffer**: Circular buffer support for continuous long-term capture

### User Interface
- **Modern Qt6 Design**: Professional interface with resizable panels and customizable layouts
- **Real-time Updates**: Live statistics and status monitoring
- **Settings Persistence**: User preferences and window layouts saved between sessions
- **Error Recovery**: Comprehensive error handling with recovery mechanisms

### Security & Privileges
- **Privilege Detection**: Automatic detection of required packet capture privileges
- **Capability Support**: Linux capabilities support as alternative to root access
- **Interface Validation**: Real-time testing of packet capture capability
- **Secure Operation**: Proper cleanup and resource management

## Limitations

### Known Issues
- **Packet Loss**: May experience packet loss during high-rate packet capture (>10,000 pps) on standard hardware
- **Segmentation Faults**: Potential crashes when processing malformed or corrupted network packets
- **High Traffic Handling**: Performance degradation and potential failures when capturing from high-bandwidth interfaces (>1Gbps sustained)
- **Memory Constraints**: Large packet captures may consume significant system memory without proper retention policies
- **Platform Limitations**: Currently optimized for Linux systems; Windows and macOS support is experimental

### Performance Considerations
- Recommended maximum sustained capture rate: 5,000-8,000 packets per second
- Memory usage scales with packet retention settings and capture duration
- ARP spoofing effectiveness depends on network topology and switch configuration
- GUI responsiveness may decrease during intensive packet analysis operations

## License

MIT License

Copyright (c) 2024 Multi-Network Analyzer (MNA)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

**Disclaimer**: This software is provided for educational and research purposes only. Users must ensure compliance with all applicable laws and regulations regarding network monitoring and analysis in their jurisdiction.