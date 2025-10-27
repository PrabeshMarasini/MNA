cmake_minimum_required(VERSION 3.16)
project(PacketCaptureGUI VERSION 1.0.0 LANGUAGES CXX C)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Qt setup
qt6_standard_project_setup()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/packetcapture)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/protocols)
include_directories(${PCAP_INCLUDE_DIRS})

# Collect all protocol analyzer sources
file(GLOB PROTOCOL_SOURCES
    "src/protocols/tcp/*.c"
    "src/protocols/udp/*.c"
    "src/protocols/http/*.c"
    "src/protocols/ftp/*.c"
    "src/protocols/smtp/*.c"
    "src/protocols/ssh/*.c"
    "src/protocols/imap/*.c"
    "src/protocols/snmp/*.c"
    "src/protocols/ipv4/*.c"
    "src/protocols/ipv6/*.c"
    "src/protocols/arp/*.c"
    "src/protocols/dhcp/*.c"
    "src/protocols/https/*.c"
    "src/protocols/quic/*.c"
)

# Packet capture core sources (excluding main.c)
set(PACKETCAPTURE_SOURCES
    src/packetcapture/protocol.c
    src/packetcapture/arp.c
    src/packetcapture/device_scanner.c
)

# Create static library for packet capture backend
add_library(packetcapture_backend STATIC
    ${PACKETCAPTURE_SOURCES}
    ${PROTOCOL_SOURCES}
)

target_link_libraries(packetcapture_backend PRIVATE
    ${PCAP_LIBRARIES}
)

target_compile_options(packetcapture_backend PRIVATE
    ${PCAP_CFLAGS_OTHER}
    -Wall -Wextra
)

# Qt GUI application sources
set(GUI_SOURCES
    UI/main.cpp
    UI/MainWindow.cpp
    UI/NetworkInterfaceDialog.cpp
    UI/PacketTableView.cpp
    UI/HexView.cpp
    UI/ProtocolTreeView.cpp
    UI/PacketCaptureController.cpp
    UI/PacketDisplayController.cpp
    UI/PacketFilterWidget.cpp
    UI/DeviceSelectionDialog.cpp
    UI/DeviceDiscoveryController.cpp
    UI/ARPSpoofingController.cpp
    UI/Models/PacketModel.cpp
    UI/Models/ProtocolTreeModel.cpp
    UI/Models/PacketFilterProxyModel.cpp
    UI/Wrappers/ProtocolAnalysisWrapper.cpp
    UI/Utils/DataValidator.cpp
    UI/Utils/NetworkInterfaceManager.cpp
    UI/Utils/PrivilegeChecker.cpp
    UI/Utils/SettingsManager.cpp
    UI/Utils/ApplicationManager.cpp
    UI/Utils/ErrorHandler.cpp
    UI/Utils/MemoryManager.cpp
    UI/Utils/ErrorRecoveryDialog.cpp
    UI/Utils/LoggingDialog.cpp
    UI/Utils/PacketInfoGenerator.cpp
    UI/Dialogs/AboutDialog.cpp
    UI/Dialogs/SettingsDialog.cpp
    UI/CaptureControlWidget.cpp
)

# Qt GUI application headers (for MOC)
set(GUI_HEADERS
    UI/MainWindow.h
    UI/NetworkInterfaceDialog.h
    UI/PacketTableView.h
    UI/HexView.h
    UI/ProtocolTreeView.h
    UI/PacketCaptureController.h
    UI/PacketDisplayController.h
    UI/PacketFilterWidget.h
    UI/DeviceSelectionDialog.h
    UI/DeviceDiscoveryController.h
    UI/ARPSpoofingController.h
    UI/Models/PacketModel.h
    UI/Models/ProtocolTreeModel.h
    UI/Models/PacketFilterProxyModel.h
    UI/Utils/SettingsManager.h
    UI/Utils/ApplicationManager.h
    UI/Utils/ErrorHandler.h
    UI/Utils/MemoryManager.h
    UI/Utils/ErrorRecoveryDialog.h
    UI/Utils/LoggingDialog.h
    UI/Dialogs/AboutDialog.h
    UI/Dialogs/SettingsDialog.h
    UI/CaptureControlWidget.h
)

# Create Qt GUI executable
qt6_add_executable(PacketCaptureGUI ${GUI_SOURCES})

# Set target properties
set_target_properties(PacketCaptureGUI PROPERTIES
    WIN32_EXECUTABLE TRUE
    MACOSX_BUNDLE TRUE
)

# Link libraries
target_link_libraries(PacketCaptureGUI PRIVATE
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
    packetcapture_backend
    ${PCAP_LIBRARIES}
    pthread
)

# Compiler options
target_compile_options(PacketCaptureGUI PRIVATE
    ${PCAP_CFLAGS_OTHER}
)

# Install target
install(TARGETS PacketCaptureGUI
    BUNDLE DESTINATION .
    RUNTIME DESTINATION bin
)

# Original command-line tool (optional)
add_executable(arp_tool
    src/packetcapture/main.c
)

target_link_libraries(arp_tool PRIVATE
    packetcapture_backend
)

# Testing (keeping only the C protocol tests)
enable_testing()

# Test executable for C protocols (commented out - missing file)
# add_executable(test_protocols
#     src/packetcapture/test_protocols.c
# )
# 
# target_link_libraries(test_protocols PRIVATE
#     packetcapture_backend
# )
# 
# add_test(NAME protocol_tests COMMAND test_protocols)