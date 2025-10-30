#ifndef PORTSCAN_H
#define PORTSCAN_H

// Structure to hold port scan results
typedef struct {
    int port;
    const char* service;
    const char* status;  // "open", "closed", or "filtered"
} PortScanResult;

// Function to scan a single port
int scan_port(const char* hostname, int port);

// Function to scan a range of ports
int scan_port_range(const char* hostname, int start_port, int end_port, PortScanResult* results, int max_results);

// Function to scan common ports
int scan_common_ports(const char* hostname, PortScanResult* results, int max_results);

// Main function to run port scan
int run_port_scan(const char* hostname);

// Extended function to run comprehensive port scan for localhost
int run_port_scan_extended(const char* hostname);

// Get service name for a port
const char* get_service_name(int port);

#endif