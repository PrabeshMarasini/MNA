#include "portscan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>

#define CONNECT_TIMEOUT_SECONDS 3
#define LOCALHOST_TIMEOUT_MILLISECONDS 100
#define MAX_COMMON_PORTS 21

// Common ports to scan
static const struct {
    int port;
    const char* service;
} common_ports[MAX_COMMON_PORTS] = {
    {21, "FTP"},
    {22, "SSH"},
    {23, "Telnet"},
    {25, "SMTP"},
    {53, "DNS"},
    {80, "HTTP"},
    {110, "POP3"},
    {143, "IMAP"},
    {443, "HTTPS"},
    {993, "IMAPS"},
    {995, "POP3S"},
    {1433, "MSSQL"},
    {3306, "MySQL"},
    {3389, "RDP"},
    {5432, "PostgreSQL"},
    {5900, "VNC"},
    {8000, "HTTP-Alt2"},  // Added for Flask development servers
    {8080, "HTTP-Alt"},
    {8443, "HTTPS-Alt"},
    {27017, "MongoDB"},
    {27018, "MongoDB"}
};

// Resolve hostname to IP address
static int resolve_hostname(const char *hostname, struct in_addr *addr) {
    struct hostent *he = gethostbyname(hostname);
    if (he == NULL) {
        return -1;
    }
    memcpy(addr, he->h_addr_list[0], sizeof(struct in_addr));
    return 0;
}

// Scan a single port
int scan_port(const char* hostname, int port) {
    int sock = -1;
    struct sockaddr_in server_addr;
    int result = -1; // -1 = error, 0 = closed, 1 = open
    
    if (resolve_hostname(hostname, &server_addr.sin_addr) < 0) {
        return -1;
    }
    
    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }
    
    // Set up server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    struct timeval timeout;
    // Use shorter timeout for localhost
    if (strcmp(hostname, "127.0.0.1") == 0 || strcmp(hostname, "localhost") == 0) {
        timeout.tv_sec = 0;
        timeout.tv_usec = LOCALHOST_TIMEOUT_MILLISECONDS * 1000; // Convert to microseconds
    } else {
        timeout.tv_sec = CONNECT_TIMEOUT_SECONDS;
        timeout.tv_usec = 0;
    }
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    // Attempt to connect
    int connect_result = connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    
    if (connect_result == 0) {
        result = 1; // Port is open
    } else {
        if (errno == ECONNREFUSED || errno == ECONNRESET) {
            result = 0; // Port is closed
        } else {
            result = -1; // Port is filtered or error occurred
        }
    }
    
    close(sock);
    return result;
}

// Scan a range of ports
int scan_port_range(const char* hostname, int start_port, int end_port, PortScanResult* results, int max_results) {
    int found_ports = 0;
    int total_ports = end_port - start_port + 1;
    int scanned = 0;
    
    printf("Scanning %d ports on %s (%d-%d)...\n", total_ports, hostname, start_port, end_port);
    
    for (int port = start_port; port <= end_port && found_ports < max_results; port++) {
        scanned++;
        if (scanned % 10 == 0) {
            printf("Scanned %d ports...\n", scanned);
        }
        
        int status = scan_port(hostname, port);
        if (status == 1) { // Port is open
            results[found_ports].port = port;
            results[found_ports].service = "Unknown";
            results[found_ports].status = "open";
            found_ports++;
        } else if (status == 0) { // Port is closed
            // Don't add to results
        } else { // Port is filtered or error
            // Don't add to results
        }
    }
    
    return found_ports;
}

int scan_common_ports(const char* hostname, PortScanResult* results, int max_results) {
    int found_ports = 0;
    
    printf("Scanning common ports on %s...\n", hostname);
    
    for (int i = 0; i < MAX_COMMON_PORTS && found_ports < max_results; i++) {
        int port = common_ports[i].port;
        const char* service = common_ports[i].service;
        
        if (i % 5 == 0) {
            printf("Scanned %d common ports...\n", i);
        }
        
        int status = scan_port(hostname, port);
        if (status == 1) { // Port is open
            results[found_ports].port = port;
            results[found_ports].service = service;
            results[found_ports].status = "open";
            found_ports++;
        }
    }
    
    return found_ports;
}

// Get service name for a port
const char* get_service_name(int port) {
    for (int i = 0; i < MAX_COMMON_PORTS; i++) {
        if (common_ports[i].port == port) {
            return common_ports[i].service;
        }
    }
    return "Unknown";
}

// Main function to run port scan
int run_port_scan(const char* hostname) {
    PortScanResult results[50]; // Maximum 50 open ports
    int open_ports = 0;
    
    printf("=== Port Scan Results ===\n");
    printf("Target: %s\n\n", hostname);
    
    open_ports = scan_common_ports(hostname, results, 50);
    if (open_ports > 0) {
        printf("\nOpen Ports:\n");
        printf("PORT\tSERVICE\t\tSTATUS\n");
        printf("----\t-------\t\t------\n");
        
        for (int i = 0; i < open_ports; i++) {
            printf("%d\t%-12s\t%s\n", 
                   results[i].port, 
                   results[i].service, 
                   results[i].status);
        }
    } else {
        printf("No open ports found among common ports.\n");
    }
    
    printf("\nScan completed. Found %d open ports.\n", open_ports);
    
    return open_ports > 0 ? 0 : 1;
}

// Extended function to run comprehensive port scan for localhost
int run_port_scan_extended(const char* hostname) {
    PortScanResult results[500]; // Maximum 500 open ports
    int total_open = 0;
    
    printf("=== Full Port Scan Results ===\n");
    printf("Target: %s\n", hostname);
    printf("Scanning ALL 65535 ports (this may take a while)...\n\n");
    
    // Scan all ports in chunks for better progress reporting
    int chunk_size = 1000;
    int total_ports = 65535;
    
    for (int start = 1; start <= total_ports && total_open < 500; start += chunk_size) {
        int end = (start + chunk_size - 1 > total_ports) ? total_ports : start + chunk_size - 1;
        
        printf("Scanning ports %d-%d... ", start, end);
        fflush(stdout);
        
        int chunk_found = 0;
        for (int port = start; port <= end && total_open < 500; port++) {
            int status = scan_port(hostname, port);
            if (status == 1) { // Port is open
                results[total_open].port = port;
                results[total_open].service = get_service_name(port);
                results[total_open].status = "open";
                total_open++;
                chunk_found++;
                
                // Print immediately when found
                printf("\n  -> FOUND OPEN PORT: %d (%s)", port, get_service_name(port));
                fflush(stdout);
            }
        }
        
        if (chunk_found == 0) {
            printf("no open ports");
        }
        printf("\n");
        
        // Show progress
        float progress = ((float)(end) / total_ports) * 100;
        printf("Progress: %.1f%% (%d/%d ports) - Total open ports found: %d\n\n", 
               progress, end, total_ports, total_open);
    }
    
    // Display all results
    if (total_open > 0) {
        printf("\n=== ALL OPEN PORTS SUMMARY ===\n");
        printf("PORT\tSERVICE\t\tSTATUS\n");
        printf("----\t-------\t\t------\n");
        
        for (int i = 0; i < total_open; i++) {
            printf("%d\t%-12s\t%s\n", 
                   results[i].port, 
                   results[i].service, 
                   results[i].status);
        }
    } else {
        printf("No open ports found across all 65535 ports.\n");
    }
    
    printf("\nFull port scan completed. Found %d open ports total.\n", total_open);
    
    return total_open > 0 ? 0 : 1;
}