#include "portscan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Port Scanner\n");
        printf("Usage: %s <hostname>\n", argv[0]);
        printf("Usage: %s self (to scan your own PC)\n", argv[0]);
        printf("Example: %s google.com\n", argv[0]);
        printf("Example: %s self\n", argv[0]);
        return 1;
    }
    
    const char* hostname = argv[1];
    char local_hostname[256] = "127.0.0.1"; // Default to localhost
    
    // Handle "self" parameter
    if (strcmp(hostname, "self") == 0) {
        printf("Scanning your own PC (localhost)...\n");
        hostname = local_hostname;
        
        printf("Network Port Scanner\n");
        printf("====================\n\n");
        
        // For self scan, do both common ports and extended range
        run_port_scan_extended(hostname);
    } else {
        printf("Network Port Scanner\n");
        printf("====================\n\n");
        
        // Run normal port scan for external hosts
        run_port_scan(hostname);
    }
    
    return 0;
}