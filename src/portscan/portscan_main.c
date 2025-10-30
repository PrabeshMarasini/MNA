#include "portscan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Port Scanner\n");
        printf("Usage: %s <hostname> [options]\n", argv[0]);
        printf("Options:\n");
        printf("  --common-only    Scan only common ports\n");
        printf("  --range <start> <end>  Scan port range\n");
        printf("  --full          Full scan (all 65535 ports)\n");
        printf("Example: %s google.com --common-only\n", argv[0]);
        printf("Example: %s localhost --range 80 443\n", argv[0]);
        return 1;
    }
    
    const char* hostname = argv[1];
    
    // Handle "self" parameter for backward compatibility
    if (strcmp(hostname, "self") == 0) {
        hostname = "127.0.0.1";
    }
    
    // Parse command line options
    if (argc > 2 && strcmp(argv[2], "--common-only") == 0) {
        // Common ports scan only
        PortScanResult results[50];
        int found = scan_common_ports(hostname, results, 50);
        
        for (int i = 0; i < found; i++) {
            printf("OPEN_PORT:%d:%s:%s\n", 
                   results[i].port, 
                   results[i].service, 
                   results[i].status);
        }
        printf("SCAN_COMPLETE:%d\n", found);
        return 0;
        
    } else if (argc > 4 && strcmp(argv[2], "--range") == 0) {
        // Port range scan
        int start_port = atoi(argv[3]);
        int end_port = atoi(argv[4]);
        
        if (start_port < 1 || end_port > 65535 || start_port > end_port) {
            printf("ERROR:Invalid port range\n");
            return 1;
        }
        
        PortScanResult results[1000];
        int found = scan_port_range(hostname, start_port, end_port, results, 1000);
        
        for (int i = 0; i < found; i++) {
            printf("OPEN_PORT:%d:%s:%s\n", 
                   results[i].port, 
                   get_service_name(results[i].port), 
                   results[i].status);
        }
        printf("SCAN_COMPLETE:%d\n", found);
        return 0;
        
    } else if (argc > 2 && strcmp(argv[2], "--full") == 0) {
        // Full port scan
        printf("PROGRESS:0\n");
        fflush(stdout);
        
        int total_found = 0;
        int chunk_size = 1000;
        
        for (int start = 1; start <= 65535 && total_found < 500; start += chunk_size) {
            int end = (start + chunk_size - 1 > 65535) ? 65535 : start + chunk_size - 1;
            
            for (int port = start; port <= end && total_found < 500; port++) {
                int status = scan_port(hostname, port);
                if (status == 1) {
                    printf("OPEN_PORT:%d:%s:open\n", port, get_service_name(port));
                    fflush(stdout);
                    total_found++;
                }
            }
            
            // Report progress
            float progress = ((float)end / 65535.0) * 100.0;
            printf("PROGRESS:%.1f\n", progress);
            fflush(stdout);
        }
        
        printf("SCAN_COMPLETE:%d\n", total_found);
        return 0;
        
    } else {
        // Default: common ports scan (for backward compatibility)
        printf("Network Port Scanner\n");
        printf("====================\n\n");
        return run_port_scan(hostname);
    }
}