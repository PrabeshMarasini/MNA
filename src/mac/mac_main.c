#include "mac.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("MAC Address Vendor Lookup Tool\n");
        printf("Usage: %s <MAC_ADDRESS>\n", argv[0]);
        printf("Example: %s 00:1A:2B:3C:4D:5E\n", argv[0]);
        printf("Format: XX:XX:XX:XX:XX:XX\n");
        return 1;
    }
    
    const char* mac_address = argv[1];
    
    printf("MAC Address Vendor Lookup\n");
    printf("========================\n\n");
    
    return run_mac_lookup(mac_address);
}