#include "dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <hostname|ip_address>\n", argv[0]);
        printf("Example: %s google.com\n", argv[0]);
        printf("         %s 8.8.8.8\n", argv[0]);
        return 1;
    }
    
    const char* target = argv[1];
    
    return run_dns_lookup(target);
}