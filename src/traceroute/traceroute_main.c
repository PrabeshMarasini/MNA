#include "traceroute.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <hostname>\n", argv[0]);
        printf("Example: %s google.com\n", argv[0]);
        return 1;
    }
    
    const char* target_host = argv[1];
    
    return run_traceroute(target_host);
}