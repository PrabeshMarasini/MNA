#include "latency.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    printf("Network Latency Testing Tool\n");
    printf("============================\n\n");
    run_latency_tests();
    
    return 0;
}