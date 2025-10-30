#include "latency.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc > 1 && strcmp(argv[1], "--dns-only") == 0) {
        // DNS test only
        double dns_latency = test_dns_latency("google.com");
        printf("DNS_RESULT:%.2f\n", dns_latency);
        return 0;
    } else if (argc > 1 && strcmp(argv[1], "--udp-only") == 0) {
        // UDP test only
        double udp_latency = test_udp_latency("8.8.8.8", 53);
        printf("UDP_RESULT:%.2f\n", udp_latency);
        return 0;
    } else if (argc > 1 && strcmp(argv[1], "--https-only") == 0) {
        // HTTPS test only
        double https_latency = test_https_latency("google.com", 443);
        printf("HTTPS_RESULT:%.2f\n", https_latency);
        return 0;
    } else {
        // Full test
        printf("Network Latency Testing Tool\n");
        printf("============================\n\n");
        return run_latency_tests();
    }
}