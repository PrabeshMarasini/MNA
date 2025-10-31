#include "dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>

// Perform DNS lookup for a hostname
int perform_dns_lookup(const char* target, const char* record_type, DnsLookupResult* results) {
    struct addrinfo hints, *res, *p;
    struct timeval start_time, end_time;
    int status;

    memset(results, 0, sizeof(DnsLookupResult));
    strncpy(results->hostname, target, sizeof(results->hostname) - 1);
    strncpy(results->query_type, record_type, sizeof(results->query_type) - 1);
    
    // Set up hints for getaddrinfo
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // Allow both IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;
    
    gettimeofday(&start_time, NULL);
    status = getaddrinfo(target, NULL, &hints, &res);
    gettimeofday(&end_time, NULL);
    results->query_time_ms = (end_time.tv_sec - start_time.tv_sec) * 1000.0 + 
                            (end_time.tv_usec - start_time.tv_usec) / 1000.0;
    
    if (status != 0) {
        results->status = -1;
        strncpy(results->error_message, gai_strerror(status), sizeof(results->error_message) - 1);
        return -1;
    }

    int record_index = 0;
    for (p = res; p != NULL && record_index < MAX_DNS_RECORDS; p = p->ai_next) {
        DnsRecord *record = &results->records[record_index];
        
        if (p->ai_family == AF_INET) {
            // IPv4 address
            strncpy(record->type, "A", sizeof(record->type) - 1);
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            inet_ntop(AF_INET, &ipv4->sin_addr, record->data, sizeof(record->data));
            record_index++;
        } else if (p->ai_family == AF_INET6) {
            // IPv6 address
            strncpy(record->type, "AAAA", sizeof(record->type) - 1);
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            inet_ntop(AF_INET6, &ipv6->sin6_addr, record->data, sizeof(record->data));
            record_index++;
        }
    }
    
    results->record_count = record_index;
    
    // Get DNS server information
    strncpy(results->dns_server, "System Default", sizeof(results->dns_server) - 1);
    
    freeaddrinfo(res);
    results->status = 0;
    return 0;
}

// Reverse DNS lookup
int reverse_dns_lookup(const char* ip_address, char* hostname, size_t hostname_size) {
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    char hbuf[NI_MAXHOST];
    int result;
    
    // Try to parse as IPv4 first
    if (inet_pton(AF_INET, ip_address, &(sa.sin_addr)) == 1) {
        sa.sin_family = AF_INET;
        result = getnameinfo((struct sockaddr*)&sa, sizeof(sa), hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD);
        if (result == 0) {
            strncpy(hostname, hbuf, hostname_size - 1);
            hostname[hostname_size - 1] = '\0';
            return 0;
        }
    }
    // Try to parse as IPv6
    else if (inet_pton(AF_INET6, ip_address, &(sa6.sin6_addr)) == 1) {
        sa6.sin6_family = AF_INET6;
        result = getnameinfo((struct sockaddr*)&sa6, sizeof(sa6), hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD);
        if (result == 0) {
            strncpy(hostname, hbuf, hostname_size - 1);
            hostname[hostname_size - 1] = '\0';
            return 0;
        }
    }
    
    strncpy(hostname, "Unknown", hostname_size - 1);
    return -1;
}

void print_dns_results(const DnsLookupResult* results) {
    printf("\n=== DNS Lookup Results ===\n\n");
    
    if (results->status != 0) {
        printf("Error: %s\n", results->error_message);
        printf("=========================\n");
        return;
    }
    
    printf("Hostname: %s\n", results->hostname);
    printf("Query Type: %s\n", results->query_type);
    printf("\n");
    
    if (results->record_count > 0) {
        printf("Results:\n");
        for (int i = 0; i < results->record_count; i++) {
            const DnsRecord *record = &results->records[i];
            printf("- %s (%s)\n", record->data, record->type);
        }
    } else {
        printf("No records found\n");
    }
    
    printf("\nDNS Server Used: %s\n", results->dns_server);
    printf("Query Time: %.2f ms\n", results->query_time_ms);
    printf("Status: Success\n");
    
    // If we looked up an IP address, try reverse DNS
    if (strcmp(results->query_type, "PTR") == 0 || 
        (strchr(results->hostname, '.') && 
         strspn(results->hostname, "0123456789.") == strlen(results->hostname))) {
        char reverse_hostname[256];
        if (reverse_dns_lookup(results->hostname, reverse_hostname, sizeof(reverse_hostname)) == 0) {
            printf("\n=== Reverse DNS Lookup ===\n");
            printf("%s -> %s\n", results->hostname, reverse_hostname);
            printf("==========================\n");
        }
    }
    
    printf("\n=========================\n");
}

int run_dns_lookup(const char* target) {
    DnsLookupResult results;
    
    printf("=== DNS Lookup ===\n\n");
    // Check if target is an IP address
    struct in_addr addr4;
    struct in6_addr addr6;
    int is_ipv4 = (inet_pton(AF_INET, target, &addr4) == 1);
    int is_ipv6 = (inet_pton(AF_INET6, target, &addr6) == 1);
    
    if (is_ipv4 || is_ipv6) {
        char hostname[256];
        if (reverse_dns_lookup(target, hostname, sizeof(hostname)) == 0) {
            printf("Reverse DNS Lookup:\n");
            printf("%s -> %s\n\n", target, hostname);
        } else {
            printf("Reverse DNS Lookup:\n");
            printf("%s -> No PTR record found\n\n", target);
        }
        return 0;
    }
    
    // Perform forward DNS lookup
    if (perform_dns_lookup(target, "A", &results) < 0) {
        print_dns_results(&results);
        return 1;
    }
    
    print_dns_results(&results);
    return 0;
}