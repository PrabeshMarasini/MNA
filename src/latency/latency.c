#include "latency.h"
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
#include <resolv.h>

#define BUFFER_SIZE 1024
#define TIMEOUT_SECONDS 10

static long long get_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// Resolve hostname to IP address
static int resolve_hostname(const char *hostname, struct in_addr *addr) {
    struct hostent *he = gethostbyname(hostname);
    if (he == NULL) {
        return -1;
    }
    memcpy(addr, he->h_addr_list[0], sizeof(struct in_addr));
    return 0;
}

// Test DNS latency by resolving a hostname
double test_dns_latency(const char *hostname) {
    printf("Testing DNS latency for %s...\n", hostname);
    
    long long start_time, end_time;
    struct hostent *he;
    start_time = get_time_ms();
    he = gethostbyname(hostname);
    end_time = get_time_ms();
    
    if (he == NULL) {
        printf("DNS resolution failed for %s\n", hostname);
        return -1.0;
    }
    
    double latency_ms = end_time - start_time;
    printf("DNS resolution time: %.2f ms\n", latency_ms);
    
    return latency_ms;
}

// Test UDP latency by sending a packet to a server
double test_udp_latency(const char *hostname, int port) {
    printf("Testing UDP latency to %s:%d...\n", hostname, port);
    
    int sock = -1;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    long long start_time, end_time;
    double latency_ms = -1.0;
    
    // Resolve hostname
    if (resolve_hostname(hostname, &server_addr.sin_addr) < 0) {
        printf("Failed to resolve hostname: %s\n", hostname);
        return -1.0;
    }
    
    // Create UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        printf("Failed to create UDP socket\n");
        return -1.0;
    }
    
    // Set up server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SECONDS;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    // Prepare a simple DNS query (A record for example.com)
    unsigned char dns_query[] = {
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        // Query name: example.com
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,       
        0x00, 0x01,  
        0x00, 0x01 
    };
    int query_len = sizeof(dns_query);
    
    start_time = get_time_ms();
    
    // Send DNS query
    if (sendto(sock, dns_query, query_len, 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("Failed to send UDP packet\n");
        close(sock);
        return -1.0;
    }
    
    // Receive response
    socklen_t addr_len = sizeof(server_addr);
    ssize_t received = recvfrom(sock, buffer, BUFFER_SIZE - 1, 0, (struct sockaddr*)&server_addr, &addr_len);
    
    // End timing
    end_time = get_time_ms();
    
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("UDP timeout - no response received\n");
        } else {
            printf("Failed to receive UDP response\n");
        }
        close(sock);
        return -1.0;
    }
    
    buffer[received] = '\0';
    latency_ms = end_time - start_time;
    printf("UDP round-trip time: %.2f ms\n", latency_ms);
    
    close(sock);
    return latency_ms;
}

// Test HTTPS latency
double test_https_latency(const char *hostname, int port) {
    printf("Testing HTTPS latency to %s:%d...\n", hostname, port);
    
    int sock = -1;
    struct sockaddr_in server_addr;
    long long start_time, end_time;
    double latency_ms = -1.0;
    
    // Resolve hostname
    if (resolve_hostname(hostname, &server_addr.sin_addr) < 0) {
        printf("Failed to resolve hostname: %s\n", hostname);
        return -1.0;
    }
    
    // Create TCP socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("Failed to create TCP socket\n");
        return -1.0;
    }
    
    // Set socket timeout
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SECONDS;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    // Set up server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    // Start timing
    start_time = get_time_ms();
    
    // Connect to server
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("Failed to connect to HTTPS server\n");
        close(sock);
        return -1.0;
    }
    
    // End timing
    end_time = get_time_ms();
    
    latency_ms = end_time - start_time;
    printf("HTTPS connection time: %.2f ms\n", latency_ms);
    
    // Send a simple HTTP request to test full handshake
    const char *request = "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n";
    char full_request[512];
    snprintf(full_request, sizeof(full_request), request, hostname);
    
    start_time = get_time_ms();
    
    if (send(sock, full_request, strlen(full_request), 0) < 0) {
        printf("Failed to send HTTPS request\n");
        close(sock);
        return latency_ms;
    }
    
    // Read response header only
    char buffer[BUFFER_SIZE];
    ssize_t received = recv(sock, buffer, BUFFER_SIZE - 1, 0);
    
    // End timing
    end_time = get_time_ms();
    
    if (received > 0) {
        // Null terminate for safe printing
        if (received < BUFFER_SIZE) {
            buffer[received] = '\0';
        } else {
            buffer[BUFFER_SIZE - 1] = '\0';
        }
        
        double request_response_time = end_time - start_time;
        printf("HTTPS request/response time: %.2f ms\n", request_response_time);
        
        // Use the longer of connection time or request/response time
        if (request_response_time > latency_ms) {
            latency_ms = request_response_time;
        }
    } else {
        printf("No response received from HTTPS server\n");
    }
    
    close(sock);
    return latency_ms;
}

int run_latency_tests(void) {
    double dns_latency, udp_latency, https_latency;
    
    printf("=== Network Latency Test ===\n\n"); // Google DNS
    dns_latency = test_dns_latency("google.com");
    udp_latency = test_udp_latency("8.8.8.8", 53);
    https_latency = test_https_latency("google.com", 443);
    
    printf("\n=== Latency Test Results ===\n");
    if (dns_latency >= 0) {
        printf("DNS Latency: %.2f ms\n", dns_latency);
    } else {
        printf("DNS Latency: Test failed\n");
    }
    
    if (udp_latency >= 0) {
        printf("UDP Latency: %.2f ms\n", udp_latency);
    } else {
        printf("UDP Latency: Test failed\n");
    }
    
    if (https_latency >= 0) {
        printf("HTTPS Latency: %.2f ms\n", https_latency);
    } else {
        printf("HTTPS Latency: Test failed\n");
    }
    
    return 0;
}