#include "traceroute.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <time.h>
#include <sys/select.h>

// Calculate checksum for ICMP packets
static unsigned short calculate_checksum(unsigned short *buffer, int size) {
    unsigned long sum = 0;
    unsigned short *ptr = buffer;
    int count = size;
    
    while (count > 1) {
        sum += *ptr++;
        count -= 2;
    }
    
    if (count > 0) {
        sum += *(unsigned char*)ptr;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

// Create ICMP echo packet
static void create_icmp_packet(char *packet, int packet_id, int sequence) {
    struct icmp *icmp_hdr = (struct icmp*)packet;
    
    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_id = packet_id;
    icmp_hdr->icmp_seq = sequence;
    icmp_hdr->icmp_cksum = 0;
    
    char *data = (char*)(icmp_hdr + 1);
    for (int i = 0; i < (int)(PACKET_SIZE - sizeof(struct icmp)); i++) {
        data[i] = i & 0xFF;
    }
    
    icmp_hdr->icmp_cksum = calculate_checksum((unsigned short*)icmp_hdr, PACKET_SIZE);
}

// Send ICMP packet with specific TTL
static int send_icmp_packet(int sock, struct sockaddr_in *dest_addr, int ttl, int packet_id, int sequence) {
    char packet[PACKET_SIZE];
    
    if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        return -1;
    }
    
    create_icmp_packet(packet, packet_id, sequence);
    
    if (sendto(sock, packet, PACKET_SIZE, 0, (struct sockaddr*)dest_addr, sizeof(*dest_addr)) < 0) {
        return -1;
    }
    
    return 0;
}

// Receive ICMP response
static int receive_icmp_response(int sock, int packet_id, int sequence, struct timeval *start_time, double *response_time, struct sockaddr_in *response_addr) {
    char buffer[1024];
    socklen_t addr_len = sizeof(*response_addr);
    fd_set read_set;
    struct timeval timeout, end_time;
    ssize_t bytes_received;
    
    timeout.tv_sec = DEFAULT_TIMEOUT;
    timeout.tv_usec = 0;
    
    FD_ZERO(&read_set);
    FD_SET(sock, &read_set);
    
    if (select(sock + 1, &read_set, NULL, NULL, &timeout) > 0) {
        if (FD_ISSET(sock, &read_set)) {
            bytes_received = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)response_addr, &addr_len);
            if (bytes_received < 0) {
                return -1; // Error receiving
            }
            
            gettimeofday(&end_time, NULL);
            *response_time = (end_time.tv_sec - start_time->tv_sec) * 1000.0 + 
                            (end_time.tv_usec - start_time->tv_usec) / 1000.0;
            
            struct ip *ip_hdr = (struct ip*)buffer;
            int ip_hdr_len = ip_hdr->ip_hl * 4;
            
            if (bytes_received < (ssize_t)(ip_hdr_len + sizeof(struct icmp))) {
                return -1;
            }
            
            struct icmp *icmp_hdr = (struct icmp*)(buffer + ip_hdr_len);
            
            // Check if this is our response
            if (icmp_hdr->icmp_type == ICMP_ECHOREPLY && icmp_hdr->icmp_id == packet_id && icmp_hdr->icmp_seq == sequence) {
                return 0;
            } else if (icmp_hdr->icmp_type == ICMP_TIME_EXCEEDED) {
                if (bytes_received < (ssize_t)(ip_hdr_len + 8 + sizeof(struct ip) + sizeof(struct icmp))) {
                    return 1;
                }
                
                // Extract original ICMP packet from payload
                struct ip *orig_ip_hdr = (struct ip*)(buffer + ip_hdr_len + 8);
                int orig_ip_hdr_len = orig_ip_hdr->ip_hl * 4;
                
                if (bytes_received < (ssize_t)(ip_hdr_len + 8 + orig_ip_hdr_len + sizeof(struct icmp))) {
                    return 1; 
                }
                
                struct icmp *orig_icmp_hdr = (struct icmp*)((char*)orig_ip_hdr + orig_ip_hdr_len);
                
                if (orig_icmp_hdr->icmp_id == packet_id && orig_icmp_hdr->icmp_seq == sequence) {
                    return 1;
                }
            }
        }
    }
    
    return -2; // Timeout
}

// Reverse DNS lookup
static void reverse_dns_lookup(struct in_addr addr, char *hostname, size_t hostname_size) {
    struct hostent *host_entry = gethostbyaddr((char*)&addr, sizeof(addr), AF_INET);
    if (host_entry != NULL) {
        strncpy(hostname, host_entry->h_name, hostname_size - 1);
        hostname[hostname_size - 1] = '\0';
    } else {
        strcpy(hostname, "*");
    }
}

// Perform traceroute to target
int perform_traceroute(const char* target_host, TracerouteResult* results) {
    int send_sock, recv_sock;
    struct sockaddr_in dest_addr, response_addr;
    struct in_addr target_ip;
    int ttl, probe;
    struct timeval start_time;
    
    memset(results, 0, sizeof(TracerouteResult));
    strncpy(results->target_host, target_host, sizeof(results->target_host) - 1);
    
    // Resolve target hostname
    if (resolve_hostname(target_host, &target_ip) < 0) {
        printf("traceroute: cannot resolve %s: Unknown host\n", target_host);
        return -1;
    }
    
    strncpy(results->target_ip, inet_ntoa(target_ip), sizeof(results->target_ip) - 1);
    
    // Create sending socket
    send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (send_sock < 0) {
        printf("traceroute: cannot create sending socket\n");
        return -1;
    }
    
    // Create receiving socket
    recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (recv_sock < 0) {
        close(send_sock);
        printf("traceroute: cannot create receiving socket (requires root privileges)\n");
        return -1;
    }
    
    // Set up destination address
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = target_ip;
    dest_addr.sin_port = htons(33434); // Common traceroute port
    
    // Set socket options for the sending socket
    int ttl_val = 1;
    if (setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) < 0) {
        printf("traceroute: cannot set socket options\n");
        close(send_sock);
        close(recv_sock);
        return -1;
    }
    
    printf("traceroute to %s (%s), %d hops max, %d byte packets\n", 
           target_host, inet_ntoa(target_ip), MAX_HOPS, PACKET_SIZE);
    
    // Perform traceroute
    int target_reached = 0;
    for (ttl = 1; ttl <= MAX_HOPS; ttl++) {
        TracerouteHop *hop = &results->hops[ttl-1];
        hop->hop_number = ttl;
        hop->probe_count = 0;
        
        printf("%2d ", ttl);
        fflush(stdout);
        
        int target_reached = 0;
        
        // Send 3 probes
        for (probe = 0; probe < MAX_PROBES; probe++) {
            int packet_id = getpid() & 0xFFFF;

            if (send_icmp_packet(send_sock, &dest_addr, ttl, packet_id, probe) < 0) {
                hop->status[probe] = 2; // Unreachable
                printf(" !");
                fflush(stdout);
                continue;
            }
            
            // Receive response
            double response_time;
            int result = receive_icmp_response(recv_sock, packet_id, probe, &start_time, &response_time, &response_addr);
            
            if (result == 0) {
                // Target reached
                hop->response_times[probe] = response_time;
                hop->status[probe] = 0; // Success
                hop->probe_count++;
                strncpy(hop->ip_address, inet_ntoa(response_addr.sin_addr), sizeof(hop->ip_address) - 1);
                reverse_dns_lookup(response_addr.sin_addr, hop->hostname, sizeof(hop->hostname));
                printf(" %s (%s)  %.3f ms", hop->hostname, hop->ip_address, response_time);
                target_reached = 1;
            } else if (result == 1) {
                hop->response_times[probe] = response_time;
                hop->status[probe] = 0; // Success
                hop->probe_count++;
                strncpy(hop->ip_address, inet_ntoa(response_addr.sin_addr), sizeof(hop->ip_address) - 1);
                reverse_dns_lookup(response_addr.sin_addr, hop->hostname, sizeof(hop->hostname));
                printf(" %s (%s)  %.3f ms", hop->hostname, hop->ip_address, response_time);
            } else if (result == -2) {
                hop->status[probe] = 1; // Timeout
                printf(" *");
            } else {
                hop->status[probe] = 2; // Unreachable
                printf(" !");
            }
            
            fflush(stdout);
            usleep(100000); // 100ms
        }
        
        printf("\n");
        
        if (target_reached) {
            results->total_hops = ttl;
            break;
        }
        
        if (ttl >= MAX_HOPS) {
            results->total_hops = MAX_HOPS;
            break;
        }
    }
    
    if (!target_reached) {
        results->total_hops = MAX_HOPS;
    }
    
    close(send_sock);
    close(recv_sock);
    
    return 0;
}

// Resolve hostname to IP address
int resolve_hostname(const char* hostname, struct in_addr* addr) {
    struct hostent *host_entry = gethostbyname(hostname);
    if (host_entry == NULL) {
        return -1;
    }
    memcpy(addr, host_entry->h_addr_list[0], sizeof(struct in_addr));
    return 0;
}

// Print formatted traceroute results
void print_traceroute_results(const TracerouteResult* results) {
    printf("\n=== Traceroute Results ===\n");
    printf("Target: %s (%s)\n", results->target_host, results->target_ip);
    printf("Total hops: %d\n", results->total_hops);
    
    // Count successful hops
    int successful_hops = 0;
    for (int i = 0; i < results->total_hops; i++) {
        if (results->hops[i].probe_count > 0) {
            successful_hops++;
        }
    }
    
    printf("Successful hops: %d\n", successful_hops);
    printf("=========================\n");
}

int run_traceroute(const char* target_host) {
    TracerouteResult results;
    
    printf("=== Traceroute ===\n\n");
    
    if (perform_traceroute(target_host, &results) < 0) {
        printf("Traceroute failed!\n");
        return 1;
    }
    
    print_traceroute_results(&results);
    return 0;
}