#ifndef IPV4_H
#define IPV4_H

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#include <stdint.h>
#include <sys/types.h>
#include <pcap.h>
#include <netinet/ip.h>

// IPv4 packet analysis structure
typedef struct {
    uint8_t version;
    uint8_t header_length;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
    const u_char *options;
    int options_len;
    const u_char *payload;
    int payload_len;
} ipv4_packet_info_t;

// IPv4 traffic statistics
typedef struct {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmp_packets;
    uint64_t other_packets;
    uint64_t fragmented_packets;
    uint64_t options_packets;
    uint32_t unique_src_ips[256];  // Simple tracking
    uint32_t unique_dst_ips[256];
    int src_ip_count;
    int dst_ip_count;
} ipv4_stats_t;

// Function declarations
void parse_ipv4(const u_char *payload, int payload_len);
void analyze_ipv4_header(const ipv4_packet_info_t *ip_info);
void analyze_ipv4_flags(uint16_t flags_fragment);
void analyze_ipv4_options(const u_char *options, int options_len);
void print_ipv4_stats(void);
void reset_ipv4_stats(void);
const char* get_protocol_name(uint8_t protocol);
const char* get_tos_description(uint8_t tos);
void track_ip_addresses(uint32_t src_ip, uint32_t dst_ip);
int is_private_ip(uint32_t ip);
int is_multicast_ip(uint32_t ip);

#endif // IPV4_H
