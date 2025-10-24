#ifndef UDP_H
#define UDP_H

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#include <sys/types.h>
#include <pcap.h>
#include <stdint.h>
#include <netinet/udp.h>

// UDP protocol analysis structures
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
    const u_char *data;
    int data_len;
} udp_packet_info_t;

typedef struct {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t dns_packets;
    uint64_t dhcp_packets;
    uint64_t ntp_packets;
    uint64_t other_packets;
} udp_stats_t;

// Function declarations
void parse_udp(const u_char *payload, int payload_len);
void analyze_udp_protocol(const udp_packet_info_t *udp_info);
void print_udp_stats(void);
void reset_udp_stats(void);
const char* get_port_service(uint16_t port);
void print_hex_dump(const u_char *data, int len, int max_bytes);
int is_printable_data(const u_char *data, int len);

// Protocol-specific parsers
void parse_dns_packet(const u_char *data, int len, uint16_t src_port, uint16_t dst_port);
void parse_dhcp_packet(const u_char *data, int len, uint16_t src_port, uint16_t dst_port);
void parse_ntp_packet(const u_char *data, int len, uint16_t src_port, uint16_t dst_port);

#endif // UDP_H
