#ifndef IPV6_H
#define IPV6_H

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#include <stdint.h>
#include <sys/types.h>
#include <pcap.h>
#include <netinet/ip6.h>

// IPv6 packet analysis structure
typedef struct {
    uint8_t version;
    uint8_t traffic_class;
    uint32_t flow_label;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    struct in6_addr src_addr;
    struct in6_addr dst_addr;
    const u_char *payload;
    int payload_len;
    const u_char *extension_headers;
    int extension_headers_len;
} ipv6_packet_info_t;

// IPv6 traffic statistics
typedef struct {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t tcp_packets;
    uint64_t udp_packets;
    uint64_t icmpv6_packets;
    uint64_t other_packets;
    uint64_t extension_header_packets;
    uint64_t fragmented_packets;
    uint64_t multicast_packets;
    uint64_t link_local_packets;
} ipv6_stats_t;

// Function declarations
void parse_ipv6(const u_char *payload, int payload_len);
void analyze_ipv6_header(const ipv6_packet_info_t *ip6_info);
void analyze_ipv6_addresses(const struct in6_addr *src, const struct in6_addr *dst);
void analyze_traffic_class(uint8_t traffic_class);
const char* get_ipv6_next_header_name(uint8_t next_header);
int is_ipv6_multicast(const struct in6_addr *addr);
int is_ipv6_link_local(const struct in6_addr *addr);
int is_ipv6_loopback(const struct in6_addr *addr);
void print_ipv6_stats(void);
void reset_ipv6_stats(void);

#endif // IPV6_H
