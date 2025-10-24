#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include "ipv6.h"

// Global statistics
static ipv6_stats_t g_stats = {0};

// IPv6 next header protocol names
const char* get_ipv6_next_header_name(uint8_t next_header) {
    switch (next_header) {
        case IPPROTO_HOPOPTS: return "Hop-by-Hop Options";
        case IPPROTO_ICMPV6: return "ICMPv6";
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ROUTING: return "Routing Header";
        case IPPROTO_FRAGMENT: return "Fragment Header";
        case IPPROTO_ESP: return "ESP";
        case IPPROTO_AH: return "Authentication Header";
        case IPPROTO_DSTOPTS: return "Destination Options";
        case IPPROTO_SCTP: return "SCTP";
        case IPPROTO_MH: return "Mobility Header";
        default: return "Unknown";
    }
}

int is_ipv6_multicast(const struct in6_addr *addr) {
    return (addr->s6_addr[0] == 0xff);
}

int is_ipv6_link_local(const struct in6_addr *addr) {
    return (addr->s6_addr[0] == 0xfe && (addr->s6_addr[1] & 0xc0) == 0x80);
}

int is_ipv6_loopback(const struct in6_addr *addr) {
    static const struct in6_addr loopback = IN6ADDR_LOOPBACK_INIT;
    return memcmp(addr, &loopback, sizeof(struct in6_addr)) == 0;
}

void analyze_traffic_class(uint8_t traffic_class) {
    uint8_t dscp = (traffic_class >> 2) & 0x3F;
    uint8_t ecn = traffic_class & 0x03;
    
    printf("  DSCP: 0x%02x (%u)", dscp, dscp);
    if (dscp == 0) printf(" (Best Effort)");
    else if (dscp == 46) printf(" (Expedited Forwarding)");
    else if (dscp >= 34 && dscp <= 38) printf(" (Assured Forwarding)");
    printf("\n");
    
    printf("  ECN: 0x%01x", ecn);
    switch (ecn) {
        case 0: printf(" (Not ECT)"); break;
        case 1: printf(" (ECT(1))"); break;
        case 2: printf(" (ECT(0))"); break;
        case 3: printf(" (CE - Congestion Experienced)"); break;
    }
    printf("\n");
}

void analyze_ipv6_addresses(const struct in6_addr *src, const struct in6_addr *dst) {
    char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
    
    inet_ntop(AF_INET6, src, src_str, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, dst, dst_str, INET6_ADDRSTRLEN);
    
    printf("Source IPv6: %s", src_str);
    if (is_ipv6_loopback(src)) printf(" (Loopback)");
    else if (is_ipv6_link_local(src)) printf(" (Link-Local)");
    else if (is_ipv6_multicast(src)) printf(" (Multicast)");
    printf("\n");
    
    printf("Destination IPv6: %s", dst_str);
    if (is_ipv6_loopback(dst)) printf(" (Loopback)");
    else if (is_ipv6_link_local(dst)) printf(" (Link-Local)");
    else if (is_ipv6_multicast(dst)) printf(" (Multicast)");
    printf("\n");
    
    // Update statistics
    if (is_ipv6_multicast(src) || is_ipv6_multicast(dst)) {
        g_stats.multicast_packets++;
    }
    if (is_ipv6_link_local(src) || is_ipv6_link_local(dst)) {
        g_stats.link_local_packets++;
    }
}

void analyze_ipv6_header(const ipv6_packet_info_t *ip6_info) {
    printf("Version: %u\n", ip6_info->version);
    printf("Traffic Class: 0x%02x\n", ip6_info->traffic_class);
    analyze_traffic_class(ip6_info->traffic_class);
    printf("Flow Label: 0x%05x (%u)\n", ip6_info->flow_label, ip6_info->flow_label);
    printf("Payload Length: %u bytes\n", ip6_info->payload_length);
    printf("Next Header: %u (%s)\n", ip6_info->next_header, 
           get_ipv6_next_header_name(ip6_info->next_header));
    printf("Hop Limit: %u\n", ip6_info->hop_limit);
    
    analyze_ipv6_addresses(&ip6_info->src_addr, &ip6_info->dst_addr);
    
    // Extension headers analysis
    if (ip6_info->extension_headers_len > 0) {
        printf("Extension Headers: %d bytes\n", ip6_info->extension_headers_len);
        printf("  First 16 bytes: ");
        int show_bytes = (ip6_info->extension_headers_len > 16) ? 16 : ip6_info->extension_headers_len;
        for (int i = 0; i < show_bytes; i++) {
            printf("%02x ", ip6_info->extension_headers[i]);
        }
        if (ip6_info->extension_headers_len > 16) printf("...");
        printf("\n");
        g_stats.extension_header_packets++;
    }
    
    // Payload analysis
    if (ip6_info->payload_len > 0) {
        printf("Payload: %d bytes (%s)\n", ip6_info->payload_len, 
               get_ipv6_next_header_name(ip6_info->next_header));
        
        // Show first few bytes of payload
        printf("  First 16 bytes: ");
        int show_bytes = (ip6_info->payload_len > 16) ? 16 : ip6_info->payload_len;
        for (int i = 0; i < show_bytes; i++) {
            printf("%02x ", ip6_info->payload[i]);
        }
        if (ip6_info->payload_len > 16) printf("...");
        printf("\n");
    }
}

void parse_ipv6(const u_char *payload, int payload_len) {
    if (payload_len < (int)sizeof(struct ip6_hdr)) {
        printf("Invalid IPv6 packet: too short (%d bytes)\n", payload_len);
        return;
    }

    struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)payload;
    
    // Extract version from the first 4 bits
    uint32_t ver_tc_fl = ntohl(*(uint32_t *)payload);
    uint8_t version = (ver_tc_fl >> 28) & 0xF;
    
    // Validate IPv6 version
    if (version != 6) {
        printf("Not an IPv6 packet (version: %d)\n", version);
        return;
    }
    
    // Extract packet information
    ipv6_packet_info_t ip6_info = {
        .version = version,
        .traffic_class = (ver_tc_fl >> 20) & 0xFF,
        .flow_label = ver_tc_fl & 0xFFFFF,
        .payload_length = ntohs(ip6_hdr->ip6_plen),
        .next_header = ip6_hdr->ip6_nxt,
        .hop_limit = ip6_hdr->ip6_hops,
        .src_addr = ip6_hdr->ip6_src,
        .dst_addr = ip6_hdr->ip6_dst
    };
    
    // Calculate payload offset (IPv6 header is always 40 bytes)
    int ipv6_header_len = sizeof(struct ip6_hdr);
    
    // For simplicity, we'll treat extension headers as part of payload
    // In a full implementation, you'd parse each extension header
    if (payload_len > ipv6_header_len) {
        ip6_info.payload = payload + ipv6_header_len;
        ip6_info.payload_len = payload_len - ipv6_header_len;
        
        // Check if we have extension headers (simplified detection)
        if (ip6_info.next_header == IPPROTO_HOPOPTS || 
            ip6_info.next_header == IPPROTO_ROUTING ||
            ip6_info.next_header == IPPROTO_FRAGMENT ||
            ip6_info.next_header == IPPROTO_DSTOPTS) {
            ip6_info.extension_headers = ip6_info.payload;
            ip6_info.extension_headers_len = (ip6_info.payload_len > 8) ? 8 : ip6_info.payload_len;
        } else {
            ip6_info.extension_headers = NULL;
            ip6_info.extension_headers_len = 0;
        }
    } else {
        ip6_info.payload = NULL;
        ip6_info.payload_len = 0;
        ip6_info.extension_headers = NULL;
        ip6_info.extension_headers_len = 0;
    }
    
    // Update statistics
    g_stats.total_packets++;
    g_stats.total_bytes += payload_len;
    
    switch (ip6_info.next_header) {
        case IPPROTO_TCP: g_stats.tcp_packets++; break;
        case IPPROTO_UDP: g_stats.udp_packets++; break;
        case IPPROTO_ICMPV6: g_stats.icmpv6_packets++; break;
        case IPPROTO_FRAGMENT: g_stats.fragmented_packets++; break;
        default: g_stats.other_packets++; break;
    }
    
    // Print timestamp
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    printf("\n[%02d:%02d:%02d] ", tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
    
    printf("=== IPv6 Packet #%lu ===\n", g_stats.total_packets);
    
    analyze_ipv6_header(&ip6_info);
    
    printf("==========================\n");
}

void print_ipv6_stats(void) {
    printf("\n--- IPv6 Traffic Statistics ---\n");
    printf("Total Packets: %lu\n", g_stats.total_packets);
    printf("Total Bytes: %lu\n", g_stats.total_bytes);
    printf("TCP Packets: %lu (%.1f%%)\n", g_stats.tcp_packets,
           g_stats.total_packets ? (g_stats.tcp_packets * 100.0 / g_stats.total_packets) : 0);
    printf("UDP Packets: %lu (%.1f%%)\n", g_stats.udp_packets,
           g_stats.total_packets ? (g_stats.udp_packets * 100.0 / g_stats.total_packets) : 0);
    printf("ICMPv6 Packets: %lu (%.1f%%)\n", g_stats.icmpv6_packets,
           g_stats.total_packets ? (g_stats.icmpv6_packets * 100.0 / g_stats.total_packets) : 0);
    printf("Other Packets: %lu (%.1f%%)\n", g_stats.other_packets,
           g_stats.total_packets ? (g_stats.other_packets * 100.0 / g_stats.total_packets) : 0);
    printf("Extension Header Packets: %lu\n", g_stats.extension_header_packets);
    printf("Fragmented Packets: %lu\n", g_stats.fragmented_packets);
    printf("Multicast Packets: %lu\n", g_stats.multicast_packets);
    printf("Link-Local Packets: %lu\n", g_stats.link_local_packets);
    printf("Average Packet Size: %.1f bytes\n",
           g_stats.total_packets ? (g_stats.total_bytes / (double)g_stats.total_packets) : 0);
    printf("------------------------------\n\n");
}

void reset_ipv6_stats(void) {
    memset(&g_stats, 0, sizeof(g_stats));
}
#ifdef IPV6_STANDALONE
#include <pcap.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>

#define SNAP_LEN 65535
#define TIMEOUT_MS 1000

static pcap_t *g_handle = NULL;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;
    
    // Check minimum packet size for Ethernet header
    if (header->caplen < sizeof(struct ether_header)) return;
    
    const struct ether_header *eth_header = (struct ether_header *)packet;
    
    // Check if it's IPv6
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IPV6) return;
    
    // Extract IPv6 packet (skip Ethernet header)
    const u_char *ipv6_packet = packet + sizeof(struct ether_header);
    int ipv6_len = header->caplen - sizeof(struct ether_header);
    
    // Parse IPv6 packet
    parse_ipv6(ipv6_packet, ipv6_len);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;
    
    // Find all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }
    
    // Use first device
    device = alldevs;
    if (!device) {
        fprintf(stderr, "No devices found.\n");
        return 1;
    }
    
    printf("Using device: %s\n", device->name);
    
    // Open device for capture
    g_handle = pcap_open_live(device->name, SNAP_LEN, 1, TIMEOUT_MS, errbuf);
    if (!g_handle) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device->name, errbuf);
        return 1;
    }
    
    // Filter only IPv6 packets
    struct bpf_program fp;
    if (pcap_compile(g_handle, &fp, "ip6", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(g_handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter.\n");
        return 1;
    }
    
    printf("Listening for IPv6 packets...\n");
    
    // Initialize stats
    reset_ipv6_stats();
    
    // Start packet capture loop (Ctrl+C to stop)
    pcap_loop(g_handle, 0, packet_handler, NULL);
    
    // Cleanup
    pcap_freealldevs(alldevs);
    pcap_close(g_handle);
    return 0;
}
#endif