#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "ipv4.h"

// Global statistics
static ipv4_stats_t g_stats = {0};

// Protocol name mappings
const char* get_protocol_name(uint8_t protocol) {
    switch (protocol) {
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_IPV6: return "IPv6";
        case IPPROTO_GRE: return "GRE";
        case IPPROTO_ESP: return "ESP";
        case IPPROTO_AH: return "AH";
        case IPPROTO_SCTP: return "SCTP";
        default: return "Unknown";
    }
}

// Type of Service descriptions
const char* get_tos_description(uint8_t tos) {
    uint8_t precedence = (tos >> 5) & 0x07;
    uint8_t delay = (tos >> 4) & 0x01;
    uint8_t throughput = (tos >> 3) & 0x01;
    uint8_t reliability = (tos >> 2) & 0x01;
    
    static char desc[128];
    snprintf(desc, sizeof(desc), "Precedence:%d %s%s%s", 
             precedence,
             delay ? "Low-Delay " : "",
             throughput ? "High-Throughput " : "",
             reliability ? "High-Reliability" : "");
    return desc;
}

int is_private_ip(uint32_t ip) {
    uint8_t first = (ip >> 24) & 0xFF;
    uint8_t second = (ip >> 16) & 0xFF;
    
    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    return (first == 10) || 
           (first == 172 && second >= 16 && second <= 31) ||
           (first == 192 && second == 168);
}

int is_multicast_ip(uint32_t ip) {
    uint8_t first = (ip >> 24) & 0xFF;
    return (first >= 224 && first <= 239);
}

void track_ip_addresses(uint32_t src_ip, uint32_t dst_ip) {
    // Simple unique IP tracking (limited to 256 each)
    int found_src = 0, found_dst = 0;
    
    for (int i = 0; i < g_stats.src_ip_count && i < 256; i++) {
        if (g_stats.unique_src_ips[i] == src_ip) {
            found_src = 1;
            break;
        }
    }
    
    if (!found_src && g_stats.src_ip_count < 256) {
        g_stats.unique_src_ips[g_stats.src_ip_count++] = src_ip;
    }
    
    for (int i = 0; i < g_stats.dst_ip_count && i < 256; i++) {
        if (g_stats.unique_dst_ips[i] == dst_ip) {
            found_dst = 1;
            break;
        }
    }
    
    if (!found_dst && g_stats.dst_ip_count < 256) {
        g_stats.unique_dst_ips[g_stats.dst_ip_count++] = dst_ip;
    }
}

void analyze_ipv4_flags(uint16_t flags_fragment) {
    uint16_t flags = (flags_fragment >> 13) & 0x07;
    uint16_t fragment_offset = flags_fragment & 0x1FFF;
    
    printf("  Flags: ");
    if (flags & 0x02) printf("DF(Don't Fragment) ");
    if (flags & 0x01) printf("MF(More Fragments) ");
    if (flags == 0) printf("None ");
    printf("\n");
    
    if (fragment_offset > 0 || (flags & 0x01)) {
        printf("  Fragment Offset: %u (bytes: %u)\n", fragment_offset, fragment_offset * 8);
        g_stats.fragmented_packets++;
    }
}

void analyze_ipv4_options(const u_char *options, int options_len) {
    if (options_len == 0) return;
    
    printf("  Options (%d bytes): ", options_len);
    for (int i = 0; i < options_len && i < 16; i++) {
        printf("%02x ", options[i]);
    }
    if (options_len > 16) printf("...");
    printf("\n");
    
    g_stats.options_packets++;
}

void analyze_ipv4_header(const ipv4_packet_info_t *ip_info) {
    char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
    struct in_addr src_addr = {.s_addr = ip_info->src_ip};
    struct in_addr dst_addr = {.s_addr = ip_info->dst_ip};
    
    inet_ntop(AF_INET, &src_addr, src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_addr, dst_ip_str, INET_ADDRSTRLEN);
    
    printf("Version: %u\n", ip_info->version);
    printf("Header Length: %u bytes\n", ip_info->header_length);
    printf("Type of Service: 0x%02x (%s)\n", ip_info->tos, get_tos_description(ip_info->tos));
    printf("Total Length: %u bytes\n", ip_info->total_length);
    printf("Identification: 0x%04x (%u)\n", ip_info->identification, ip_info->identification);
    
    analyze_ipv4_flags(ip_info->flags_fragment);
    
    printf("TTL: %u\n", ip_info->ttl);
    printf("Protocol: %u (%s)\n", ip_info->protocol, get_protocol_name(ip_info->protocol));
    printf("Header Checksum: 0x%04x\n", ip_info->checksum);
    
    printf("Source IP: %s", src_ip_str);
    if (is_private_ip(ip_info->src_ip)) printf(" (Private)");
    if (is_multicast_ip(ip_info->src_ip)) printf(" (Multicast)");
    printf("\n");
    
    printf("Destination IP: %s", dst_ip_str);
    if (is_private_ip(ip_info->dst_ip)) printf(" (Private)");
    if (is_multicast_ip(ip_info->dst_ip)) printf(" (Multicast)");
    printf("\n");
    
    analyze_ipv4_options(ip_info->options, ip_info->options_len);
    
    // Payload analysis
    if (ip_info->payload_len > 0) {
        printf("Payload: %d bytes (%s)\n", ip_info->payload_len, get_protocol_name(ip_info->protocol));
        
        // Show first few bytes of payload for analysis
        printf("  First 16 bytes: ");
        int show_bytes = (ip_info->payload_len > 16) ? 16 : ip_info->payload_len;
        for (int i = 0; i < show_bytes; i++) {
            printf("%02x ", ip_info->payload[i]);
        }
        if (ip_info->payload_len > 16) printf("...");
        printf("\n");
    }
}

void parse_ipv4(const u_char *payload, int payload_len) {
    if (payload_len < (int)sizeof(struct ip)) {
        printf("Invalid IPv4 packet: too short (%d bytes)\n", payload_len);
        return;
    }

    struct ip *ip_hdr = (struct ip *)payload;
    
    // Validate IPv4 version
    if (ip_hdr->ip_v != 4) {
        printf("Not an IPv4 packet (version: %d)\n", ip_hdr->ip_v);
        return;
    }
    
    // Extract packet information
    ipv4_packet_info_t ip_info = {
        .version = ip_hdr->ip_v,
        .header_length = ip_hdr->ip_hl * 4,
        .tos = ip_hdr->ip_tos,
        .total_length = ntohs(ip_hdr->ip_len),
        .identification = ntohs(ip_hdr->ip_id),
        .flags_fragment = ntohs(ip_hdr->ip_off),
        .ttl = ip_hdr->ip_ttl,
        .protocol = ip_hdr->ip_p,
        .checksum = ntohs(ip_hdr->ip_sum),
        .src_ip = ip_hdr->ip_src.s_addr,
        .dst_ip = ip_hdr->ip_dst.s_addr
    };
    
    // Validate header length
    if (ip_info.header_length < 20 || ip_info.header_length > payload_len) {
        printf("Invalid IPv4 header length: %u\n", ip_info.header_length);
        return;
    }
    
    // Extract options if present
    if (ip_info.header_length > 20) {
        ip_info.options = payload + 20;
        ip_info.options_len = ip_info.header_length - 20;
    } else {
        ip_info.options = NULL;
        ip_info.options_len = 0;
    }
    
    // Extract payload
    if (payload_len > ip_info.header_length) {
        ip_info.payload = payload + ip_info.header_length;
        ip_info.payload_len = payload_len - ip_info.header_length;
    } else {
        ip_info.payload = NULL;
        ip_info.payload_len = 0;
    }
    
    // Update statistics
    g_stats.total_packets++;
    g_stats.total_bytes += ip_info.total_length;
    
    switch (ip_info.protocol) {
        case IPPROTO_TCP: g_stats.tcp_packets++; break;
        case IPPROTO_UDP: g_stats.udp_packets++; break;
        case IPPROTO_ICMP: g_stats.icmp_packets++; break;
        default: g_stats.other_packets++; break;
    }
    
    track_ip_addresses(ip_info.src_ip, ip_info.dst_ip);
    
    // Print timestamp
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    printf("\n[%02d:%02d:%02d] ", tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
    
    printf("=== IPv4 Packet #%lu ===\n", g_stats.total_packets);
    
    analyze_ipv4_header(&ip_info);
    
    printf("==========================\n");
}

void print_ipv4_stats(void) {
    printf("\n--- IPv4 Traffic Statistics ---\n");
    printf("Total Packets: %lu\n", g_stats.total_packets);
    printf("Total Bytes: %lu\n", g_stats.total_bytes);
    printf("TCP Packets: %lu (%.1f%%)\n", g_stats.tcp_packets,
           g_stats.total_packets ? (g_stats.tcp_packets * 100.0 / g_stats.total_packets) : 0);
    printf("UDP Packets: %lu (%.1f%%)\n", g_stats.udp_packets,
           g_stats.total_packets ? (g_stats.udp_packets * 100.0 / g_stats.total_packets) : 0);
    printf("ICMP Packets: %lu (%.1f%%)\n", g_stats.icmp_packets,
           g_stats.total_packets ? (g_stats.icmp_packets * 100.0 / g_stats.total_packets) : 0);
    printf("Other Packets: %lu (%.1f%%)\n", g_stats.other_packets,
           g_stats.total_packets ? (g_stats.other_packets * 100.0 / g_stats.total_packets) : 0);
    printf("Fragmented Packets: %lu\n", g_stats.fragmented_packets);
    printf("Packets with Options: %lu\n", g_stats.options_packets);
    printf("Unique Source IPs: %d\n", g_stats.src_ip_count);
    printf("Unique Destination IPs: %d\n", g_stats.dst_ip_count);
    printf("Average Packet Size: %.1f bytes\n",
           g_stats.total_packets ? (g_stats.total_bytes / (double)g_stats.total_packets) : 0);
    printf("------------------------------\n\n");
}

void reset_ipv4_stats(void) {
    memset(&g_stats, 0, sizeof(g_stats));
}
#ifdef IPV4_STANDALONE
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
    
    // Check if it's IPv4
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) return;
    
    // Extract IPv4 packet (skip Ethernet header)
    const u_char *ipv4_packet = packet + sizeof(struct ether_header);
    int ipv4_len = header->caplen - sizeof(struct ether_header);
    
    // Parse IPv4 packet
    parse_ipv4(ipv4_packet, ipv4_len);
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
    
    // Filter only IPv4 packets
    struct bpf_program fp;
    if (pcap_compile(g_handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(g_handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter.\n");
        return 1;
    }
    
    printf("Listening for IPv4 packets...\n");
    
    // Initialize stats
    reset_ipv4_stats();
    
    // Start packet capture loop (Ctrl+C to stop)
    pcap_loop(g_handle, 0, packet_handler, NULL);
    
    // Cleanup
    pcap_freealldevs(alldevs);
    pcap_close(g_handle);
    return 0;
}
#endif