#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include "udp.h"

// Global statistics
static udp_stats_t g_stats = {0};

// Well-known port mappings
typedef struct {
    uint16_t port;
    const char *service;
} port_service_t;

static const port_service_t port_services[] = {
    {53, "DNS"}, {67, "DHCP-Server"}, {68, "DHCP-Client"}, {69, "TFTP"},
    {123, "NTP"}, {161, "SNMP"}, {162, "SNMP-Trap"}, {514, "Syslog"},
    {520, "RIP"}, {1900, "UPnP"}, {5353, "mDNS"}, {0, NULL}
};

const char* get_port_service(uint16_t port) {
    for (int i = 0; port_services[i].service != NULL; i++) {
        if (port_services[i].port == port) {
            return port_services[i].service;
        }
    }
    return "Unknown";
}

int is_printable_data(const u_char *data, int len) {
    if (len == 0) return 0;
    int printable_count = 0;
    for (int i = 0; i < len && i < 100; i++) {
        if (isprint(data[i]) || isspace(data[i])) {
            printable_count++;
        }
    }
    return (printable_count * 100 / (len > 100 ? 100 : len)) > 70;
}

void print_hex_dump(const u_char *data, int len, int max_bytes) {
    int bytes_to_print = (len > max_bytes) ? max_bytes : len;
    
    printf("Data (hex): ");
    for (int i = 0; i < bytes_to_print; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n            ");
    }
    if (len > max_bytes) printf("... (%d more bytes)", len - max_bytes);
    printf("\n");
    
    if (is_printable_data(data, bytes_to_print)) {
        printf("Data (ascii): ");
        for (int i = 0; i < bytes_to_print; i++) {
            printf("%c", isprint(data[i]) ? data[i] : '.');
        }
        if (len > max_bytes) printf("...");
        printf("\n");
    }
}

void parse_dns_packet(const u_char *data, int len, uint16_t src_port, uint16_t dst_port) {
    (void)src_port; // Suppress unused parameter warning
    (void)dst_port; // Suppress unused parameter warning
    if (len < 12) return; // Minimum DNS header size
    
    uint16_t transaction_id = ntohs(*(uint16_t*)data);
    uint16_t flags = ntohs(*(uint16_t*)(data + 2));
    uint16_t questions = ntohs(*(uint16_t*)(data + 4));
    uint16_t answers = ntohs(*(uint16_t*)(data + 6));
    
    int is_response = (flags & 0x8000) != 0;
    int opcode = (flags >> 11) & 0x0F;
    int rcode = flags & 0x0F;
    
    printf("  DNS %s (ID: 0x%04x)\n", is_response ? "Response" : "Query", transaction_id);
    printf("  Questions: %u, Answers: %u, Opcode: %d", questions, answers, opcode);
    if (is_response) printf(", RCode: %d", rcode);
    printf("\n");
    
    g_stats.dns_packets++;
}

void parse_dhcp_packet(const u_char *data, int len, uint16_t src_port, uint16_t dst_port) {
    (void)src_port; // Suppress unused parameter warning
    (void)dst_port; // Suppress unused parameter warning
    if (len < 240) return; // Minimum DHCP packet size
    
    uint8_t op = data[0];
    uint8_t htype = data[1];
    uint8_t hlen = data[2];
    uint32_t xid = ntohl(*(uint32_t*)(data + 4));
    
    printf("  DHCP %s (XID: 0x%08x)\n", (op == 1) ? "Request" : "Reply", xid);
    printf("  Hardware Type: %u, Hardware Length: %u\n", htype, hlen);
    
    // Look for DHCP message type in options (simplified)
    if (len > 240) {
        const u_char *options = data + 240;
        int opt_len = len - 240;
        for (int i = 0; i < opt_len - 2; i++) {
            if (options[i] == 53 && options[i+1] == 1) { // DHCP Message Type
                uint8_t msg_type = options[i+2];
                const char *type_names[] = {"", "DISCOVER", "OFFER", "REQUEST", 
                                          "DECLINE", "ACK", "NAK", "RELEASE", "INFORM"};
                if (msg_type >= 1 && msg_type <= 8) {
                    printf("  Message Type: %s\n", type_names[msg_type]);
                }
                break;
            }
        }
    }
    
    g_stats.dhcp_packets++;
}

void parse_ntp_packet(const u_char *data, int len, uint16_t src_port, uint16_t dst_port) {
    (void)src_port; // Suppress unused parameter warning
    (void)dst_port; // Suppress unused parameter warning
    if (len < 48) return; // NTP packet is exactly 48 bytes
    
    uint8_t li_vn_mode = data[0];
    uint8_t stratum = data[1];
    uint8_t poll = data[2];
    uint8_t precision = data[3];
    
    int version = (li_vn_mode >> 3) & 0x07;
    int mode = li_vn_mode & 0x07;
    
    const char *mode_names[] = {"Reserved", "Symmetric Active", "Symmetric Passive",
                               "Client", "Server", "Broadcast", "Control", "Private"};
    
    printf("  NTP v%d %s\n", version, (mode < 8) ? mode_names[mode] : "Unknown");
    printf("  Stratum: %u, Poll: %d, Precision: %d\n", stratum, poll, (int8_t)precision);
    
    g_stats.ntp_packets++;
}

void analyze_udp_protocol(const udp_packet_info_t *udp_info) {
    uint16_t src_port = udp_info->src_port;
    uint16_t dst_port = udp_info->dst_port;
    
    // DNS
    if (src_port == 53 || dst_port == 53 || src_port == 5353 || dst_port == 5353) {
        parse_dns_packet(udp_info->data, udp_info->data_len, src_port, dst_port);
        return;
    }
    
    // DHCP
    if ((src_port == 67 && dst_port == 68) || (src_port == 68 && dst_port == 67)) {
        parse_dhcp_packet(udp_info->data, udp_info->data_len, src_port, dst_port);
        return;
    }
    
    // NTP
    if (src_port == 123 || dst_port == 123) {
        parse_ntp_packet(udp_info->data, udp_info->data_len, src_port, dst_port);
        return;
    }
    
    // Generic protocol analysis
    printf("  Protocol: %s", get_port_service(dst_port));
    if (strcmp(get_port_service(dst_port), "Unknown") == 0 && 
        strcmp(get_port_service(src_port), "Unknown") != 0) {
        printf(" (%s)", get_port_service(src_port));
    }
    printf("\n");
    
    if (udp_info->data_len > 0) {
        printf("  Payload: %d bytes\n", udp_info->data_len);
        print_hex_dump(udp_info->data, udp_info->data_len, 32);
    }
    
    g_stats.other_packets++;
}

void parse_udp(const u_char *payload, int payload_len) {
    if (payload_len < (int)sizeof(struct udphdr)) {
        printf("Invalid UDP packet: too short (%d bytes)\n", payload_len);
        return;
    }

    struct udphdr *udp_hdr = (struct udphdr *)payload;
    
    // Extract UDP header information
    udp_packet_info_t udp_info = {
        .src_port = ntohs(udp_hdr->source),
        .dst_port = ntohs(udp_hdr->dest),
        .length = ntohs(udp_hdr->len),
        .checksum = ntohs(udp_hdr->check),
        .data = payload + sizeof(struct udphdr),
        .data_len = payload_len - sizeof(struct udphdr)
    };
    
    // Validate UDP length
    if (udp_info.length < sizeof(struct udphdr) || udp_info.length > payload_len) {
        printf("Invalid UDP length field: %u (packet size: %d)\n", udp_info.length, payload_len);
        return;
    }
    
    // Update statistics
    g_stats.total_packets++;
    g_stats.total_bytes += udp_info.length;
    
    // Print timestamp
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    printf("\n[%02d:%02d:%02d] ", tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
    
    printf("=== UDP Packet #%lu ===\n", g_stats.total_packets);
    printf("Source Port: %u (%s)\n", udp_info.src_port, get_port_service(udp_info.src_port));
    printf("Destination Port: %u (%s)\n", udp_info.dst_port, get_port_service(udp_info.dst_port));
    printf("Length: %u bytes\n", udp_info.length);
    printf("Checksum: 0x%04x %s\n", udp_info.checksum, 
           udp_info.checksum == 0 ? "(disabled)" : "");
    
    // Protocol-specific analysis
    analyze_udp_protocol(&udp_info);
    
    printf("========================\n");
}

void print_udp_stats(void) {
    printf("\n--- UDP Traffic Statistics ---\n");
    printf("Total Packets: %lu\n", g_stats.total_packets);
    printf("Total Bytes: %lu\n", g_stats.total_bytes);
    printf("DNS Packets: %lu (%.1f%%)\n", g_stats.dns_packets, 
           g_stats.total_packets ? (g_stats.dns_packets * 100.0 / g_stats.total_packets) : 0);
    printf("DHCP Packets: %lu (%.1f%%)\n", g_stats.dhcp_packets,
           g_stats.total_packets ? (g_stats.dhcp_packets * 100.0 / g_stats.total_packets) : 0);
    printf("NTP Packets: %lu (%.1f%%)\n", g_stats.ntp_packets,
           g_stats.total_packets ? (g_stats.ntp_packets * 100.0 / g_stats.total_packets) : 0);
    printf("Other Packets: %lu (%.1f%%)\n", g_stats.other_packets,
           g_stats.total_packets ? (g_stats.other_packets * 100.0 / g_stats.total_packets) : 0);
    printf("Average Packet Size: %.1f bytes\n", 
           g_stats.total_packets ? (g_stats.total_bytes / (double)g_stats.total_packets) : 0);
    printf("-----------------------------\n\n");
}

void reset_udp_stats(void) {
    memset(&g_stats, 0, sizeof(g_stats));
}

#ifdef UDP_STANDALONE
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>


#define SNAP_LEN 65535
#define TIMEOUT_MS 1000

static pcap_t *g_handle = NULL;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;
    
    // Check minimum packet size
    if (header->caplen < sizeof(struct ether_header)) return;
    
    const struct ether_header *eth_header = (struct ether_header *)packet;
    
    // Check if it's IPv4
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) return;
    
    // Check minimum IP header size
    if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip)) return;
    
    const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    
    // Validate IP version and protocol
    if (ip_header->ip_v != 4 || ip_header->ip_p != IPPROTO_UDP) return;
    
    int ip_header_len = ip_header->ip_hl * 4;
    int udp_offset = sizeof(struct ether_header) + ip_header_len;
    
    if (header->caplen < udp_offset) return;
    
    const u_char *udp_payload = packet + udp_offset;
    int total_ip_len = ntohs(ip_header->ip_len);
    int udp_payload_len = total_ip_len - ip_header_len;
    
    // Ensure we don't read beyond captured data
    int available_len = header->caplen - udp_offset;
    if (udp_payload_len > available_len) {
        udp_payload_len = available_len;
    }
    
    // Parse UDP packet
    parse_udp(udp_payload, udp_payload_len);
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
    
    // Filter only UDP packets
    struct bpf_program fp;
    if (pcap_compile(g_handle, &fp, "udp", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(g_handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter.\n");
        return 1;
    }
    
    printf("Listening for UDP packets...\n");
    
    // Start packet capture loop (Ctrl+C to stop)
    pcap_loop(g_handle, 0, packet_handler, NULL);
    
    // Cleanup
    pcap_freealldevs(alldevs);
    pcap_close(g_handle);
    return 0;
}
#endif