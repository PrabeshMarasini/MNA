#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "protocol.h"
#include <ctype.h> // for isprint

// Enhanced TCP packet parsing with detailed analysis
void parse_tcp_packet(const u_char *payload, int payload_len, uint32_t src_ip, uint32_t dst_ip) {
    if (payload_len < (int)sizeof(struct tcphdr)) {
        printf("TCP packet too short\n");
        return;
    }
    
    struct tcphdr *tcp_hdr = (struct tcphdr *)payload;
    uint16_t src_port = ntohs(tcp_hdr->source);
    uint16_t dst_port = ntohs(tcp_hdr->dest);
    int tcp_header_len = tcp_hdr->doff * 4;
    
    // Use detailed TCP analyzer
    parse_tcp_with_context(payload, payload_len, src_ip, dst_ip);
    
    // Parse application layer if there's payload
    if (payload_len > tcp_header_len) {
        const u_char *app_payload = payload + tcp_header_len;
        int app_payload_len = payload_len - tcp_header_len;
        parse_application_layer(app_payload, app_payload_len, src_port, dst_port, 1);
    }
}

// Enhanced UDP packet parsing with detailed analysis
void parse_udp_packet(const u_char *payload, int payload_len, uint32_t src_ip, uint32_t dst_ip) {
    (void)src_ip; // Suppress unused parameter warning
    (void)dst_ip; // Suppress unused parameter warning
    if (payload_len < (int)sizeof(struct udphdr)) {
        printf("UDP packet too short\n");
        return;
    }
    
    struct udphdr *udp_hdr = (struct udphdr *)payload;
    uint16_t src_port = ntohs(udp_hdr->source);
    uint16_t dst_port = ntohs(udp_hdr->dest);
    
    // Use detailed UDP analyzer
    parse_udp(payload, payload_len);
    
    // Parse application layer
    const u_char *app_payload = payload + sizeof(struct udphdr);
    int app_payload_len = payload_len - sizeof(struct udphdr);
    
    if (app_payload_len > 0) {
        parse_application_layer(app_payload, app_payload_len, src_port, dst_port, 0);
    }
}

// Parse application layer protocols
void parse_application_layer(const u_char *payload, int payload_len, uint16_t src_port, uint16_t dst_port, int is_tcp) {
    if (payload_len <= 0) return;
    
    // DNS (usually UDP port 53, but can be TCP)
    if (src_port == 53 || dst_port == 53) {
        printf("\n=== DNS Analysis ===\n");
        // Use the UDP's DNS parser for both TCP and UDP
        parse_dns_packet(payload, payload_len, src_port, dst_port);
        printf("===================\n");
        return;
    }
    
    // HTTP (TCP port 80)
    if (is_tcp && (src_port == 80 || dst_port == 80)) {
        // Check if it looks like HTTP
        if (payload_len > 4 && 
            (strncmp((char*)payload, "GET ", 4) == 0 ||
             strncmp((char*)payload, "POST ", 5) == 0 ||
             strncmp((char*)payload, "HTTP/", 5) == 0 ||
             strncmp((char*)payload, "PUT ", 4) == 0 ||
             strncmp((char*)payload, "DELETE ", 7) == 0)) {
            printf("\n=== HTTP Analysis ===\n");
            parse_http(payload, payload_len);
            printf("====================\n");
        }
        return;
    }
    
    // HTTPS/TLS (TCP port 443)
    if (is_tcp && (src_port == 443 || dst_port == 443)) {
        printf("\n=== HTTPS/TLS Analysis ===\n");
        if (payload_len > 0 && payload[0] == 0x16) {
            parse_tls_handshake(payload, payload_len);
        } else if (payload_len > 0 && payload[0] == 0x15) {
            printf("TLS Alert message detected\n");
        } else if (payload_len > 0 && payload[0] == 0x17) {
            printf("TLS Application Data (encrypted)\n");
        } else {
            printf("Encrypted HTTPS traffic detected\n");
        }
        printf("=========================\n");
        return;
    }
    
    // QUIC (UDP port 443 or 80)
    if (!is_tcp && (src_port == 443 || dst_port == 443 || src_port == 80 || dst_port == 80)) {
        if (detect_quic_packet(payload, payload_len)) {
            printf("\n=== QUIC Analysis ===\n");
            parse_quic(payload, payload_len, (int)src_port, (int)dst_port);
            printf("====================\n");
            return;
        }
    }
    
    // DHCP (UDP ports 67/68)
    if (!is_tcp && ((src_port == 67 && dst_port == 68) || (src_port == 68 && dst_port == 67))) {
        printf("\n=== DHCP Analysis ===\n");
        parse_dhcp(payload, payload_len);
        printf("====================\n");
        return;
    }
    
    // SSH (TCP port 22)
    if (is_tcp && (src_port == 22 || dst_port == 22)) {
        printf("\n=== SSH Analysis ===\n");
        parse_ssh(payload, payload_len, (int)src_port, (int)dst_port);
        printf("===================\n");
        return;
    }
    
    // FTP (TCP port 21 or 20)
    if (is_tcp && (src_port == 21 || dst_port == 21 || src_port == 20 || dst_port == 20)) {
        printf("\n=== FTP Analysis ===\n");
        parse_ftp(payload, payload_len, (int)src_port, (int)dst_port);
        printf("==================\n");
        return;
    }
    
    // SMTP (TCP port 25, 465, 587)
    if (is_tcp && (src_port == 25 || dst_port == 25 || src_port == 465 || dst_port == 465 || src_port == 587 || dst_port == 587)) {
        printf("\n=== SMTP Analysis ===\n");
        parse_smtp(payload, payload_len, (int)src_port, (int)dst_port);
        printf("===================\n");
        return;
    }
    
    // IMAP (TCP port 143, 993)
    if (is_tcp && (src_port == 143 || dst_port == 143 || src_port == 993 || dst_port == 993)) {
        printf("\n=== IMAP Analysis ===\n");
        parse_imap(payload, payload_len, (int)src_port, (int)dst_port);
        printf("===================\n");
        return;
    }
    
    // SNMP (UDP ports 161, 162)
    if (!is_tcp && (src_port == 161 || dst_port == 161 || src_port == 162 || dst_port == 162)) {
        printf("\n=== SNMP Analysis ===\n");
        parse_snmp(payload, payload_len, (int)src_port, (int)dst_port);
        printf("===================\n");
        return;
    }
    
    // Generic protocol detection for other common ports
    if (is_tcp) {
        // POP3 (TCP port 110, 995)
        if (src_port == 110 || dst_port == 110 || src_port == 995 || dst_port == 995) {
            printf("\n=== POP3 Analysis ===\n");
            printf("POP3 traffic detected (port %u <-> %u)\n", src_port, dst_port);
            if (payload_len > 0) {
                printf("Data preview: ");
                for (int i = 0; i < payload_len && i < 100; i++) {
                    if (payload[i] >= 32 && payload[i] <= 126) {
                        printf("%c", payload[i]);
                    } else {
                        printf(".");
                    }
                }
                printf("\n");
            }
            printf("====================\n");
            return;
        }
        
        // Telnet (TCP port 23)
        if (src_port == 23 || dst_port == 23) {
            printf("\n=== Telnet Analysis ===\n");
            printf("Telnet traffic detected (port %u <-> %u)\n", src_port, dst_port);
            printf("WARNING: Unencrypted protocol!\n");
            printf("======================\n");
            return;
        }
    } else {
        // NTP (UDP port 123)
        if (src_port == 123 || dst_port == 123) {
            printf("\n=== NTP Analysis ===\n");
            printf("NTP traffic detected (port %u <-> %u)\n", src_port, dst_port);
            printf("Payload length: %d bytes\n", payload_len);
            printf("==================\n");
            return;
        }
        
        // TFTP (UDP port 69)
        if (src_port == 69 || dst_port == 69) {
            printf("\n=== TFTP Analysis ===\n");
            printf("TFTP traffic detected (port %u <-> %u)\n", src_port, dst_port);
            printf("Payload length: %d bytes\n", payload_len);
            printf("===================\n");
            return;
        }
    }
}

// Helper functions for protocol identification (kept for compatibility)
void identify_tcp_protocol(uint16_t src, uint16_t dst) {
    if (src == 80 || dst == 80) printf("HTTP");
    else if (src == 443 || dst == 443) printf("HTTPS (TLS/SSL)");
    else if (src == 21 || dst == 21) printf("FTP");
    else if (src == 25 || dst == 25) printf("SMTP");
    else if (src == 110 || dst == 110) printf("POP3");
    else if (src == 143 || dst == 143) printf("IMAP");
    else if (src == 22 || dst == 22) printf("SSH");
    else if (src == 139 || dst == 139) printf("NetBIOS");
    else if (src == 5060 || dst == 5060 || src == 5061 || dst == 5061) printf("SIP");
    else printf("TCP");
}

void identify_udp_protocol(uint16_t src, uint16_t dst) {
    if (src == 53 || dst == 53) printf("DNS");
    else if (src == 67 || dst == 67 || src == 68 || dst == 68) printf("DHCP");
    else if (src == 123 || dst == 123) printf("NTP");
    else if (src == 137 || dst == 137 || src == 138 || dst == 138) printf("NetBIOS");
    else if (src == 161 || dst == 161 || src == 162 || dst == 162) printf("SNMP");
    else if (src == 5060 || dst == 5060 || src == 5061 || dst == 5061) printf("SIP");
    else printf("UDP");
}

// Function to print hex values and ASCII representation of a packet
void print_hex(const u_char *data, int len) {
    for (int i = 0; i < len; i += 16) {
        // Print offset
        printf("%04x  ", i);

        // Print hex part
        for (int j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02x ", data[i + j]);
            else
                printf("   ");  // for alignment
        }

        // Print ASCII part
        printf(" ");
        for (int j = 0; j < 16 && i + j < len; j++) {
            u_char ch = data[i + j];
            printf("%c", isprint(ch) ? ch : '.');
        }

        printf("\n");
    }
}

void identify_protocol(const u_char *packet, int packet_len) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    uint16_t eth_type = ntohs(eth->h_proto);
    const u_char *payload = packet + sizeof(struct ethhdr);

    printf("\n=== PACKET ANALYSIS ===\n");
    printf("Packet Length: %d bytes\n", packet_len);

    switch (eth_type) {
        case ETH_P_ARP:
            printf("Protocol: ARP\n");
            printf("=== ARP Analysis ===\n");
            parse_arp(packet, packet_len);
            printf("===================\n");
            print_hex(packet, packet_len);
            return;

        case ETH_P_IP: {
            printf("=== IPv4 Analysis ===\n");
            parse_ipv4(payload, packet_len - sizeof(struct ethhdr));
            printf("====================\n");
            
            struct iphdr *ip = (struct iphdr *)payload;

            const u_char *transport_payload = payload + (ip->ihl * 4);
            int transport_len = packet_len - sizeof(struct ethhdr) - (ip->ihl * 4);

            switch (ip->protocol) {
                case IPPROTO_ICMP:
                    printf("\n=== ICMP Analysis ===\n");
                    printf("ICMP packet detected\n");
                    printf("====================\n");
                    break;

                case IPPROTO_TCP:
                    parse_tcp_packet(transport_payload, transport_len, ip->saddr, ip->daddr);
                    break;

                case IPPROTO_UDP:
                    parse_udp_packet(transport_payload, transport_len, ip->saddr, ip->daddr);
                    break;

                default:
                    printf("\n=== Unknown IPv4 Protocol ===\n");
                    printf("Protocol Number: %d\n", ip->protocol);
                    printf("=============================\n");
                    break;
            }

            printf("\n=== Raw Packet Data ===\n");
            print_hex(packet, packet_len);
            printf("======================\n");
            return;
        }

        case ETH_P_IPV6: {
            printf("=== IPv6 Analysis ===\n");
            parse_ipv6(payload, packet_len - sizeof(struct ethhdr));
            printf("====================\n");
            
            struct ip6_hdr *ip6 = (struct ip6_hdr *)payload;

            uint8_t nexthdr = ip6->ip6_nxt;
            const u_char *transport_payload = payload + sizeof(struct ip6_hdr);
            int transport_len = packet_len - sizeof(struct ethhdr) - sizeof(struct ip6_hdr);

            switch (nexthdr) {
                case IPPROTO_ICMPV6:
                    printf("\n=== ICMPv6 Analysis ===\n");
                    printf("ICMPv6 packet detected\n");
                    printf("======================\n");
                    break;

                case IPPROTO_TCP:
                    printf("\n[IPv6 Transport]\n");
                    parse_tcp_packet(transport_payload, transport_len, 
                                   *((uint32_t*)&ip6->ip6_src.s6_addr[12]), 
                                   *((uint32_t*)&ip6->ip6_dst.s6_addr[12]));
                    break;

                case IPPROTO_UDP:
                    printf("\n[IPv6 Transport]\n");
                    parse_udp_packet(transport_payload, transport_len, 
                                   *((uint32_t*)&ip6->ip6_src.s6_addr[12]), 
                                   *((uint32_t*)&ip6->ip6_dst.s6_addr[12]));
                    break;

                default:
                    printf("\n=== Unknown IPv6 Protocol ===\n");
                    printf("Next Header: %d\n", nexthdr);
                    printf("=============================\n");
                    break;
            }

            printf("\n=== Raw Packet Data ===\n");
            print_hex(packet, packet_len);
            printf("======================\n");
            return;
        }

        default:
            printf("=== Unknown Ethernet Protocol ===\n");
            printf("Ethernet Type: 0x%04x\n", eth_type);
            printf("=================================\n");
            print_hex(packet, packet_len);
            return;
    }
    
    printf("========================\n");
}
