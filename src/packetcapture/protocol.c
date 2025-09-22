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

// Helper functions for protocol identification
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

    printf("Packet Length: %d bytes\n", packet_len);

    switch (eth_type) {
        case ETH_P_ARP:
            printf("Protocol: ARP\n");
            print_hex(packet, packet_len);
            return;

        case ETH_P_IP: {
            struct iphdr *ip = (struct iphdr *)payload;
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip->daddr), dst_ip, INET_ADDRSTRLEN);

            printf("Source IP: %s\n", src_ip);
            printf("Destination IP: %s\n", dst_ip);

            payload += ip->ihl * 4;

            printf("Protocol: ");
            switch (ip->protocol) {
                case IPPROTO_ICMP:
                    printf("ICMP\n");
                    break;

                case IPPROTO_TCP: {
                    struct tcphdr *tcp = (struct tcphdr *)payload;
                    uint16_t src = ntohs(tcp->source);
                    uint16_t dst = ntohs(tcp->dest);
                    identify_tcp_protocol(src, dst);
                    printf("\n");
                    break;
                }

                case IPPROTO_UDP: {
                    struct udphdr *udp = (struct udphdr *)payload;
                    uint16_t src = ntohs(udp->source);
                    uint16_t dst = ntohs(udp->dest);
                    identify_udp_protocol(src, dst);
                    printf("\n");
                    break;
                }

                default:
                    printf("IPv4 - Unknown Protocol %d\n", ip->protocol);
                    break;
            }

            print_hex(packet, packet_len);
            return;
        }

        case ETH_P_IPV6: {
            struct ip6_hdr *ip6 = (struct ip6_hdr *)payload;
            char src_ip[INET6_ADDRSTRLEN];
            char dst_ip[INET6_ADDRSTRLEN];

            inet_ntop(AF_INET6, &(ip6->ip6_src), src_ip, sizeof(src_ip));
            inet_ntop(AF_INET6, &(ip6->ip6_dst), dst_ip, sizeof(dst_ip));

            printf("Source IP: %s\n", src_ip);
            printf("Destination IP: %s\n", dst_ip);

            uint8_t nexthdr = ip6->ip6_nxt;
            payload += sizeof(struct ip6_hdr);

            printf("Protocol: ");
            switch (nexthdr) {
                case IPPROTO_ICMPV6:
                    printf("ICMPv6\n");
                    break;

                case IPPROTO_TCP: {
                    struct tcphdr *tcp = (struct tcphdr *)payload;
                    uint16_t src = ntohs(tcp->source);
                    uint16_t dst = ntohs(tcp->dest);
                    identify_tcp_protocol(src, dst);
                    printf(" (IPv6)\n");
                    break;
                }

                case IPPROTO_UDP: {
                    struct udphdr *udp = (struct udphdr *)payload;
                    uint16_t src = ntohs(udp->source);
                    uint16_t dst = ntohs(udp->dest);
                    identify_udp_protocol(src, dst);
                    printf(" (IPv6)\n");
                    break;
                }

                default:
                    printf("IPv6 - Unknown Protocol %d\n", nexthdr);
                    break;
            }

            print_hex(packet, packet_len);
            return;
        }

        default:
            printf("Unknown Ethernet Type 0x%04x\n", eth_type);
            print_hex(packet, packet_len);
            return;
    }
}
