#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <sys/types.h>       // for u_char, u_int
#include <netinet/in.h>
#include <pcap.h>            // include after sys/types.h

// Include available protocol analyzers
#include "../protocols/tcp/tcp.h"
#include "../protocols/udp/udp.h"
#include "../protocols/http/http.h"
#include "../protocols/ftp/ftp.h"
#include "../protocols/smtp/smtp.h"
#include "../protocols/ssh/ssh.h"
#include "../protocols/imap/imap.h"
#include "../protocols/snmp/snmp.h"
#include "../protocols/ipv4/ipv4.h"
#include "../protocols/ipv6/ipv6.h"
#include "../protocols/arp/arp.h"
#include "../protocols/dhcp/dhcp.h"
#include "../protocols/https/https.h"
#include "../protocols/quic/quic.h"

// Main protocol identification functions
void identify_protocol(const u_char *packet, int packet_len);
void identify_tcp_protocol(uint16_t src, uint16_t dst);
void identify_udp_protocol(uint16_t src, uint16_t dst);
void print_hex(const u_char *data, int len);

// Enhanced protocol parsing functions
void parse_tcp_packet(const u_char *payload, int payload_len, uint32_t src_ip, uint32_t dst_ip);
void parse_udp_packet(const u_char *payload, int payload_len, uint32_t src_ip, uint32_t dst_ip);
void parse_application_layer(const u_char *payload, int payload_len, uint16_t src_port, uint16_t dst_port, int is_tcp);

#endif // PROTOCOL_H
