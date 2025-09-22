#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <sys/types.h>       // for u_char, u_int
#include <netinet/in.h>
#include <pcap.h>            // include after sys/types.h

void identify_protocol(const u_char *packet, int packet_len);
void identify_tcp_protocol(uint16_t src, uint16_t dst);
void identify_udp_protocol(uint16_t src, uint16_t dst);
void print_hex(const u_char *data, int len);

#endif // PROTOCOL_H
