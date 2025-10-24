#ifndef DNS_H
#define DNS_H

#include <pcap.h>

void parse_dns_packet(const u_char *payload, int payload_len);

#endif