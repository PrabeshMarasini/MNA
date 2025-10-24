#ifndef ARP_H
#define ARP_H

#include <pcap.h>

void parse_arp(const u_char *packet, int packet_len);

#endif // ARP_H
