#ifndef DHCP_H
#define DHCP_H

#include <stdint.h>
#include <pcap.h>

void parse_dhcp(const u_char *payload, int payload_len);

#endif
