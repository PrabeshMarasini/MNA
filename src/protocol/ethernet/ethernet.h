#ifdef ETHERNET_H
#define ETHERNET_H

#include <stdint.h>

#define ETHER_ADDR_LEN 6

struct ethernet_header {
    uint8_t dest_mac[ETHER_ADDR_LEN];
    uint8_t src_mac[ETHER_ADDR_LEN];
    uint16_t ethertype;
} __attribute__((packed));

void parse_ethernet(const u_char *packet, int len);

#endif