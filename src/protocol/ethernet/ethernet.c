#include "ethernet.h"
#include <stdio.h>
#include <arpa/inet.h>

void print_mac_address(uint8_t *mac) {
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        printf("%02x", mac[i]);
        if (i < ETHER_ADDR_LEN - 1) printf(":");
    }
}

void parse_ethernet(const u_char *packet, int len) {
    if (len < sizeof(struct ethernet_header)) return;

    const struct ethernet_header *eth = (const struct ethernet_header *)packet;
    uint16_t ethertype = ntohs(eth->ethertype);

    printf("Ethernet Header:\n");
    printf("  Src MAC: ");
    print_mac_address((uint8_t *)eth->src_mac);
    printf("\n  Dest MAC: ");
    print_mac_address((uint8_t *)eth->dest_mac);
    printf("\n  Ethertype: 0x%04x\n", ethertype);
}
