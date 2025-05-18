#ifndef IP_H
#define IP_H

#include <stdint.h>

struct ip_header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ihl:4;
    uint8_t version:4;
#else
    uint8_t version:4;
    uint8_t ihl:4;
#endif
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
} __attribute__((packed));

void parse_ip(const u_char *packet, int len);

#endif
