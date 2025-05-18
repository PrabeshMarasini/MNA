#include "ip.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

void parse_ip(const u_char *packet, int len) {
    if (len < sizeof(struct ip_header)) return;

    const struct ip_header *ip = (const struct ip_header *)packet;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ip->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &ip->dest_ip, dst, sizeof(dst));

    printf("IP Header:\n");
    printf("  Src IP: %s\n", src);
    printf("  Dest IP: %s\n", dst);
    printf("  Protocol: %u\n", ip->protocol);
}
