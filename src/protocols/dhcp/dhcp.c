#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "dhcp.h"

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_OPTION_MSG_TYPE 53
#define DHCP_OPTION_END 255

const char *dhcp_message_type(uint8_t type) {
    switch (type) {
        case 1: return "DHCP Discover";
        case 2: return "DHCP Offer";
        case 3: return "DHCP Request";
        case 4: return "DHCP Decline";
        case 5: return "DHCP ACK";
        case 6: return "DHCP NAK";
        case 7: return "DHCP Release";
        case 8: return "DHCP Inform";
        default: return "Unknown";
    }
}

struct dhcp_header {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint8_t options[312];
};

void parse_dhcp(const u_char *payload, int payload_len) {
    if (payload_len < (int)sizeof(struct dhcp_header)) return;

    const struct dhcp_header *dhcp = (const struct dhcp_header *)payload;

    printf("=== DHCP Packet ===\n");
    printf("Transaction ID: 0x%08x\n", ntohl(dhcp->xid));
    printf("Client IP: %s\n", inet_ntoa(*(struct in_addr *)&dhcp->ciaddr));
    printf("Your IP: %s\n", inet_ntoa(*(struct in_addr *)&dhcp->yiaddr));
    printf("Server IP: %s\n", inet_ntoa(*(struct in_addr *)&dhcp->siaddr));
    printf("Gateway IP: %s\n", inet_ntoa(*(struct in_addr *)&dhcp->giaddr));

    printf("Client MAC: ");
    for (int i = 0; i < dhcp->hlen && i < 16; i++)
        printf("%02x%c", dhcp->chaddr[i], (i == dhcp->hlen - 1) ? '\n' : ':');

    if (dhcp->options[0] != 0x63 || dhcp->options[1] != 0x82 ||
        dhcp->options[2] != 0x53 || dhcp->options[3] != 0x63) {
        printf("Invalid DHCP magic cookie.\n");
        return;
    }

    int i = 4;
    while (i < payload_len - (int)((const u_char *)dhcp->options - payload)) {
        uint8_t option = dhcp->options[i++];
        if (option == DHCP_OPTION_END) break;
        if (option == 0) continue;

        uint8_t len = dhcp->options[i++];
        if (i + len > 312) break;

        if (option == DHCP_OPTION_MSG_TYPE && len == 1) {
            uint8_t msg_type = dhcp->options[i];
            printf("DHCP Message Type: %s (%d)\n", dhcp_message_type(msg_type), msg_type);
        }

        i += len;
    }

    printf("===================\n");
}
