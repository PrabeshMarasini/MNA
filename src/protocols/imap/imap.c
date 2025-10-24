#include <stdio.h>
#include <string.h>
#include "imap.h"

void parse_imap(const u_char *payload, int payload_len, int src_port, int dst_port) {
    if (src_port != 143 && dst_port != 143) return;

    printf("=== IMAP Packet ===\n");

    if (dst_port == 143)
        printf("Client -> Server\n");
    else
        printf("Server -> Client\n");

    printf("Data: ");
    for (int i = 0; i < payload_len && i < 80; i++) {
        if (payload[i] >= 32 && payload[i] <= 126)
            putchar(payload[i]);
        else if (payload[i] == '\r' || payload[i] == '\n')
            putchar(payload[i]);
        else
            putchar('.');
    }
    printf("\n");

    if (dst_port == 143) {
        if (payload_len > 5) {
            if (strstr((const char *)payload, "LOGIN"))
                printf("Command: LOGIN\n");
            else if (strstr((const char *)payload, "SELECT"))
                printf("Command: SELECT\n");
            else if (strstr((const char *)payload, "FETCH"))
                printf("Command: FETCH\n");
            else if (strstr((const char *)payload, "LOGOUT"))
                printf("Command: LOGOUT\n");
        }
    }

    if (src_port == 143) {
        if (strstr((const char *)payload, "OK"))
            printf("Response: OK\n");
        else if (strstr((const char *)payload, "NO"))
            printf("Response: NO\n");
        else if (strstr((const char *)payload, "BAD"))
            printf("Response: BAD\n");
    }

    printf("===================\n");
}
