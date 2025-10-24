#include <stdio.h>
#include <string.h>
#include <time.h>
#include "imap.h"

#define COLOR_RESET   "\033[0m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_RED     "\033[31m"

void print_timestamp() {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", t);
    printf("%s", buf);
}

void parse_and_print(const char *payload, int length, int src_port, int dst_port, int *cmd_count, int *resp_count) {
    print_timestamp();
    if (dst_port == 143) {
        printf(" %s[Client -> Server]%s\n", COLOR_BLUE, COLOR_RESET);
        (*cmd_count)++;
    } else {
        printf(" %s[Server -> Client]%s\n", COLOR_GREEN, COLOR_RESET);
        (*resp_count)++;
    }

    // Show payload truncated to 80 chars with ellipsis if longer
    printf("Data: ");
    int max_len = 80;
    int show_len = length < max_len ? length : max_len;
    for (int i = 0; i < show_len; i++) {
        unsigned char c = (unsigned char)payload[i];
        if (c >= 32 && c <= 126)
            putchar(c);
        else if (c == '\r' || c == '\n')
            putchar(c);
        else
            putchar('.');
    }
    if (length > max_len)
        printf("...");

    printf("\n");

    // Call your existing parser to print commands/responses
    parse_imap((const unsigned char *)payload, length, src_port, dst_port);

    printf("%s=============================================%s\n\n", COLOR_YELLOW, COLOR_RESET);
}

int main() {
    const char *client_payloads[] = {
        "A001 LOGIN user pass\r\n",
        "A002 SELECT INBOX\r\n",
        "A003 FETCH 1 BODY[]\r\n",
        "A004 LOGOUT\r\n",
        "A005 UNKNOWNCMD\r\n"
    };

    const char *server_payloads[] = {
        "* OK IMAP4rev1 Service Ready\r\n",
        "A001 OK LOGIN completed\r\n",
        "A002 NO SELECT failed\r\n",
        "A003 BAD FETCH failed\r\n",
        "A005 BAD Unknown command\r\n"
    };

    int cmd_count = 0, resp_count = 0;

    printf("%s=== Testing Client IMAP Commands ===%s\n\n", COLOR_BLUE, COLOR_RESET);
    for (int i = 0; i < (int)(sizeof(client_payloads)/sizeof(client_payloads[0])); i++) {
        parse_and_print(client_payloads[i], strlen(client_payloads[i]), 12345, 143, &cmd_count, &resp_count);
    }

    printf("%s=== Testing Server IMAP Responses ===%s\n\n", COLOR_GREEN, COLOR_RESET);
    for (int i = 0; i < (int)(sizeof(server_payloads)/sizeof(server_payloads[0])); i++) {
        parse_and_print(server_payloads[i], strlen(server_payloads[i]), 143, 12345, &cmd_count, &resp_count);
    }

    printf("%sSummary:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("Total client commands parsed: %d\n", cmd_count);
    printf("Total server responses parsed: %d\n", resp_count);

    return 0;
}
