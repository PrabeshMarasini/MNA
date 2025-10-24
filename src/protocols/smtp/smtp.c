#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include "smtp.h"

// Check if payload contains printable SMTP control characters
static int is_printable_ascii(const u_char *data, int len) {
    for (int i = 0; i < len; i++) {
        if ((data[i] < 32 || data[i] > 126) && data[i] != '\r' && data[i] != '\n')
            return 0;
    }
    return 1;
}

static int starts_with_ci(const char *line, const char *prefix) {
    size_t n = strlen(prefix);
    for (size_t i = 0; i < n; i++) {
        if (tolower((unsigned char)line[i]) != tolower((unsigned char)prefix[i])) return 0;
    }
    return 1;
}

static void print_server_reply(const char *line, int *in_multiline_code) {
    // Format: CODE[ -]TEXT, e.g., 250-... or 250 ...
    if (isdigit((unsigned char)line[0]) && isdigit((unsigned char)line[1]) && isdigit((unsigned char)line[2])) {
        int code = (line[0]-'0')*100 + (line[1]-'0')*10 + (line[2]-'0');
        char sep = line[3];
        const char *text = line + (sep == ' ' || sep == '-' ? 4 : 3);
        printf("Reply %d%c %s\n", code, sep, text);
        if (sep == '-') *in_multiline_code = code; else *in_multiline_code = 0;
    } else if (*in_multiline_code) {
        printf("Reply %d- %s\n", *in_multiline_code, line);
    } else {
        printf("Reply %s\n", line);
    }
}

static void redact_and_print_client_line(const char *line) {
    if (starts_with_ci(line, "AUTH ")) {
        // Print mechanism but redact rest
        const char *mech = line + 5;
        printf("AUTH %.*s <redacted>\n", (int)strcspn(mech, " \r\n"), mech);
        return;
    }
    if (starts_with_ci(line, "PASS ") || starts_with_ci(line, "LOGIN ")) {
        printf("<redacted sensitive>\n");
        return;
    }
    printf("%s\n", line);
}

// Parse SMTP control messages
void parse_smtp(const u_char *payload, int payload_len, int src_port, int dst_port) {
    // Typical SMTP ports: 25 (standard), 587 (submission), 465 (implicit TLS)
    if (src_port != 25 && dst_port != 25 && src_port != 587 && dst_port != 587 && src_port != 465 && dst_port != 465) return;

    if (!is_printable_ascii(payload, payload_len)) return;

    int server_to_client = (src_port == 25 || src_port == 587 || src_port == 465);
    printf("=== SMTP Packet ===\n");
    printf(server_to_client ? "Server -> Client:\n" : "Client -> Server:\n");

    char buffer[2049];
    int copy_len = (payload_len < 2048) ? payload_len : 2048;
    memcpy(buffer, payload, copy_len);
    buffer[copy_len] = '\0';

    int in_multiline_code = 0;
    char *saveptr = NULL;
    char *line = strtok_r(buffer, "\r\n", &saveptr);
    while (line) {
        if (server_to_client) {
            print_server_reply(line, &in_multiline_code);
        } else {
            // Parse key client commands for quick insights
            if (starts_with_ci(line, "EHLO ") || starts_with_ci(line, "HELO ")) {
                printf("%s\n", line);
            } else if (starts_with_ci(line, "MAIL FROM:")) {
                printf("MAIL FROM: %s\n", line + 10);
            } else if (starts_with_ci(line, "RCPT TO:")) {
                printf("RCPT TO: %s\n", line + 8);
            } else if (starts_with_ci(line, "STARTTLS")) {
                printf("STARTTLS\n");
            } else if (starts_with_ci(line, "DATA")) {
                printf("DATA (message body follows)\n");
            } else if (starts_with_ci(line, "QUIT")) {
                printf("QUIT\n");
            } else {
                redact_and_print_client_line(line);
            }
        }
        line = strtok_r(NULL, "\r\n", &saveptr);
    }

    printf("===================\n");
}

#ifdef SMTP_STANDALONE
#define ETHERNET_HEADER_LEN 14

static void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)user;
    if (header->caplen < ETHERNET_HEADER_LEN) return;

    // Parse Ethernet ethertype
    uint16_t ethertype;
    memcpy(&ethertype, packet + 12, sizeof(uint16_t));
    ethertype = ntohs(ethertype);

    if (ethertype == 0x0800) { // IPv4
        if (header->caplen < ETHERNET_HEADER_LEN + (int)sizeof(struct ip)) return;
        const struct ip *ip_header = (const struct ip *)(packet + ETHERNET_HEADER_LEN);
        if (ip_header->ip_v != 4) return;
        int ip_header_len = ip_header->ip_hl * 4;
        if (header->caplen < ETHERNET_HEADER_LEN + ip_header_len + (int)sizeof(struct tcphdr)) return;
        if (ip_header->ip_p != IPPROTO_TCP) return;
        const struct tcphdr *tcp = (const struct tcphdr *)(packet + ETHERNET_HEADER_LEN + ip_header_len);
        int thl = tcp->doff * 4;
        int total_len = ntohs(ip_header->ip_len);
        int payload_offset = ETHERNET_HEADER_LEN + ip_header_len + thl;
        int payload_len = total_len - ip_header_len - thl;
        if (payload_len <= 0 || header->caplen < payload_offset) return;
        const u_char *payload = packet + payload_offset;
        int src_port = ntohs(tcp->source);
        int dst_port = ntohs(tcp->dest);
        parse_smtp(payload, payload_len, src_port, dst_port);
        return;
    }

    if (ethertype == 0x86DD) { // IPv6
        if (header->caplen < ETHERNET_HEADER_LEN + (int)sizeof(struct ip6_hdr)) return;
        const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(packet + ETHERNET_HEADER_LEN);
        // Only handle simple case without extension headers
        if (ip6->ip6_nxt != IPPROTO_TCP) return;
        int ip6_header_len = 40; // fixed
        const struct tcphdr *tcp = (const struct tcphdr *)(packet + ETHERNET_HEADER_LEN + ip6_header_len);
        if ((const u_char *)tcp + sizeof(struct tcphdr) > packet + header->caplen) return;
        int thl = tcp->doff * 4;
        uint16_t plen = ntohs(ip6->ip6_plen);
        int payload_offset = ETHERNET_HEADER_LEN + ip6_header_len + thl;
        int payload_len = (int)plen - thl;
        if (payload_len <= 0 || header->caplen < payload_offset) return;
        const u_char *payload = packet + payload_offset;
        int src_port = ntohs(tcp->source);
        int dst_port = ntohs(tcp->dest);
        parse_smtp(payload, payload_len, src_port, dst_port);
        return;
    }
}

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *iface = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            iface = argv[++i];
        } else {
            fprintf(stderr, "Usage: %s [-i iface]\n", argv[0]);
            return 1;
        }
    }

    if (!iface) {
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
            fprintf(stderr, "Error finding devices: %s\n", errbuf);
            return 1;
        }
        iface = alldevs->name;
        pcap_freealldevs(alldevs);
    }

    pcap_t *handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open device %s: %s\n", iface, errbuf);
        return 1;
    }

    struct bpf_program fp;
    const char filter_exp[] = "tcp port 25 or tcp port 465 or tcp port 587";
    if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    printf("Capturing SMTP on: %s\n", iface);
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}
#endif
