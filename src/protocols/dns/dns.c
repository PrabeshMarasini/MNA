#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "dns.h"

// DNS header structure (fixed 12 bytes)
struct dns_header {
    uint16_t id;       // Transaction ID
    uint16_t flags;    // Flags and codes
    uint16_t qdcount;  // Number of questions
    uint16_t ancount;  // Number of answers
    uint16_t nscount;  // Number of authority records
    uint16_t arcount;  // Number of additional records
};

static void print_dns_flags(uint16_t flags) {
    printf("Flags:\n");
    printf("  QR: %d (Query=0, Response=1)\n", (flags >> 15) & 0x1);
    printf("  Opcode: %d\n", (flags >> 11) & 0xF);
    printf("  AA: %d (Authoritative Answer)\n", (flags >> 10) & 0x1);
    printf("  TC: %d (Truncated)\n", (flags >> 9) & 0x1);
    printf("  RD: %d (Recursion Desired)\n", (flags >> 8) & 0x1);
    printf("  RA: %d (Recursion Available)\n", (flags >> 7) & 0x1);
    printf("  Z: %d (Reserved)\n", (flags >> 6) & 0x1);
    printf("  AD: %d (Authentic Data)\n", (flags >> 5) & 0x1);
    printf("  CD: %d (Checking Disabled)\n", (flags >> 4) & 0x1);
    printf("  RCODE: %d (Response code)\n", flags & 0xF);
}

// Helper: Decode DNS name from the packet (handles compression)
static int dns_decode_name(const u_char *buffer,
                           const u_char *payload_start,
                           int payload_len,
                           char *output,
                           int output_len) {
    int pos = 0;
    int jumped = 0;
    int count = 0;
    int jump_count = 0;
    const u_char *ptr = buffer;

    while (1) {
        if (ptr < payload_start || ptr >= payload_start + payload_len) return -1;
        uint8_t len = *ptr;
        if (len == 0) {
            if (pos >= output_len) return -1;
            output[pos] = '\0';
            if (!jumped) count++;
            break;
        }

        if ((len & 0xC0) == 0xC0) {
            if (ptr + 1 >= payload_start + payload_len) return -1;
            if (!jumped) count += 2;
            int offset = ((len & 0x3F) << 8) | *(ptr + 1);
            if (offset < 0 || offset >= payload_len) return -1;
            ptr = payload_start + offset;
            jumped = 1;
            jump_count++;
            if (jump_count > 10) return -1; // prevent infinite loops
            continue;
        } else {
            ptr++;
            if (len > 63) return -1; // label too long
            if (ptr + len > payload_start + payload_len) return -1;
            if (pos + len + 1 >= output_len) return -1;
            memcpy(output + pos, ptr, len);
            pos += len;
            output[pos++] = '.';
            ptr += len;
            if (!jumped) count += len + 1;
        }
    }

    if (pos > 0 && output[pos - 1] == '.') output[pos - 1] = '\0';
    if (pos > 255) return -1;
    return count;
}

static int safe_read_u16(const u_char *payload, int payload_len, int offset, uint16_t *out) {
    if (offset + 2 > payload_len) return -1;
    uint16_t v;
    memcpy(&v, payload + offset, sizeof(uint16_t));
    *out = ntohs(v);
    return 0;
}

static int safe_read_u32(const u_char *payload, int payload_len, int offset, uint32_t *out) {
    if (offset + 4 > payload_len) return -1;
    uint32_t v;
    memcpy(&v, payload + offset, sizeof(uint32_t));
    *out = ntohl(v);
    return 0;
}

static const char *rr_type_to_str(uint16_t t) {
    switch (t) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 41: return "OPT"; // EDNS(0)
        case 43: return "DS";
        case 46: return "RRSIG";
        case 48: return "DNSKEY";
        case 50: return "NSEC3";
        default: return "UNKNOWN";
    }
}

static void print_ipv4_rdata(const u_char *rdata, uint16_t rdlength) {
    if (rdlength == 4) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, rdata, ip, sizeof(ip));
        printf("    A: %s\n", ip);
    }
}

static void print_ipv6_rdata(const u_char *rdata, uint16_t rdlength) {
    if (rdlength == 16) {
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, rdata, ip, sizeof(ip));
        printf("    AAAA: %s\n", ip);
    }
}

static int print_domain_name_from_rdata(const u_char *payload, int payload_len, int rdata_offset) {
    char name[256];
    int nlen = dns_decode_name(payload + rdata_offset, payload, payload_len, name, sizeof(name));
    if (nlen < 0) return -1;
    printf("    Name: %s\n", name);
    return 0;
}

static int parse_and_print_rr(const char *section,
                              const u_char *payload,
                              int payload_len,
                              int *offset) {
    char name[256];
    int name_len = dns_decode_name(payload + *offset, payload, payload_len, name, sizeof(name));
    if (name_len < 0) { printf("Failed to decode RR name\n"); return -1; }
    int off = *offset + name_len;

    uint16_t type, classcode, rdlength;
    uint32_t ttl;
    if (safe_read_u16(payload, payload_len, off, &type) < 0) return -1; else off += 2;
    if (safe_read_u16(payload, payload_len, off, &classcode) < 0) return -1; else off += 2;
    if (safe_read_u32(payload, payload_len, off, &ttl) < 0) return -1; else off += 4;
    if (safe_read_u16(payload, payload_len, off, &rdlength) < 0) return -1; else off += 2;
    if (off + rdlength > payload_len) return -1;

    printf("%s RR:\n", section);
    printf("  Name: %s\n", name);
    printf("  Type: %s(%u)\n", rr_type_to_str(type), type);
    printf("  Class: %u\n", classcode);
    printf("  TTL: %u\n", ttl);
    printf("  RDLength: %u\n", rdlength);

    const u_char *rdata = payload + off;

    switch (type) {
        case 1: // A
            print_ipv4_rdata(rdata, rdlength);
            break;
        case 28: // AAAA
            print_ipv6_rdata(rdata, rdlength);
            break;
        case 2: // NS
        case 5: // CNAME
        case 12: // PTR
            if (print_domain_name_from_rdata(payload, payload_len, off) < 0) printf("    [name decode failed]\n");
            break;
        case 15: { // MX
            uint16_t pref;
            if (safe_read_u16(payload, payload_len, off, &pref) == 0) {
                printf("    Preference: %u\n", pref);
                if (print_domain_name_from_rdata(payload, payload_len, off + 2) < 0) printf("    [exchange decode failed]\n");
            }
            break;
        }
        case 16: { // TXT (may contain multiple strings)
            int r_off = 0;
            while (r_off < rdlength) {
                uint8_t slen = rdata[r_off++];
                if (r_off + slen > rdlength) break;
                printf("    TXT: ");
                for (int i = 0; i < slen; i++) putchar(isprint(rdata[r_off + i]) ? rdata[r_off + i] : '.');
                putchar('\n');
                r_off += slen;
            }
            break;
        }
        case 6: { // SOA
            // Skipping detailed SOA fields decoding for brevity
            break;
        }
        case 33: { // SRV
            uint16_t priority, weight, port;
            if (safe_read_u16(payload, payload_len, off, &priority) == 0 &&
                safe_read_u16(payload, payload_len, off + 2, &weight) == 0 &&
                safe_read_u16(payload, payload_len, off + 4, &port) == 0) {
                printf("    Priority: %u, Weight: %u, Port: %u\n", priority, weight, port);
                if (print_domain_name_from_rdata(payload, payload_len, off + 6) < 0) printf("    [target decode failed]\n");
            }
            break;
        }
        case 41: { // OPT (EDNS0)
            printf("    OPT record (EDNS0)\n");
            if (rdlength > 0) printf("    Options present (%u bytes)\n", rdlength);
            break;
        }
        default:
            if (rdlength > 0) {
                printf("    RDATA: %u bytes\n", rdlength);
            }
            break;
    }

    *offset = off + rdlength;
    return 0;
}

static void parse_dns_question(const u_char *buffer, const u_char *payload_start, int payload_len, int *offset) {
    char qname[256];
    int len = dns_decode_name(buffer, payload_start, payload_len, qname, sizeof(qname));
    if (len < 0) {
        printf("Failed to decode DNS question name\n");
        return;
    }
    printf("  Query Name: %s\n", qname);

    uint16_t qtype = 0, qclass = 0;
    int rel = (int)(buffer - payload_start);
    if (safe_read_u16(payload_start, payload_len, rel + len, &qtype) < 0) return;
    if (safe_read_u16(payload_start, payload_len, rel + len + 2, &qclass) < 0) return;

    printf("  Query Type: %u\n", qtype);
    printf("  Query Class: %u\n", qclass);

    *offset += len + 4; // name + type(2) + class(2)
}

void parse_dns_packet(const u_char *payload, int payload_len) {
    if (payload_len < sizeof(struct dns_header)) {
        printf("DNS packet too short\n");
        return;
    }

    struct dns_header *dns = (struct dns_header *)payload;

    printf("DNS Packet:\n");
    printf("Transaction ID: 0x%04x\n", ntohs(dns->id));
    print_dns_flags(ntohs(dns->flags));

    uint16_t qdcount = ntohs(dns->qdcount);
    uint16_t ancount = ntohs(dns->ancount);
    uint16_t nscount = ntohs(dns->nscount);
    uint16_t arcount = ntohs(dns->arcount);

    printf("Questions: %d\n", qdcount);
    printf("Answers: %d\n", ancount);
    printf("Authority Records: %d\n", nscount);
    printf("Additional Records: %d\n", arcount);

    int offset = sizeof(struct dns_header);
    for (int i = 0; i < qdcount; i++) {
        printf("Question %d:\n", i + 1);
        if (offset >= payload_len) { printf(" Truncated in questions\n"); return; }
        parse_dns_question(payload + offset, payload, payload_len, &offset);
    }

    if (((ntohs(dns->flags) >> 9) & 0x1) == 1) {
        printf("Note: TC bit set (message truncated). Some sections may be incomplete.\n");
    }

    for (int i = 0; i < ancount; i++) {
        if (offset >= payload_len) { printf(" Truncated in answers\n"); return; }
        if (parse_and_print_rr("Answer", payload, payload_len, &offset) < 0) { printf(" Failed to parse answer RR\n"); return; }
    }
    for (int i = 0; i < nscount; i++) {
        if (offset >= payload_len) { printf(" Truncated in authority\n"); return; }
        if (parse_and_print_rr("Authority", payload, payload_len, &offset) < 0) { printf(" Failed to parse authority RR\n"); return; }
    }
    for (int i = 0; i < arcount; i++) {
        if (offset >= payload_len) { printf(" Truncated in additional\n"); return; }
        if (parse_and_print_rr("Additional", payload, payload_len, &offset) < 0) { printf(" Failed to parse additional RR\n"); return; }
    }
}

#ifdef DNS_STANDALONE
#include <pcap.h>

#define ETHERNET_HEADER_LEN 14

static void dns_packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)user;
    if (header->caplen < ETHERNET_HEADER_LEN + (int)sizeof(struct ip)) return;

    const struct ip *ip_header = (const struct ip *)(packet + ETHERNET_HEADER_LEN);
    if (ip_header->ip_v != 4) return;
    int ip_header_len = ip_header->ip_hl * 4;
    if (header->caplen < ETHERNET_HEADER_LEN + ip_header_len + (int)sizeof(struct udphdr)) return;

    if (ip_header->ip_p != IPPROTO_UDP) return;
    const struct udphdr *udp_header = (const struct udphdr *)(packet + ETHERNET_HEADER_LEN + ip_header_len);
    uint16_t sport = ntohs(udp_header->uh_sport);
    uint16_t dport = ntohs(udp_header->uh_dport);
    if (sport != 53 && dport != 53) return;

    int udp_len = ntohs(udp_header->uh_ulen);
    if (udp_len < (int)sizeof(struct udphdr)) return;

    const u_char *dns_payload = packet + ETHERNET_HEADER_LEN + ip_header_len + sizeof(struct udphdr);
    int dns_payload_len = udp_len - (int)sizeof(struct udphdr);

    printf("\n=== DNS Packet Detected ===\n");
    parse_dns_packet(dns_payload, dns_payload_len);
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
    const char filter_exp[] = "udp port 53";
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

    printf("Capturing on device: %s\n", iface);
    printf("Waiting for DNS packets...\n");
    pcap_loop(handle, 0, dns_packet_handler, NULL);
    pcap_close(handle);
    return 0;
}
#endif
