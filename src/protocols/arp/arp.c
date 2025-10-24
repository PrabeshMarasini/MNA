#include <stdio.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "arp.h"

// Simple IP->MAC table to flag changes (potential ARP poisoning)
#define ARP_SEEN_MAX 64
struct arp_seen_entry {
    uint32_t ip_be; // IPv4 in network byte order
    unsigned char mac[6];
    int in_use;
};
static struct arp_seen_entry arp_seen[ARP_SEEN_MAX];

// Simple MAC->IP table to flag a MAC claiming many IPs
struct mac_seen_entry {
    unsigned char mac[6];
    uint32_t ip_be; // last IP observed for this MAC
    int in_use;
};
static struct mac_seen_entry mac_seen[ARP_SEEN_MAX];

// Track potential ARP scans: unique targets queried by a given source MAC
struct scan_entry {
    unsigned char mac[6];
    uint32_t targets[16]; // up to 16 unique targets tracked
    int in_use;
};
static struct scan_entry scan_table[ARP_SEEN_MAX];

static void mac_to_str(const unsigned char *m, char *out, size_t outlen) {
    snprintf(out, outlen, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

#ifdef ARP_STANDALONE
#define SNAP_LEN 1518

static void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;
    parse_arp(packet, header->caplen);
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

    pcap_t *handle = pcap_open_live(iface, SNAP_LEN, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open device %s: %s\n", iface, errbuf);
        return 1;
    }

    struct bpf_program fp;
    const char filter[] = "arp or (vlan and arp)";
    if (pcap_compile(handle, &fp, filter, 0, 0) == -1 || pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "BPF error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    printf("Listening for ARP on %s...\n", iface);
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}
#endif

static void arp_seen_update(uint32_t ip_be, const unsigned char *mac) {
    // Look for existing
    for (int i = 0; i < ARP_SEEN_MAX; i++) {
        if (arp_seen[i].in_use && arp_seen[i].ip_be == ip_be) {
            if (memcmp(arp_seen[i].mac, mac, 6) != 0) {
                char oldm[18], newm[18];
                mac_to_str(arp_seen[i].mac, oldm, sizeof(oldm));
                mac_to_str(mac, newm, sizeof(newm));
                struct in_addr a; a.s_addr = ip_be;
                printf("[Alert] ARP mapping change for %s: %s -> %s\n",
                       inet_ntoa(a), oldm, newm);
                memcpy(arp_seen[i].mac, mac, 6);
            }
            return;
        }
    }
    // Insert new
    for (int i = 0; i < ARP_SEEN_MAX; i++) {
        if (!arp_seen[i].in_use) {
            arp_seen[i].in_use = 1;
            arp_seen[i].ip_be = ip_be;
            memcpy(arp_seen[i].mac, mac, 6);
            return;
        }
    }
}

static int find_arp_offset(const u_char *packet, int packet_len, int *vlan_ids, int *vlan_count) {
    // Expect Ethernet header
    if (packet_len < (int)sizeof(struct ethhdr)) return -1;
    const struct ethhdr *eth = (const struct ethhdr *)packet;
    uint16_t ethertype = ntohs(eth->h_proto);
    int offset = sizeof(struct ethhdr);
    // VLAN tags (802.1Q / 802.1ad)
    if (vlan_count) *vlan_count = 0;
    if (ethertype == 0x8100 || ethertype == 0x88A8) {
        if (packet_len < offset + 4) return -1;
        if (vlan_ids) vlan_ids[0] = ntohs(*(const uint16_t *)(packet + offset)) & 0x0FFF;
        ethertype = ntohs(*(const uint16_t *)(packet + offset + 2));
        offset += 4;
        if (vlan_count) *vlan_count = 1;
        // Double VLAN (QinQ)
        if (ethertype == 0x8100 || ethertype == 0x88A8) {
            if (packet_len < offset + 4) return -1;
            if (vlan_ids) vlan_ids[1] = ntohs(*(const uint16_t *)(packet + offset)) & 0x0FFF;
            ethertype = ntohs(*(const uint16_t *)(packet + offset + 2));
            offset += 4;
            if (vlan_count) *vlan_count = 2;
        }
    }
    if (ethertype != ETH_P_ARP) return -1;
    if (packet_len < offset + (int)sizeof(struct ether_arp)) return -1;
    return offset;
}

void parse_arp(const u_char *packet, int packet_len) {
    int vlan_ids[2] = {0, 0};
    int vlan_count = 0;
    int off = find_arp_offset(packet, packet_len, vlan_ids, &vlan_count);
    if (off < 0) return;

    const struct ether_arp *arp = (const struct ether_arp *)(packet + off);

    // Validate classic IPv4 ARP
    uint16_t hrd = ntohs(arp->ea_hdr.ar_hrd);
    uint16_t pro = ntohs(arp->ea_hdr.ar_pro);
    unsigned char hln = arp->ea_hdr.ar_hln;
    unsigned char pln = arp->ea_hdr.ar_pln;
    uint16_t op = ntohs(arp->ea_hdr.ar_op);
    if (!(hrd == ARPHRD_ETHER && pro == ETH_P_IP && hln == 6 && pln == 4)) {
        printf("ARP (non-IPv4 or non-Ethernet): hrd=%u pro=0x%04x hln=%u pln=%u op=%u\n",
               hrd, pro, hln, pln, op);
        return;
    }

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp->arp_spa, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, arp->arp_tpa, dst_ip, sizeof(dst_ip));

    char sha[18], tha[18];
    mac_to_str(arp->arp_sha, sha, sizeof(sha));
    mac_to_str(arp->arp_tha, tha, sizeof(tha));

    int gratuitous = (memcmp(arp->arp_spa, arp->arp_tpa, 4) == 0);
    int probe = (op == ARPOP_REQUEST && *(const uint32_t *)arp->arp_spa == 0);
    int target_mac_zero = (arp->arp_tha[0]|arp->arp_tha[1]|arp->arp_tha[2]|arp->arp_tha[3]|arp->arp_tha[4]|arp->arp_tha[5]) == 0;

    if (op == ARPOP_REQUEST) {
        if (vlan_count == 1) printf("VLAN %d: ", vlan_ids[0]);
        else if (vlan_count == 2) printf("VLAN %d/%d: ", vlan_ids[0], vlan_ids[1]);
        printf("ARP who-has %s tell %s (%s)%s%s\n",
               dst_ip,
               src_ip,
               sha,
               probe ? " [probe]" : "",
               (!target_mac_zero ? " [warn: target MAC set in request]" : ""));
        // Update scan table: count unique targets per source MAC
        for (int i = 0; i < ARP_SEEN_MAX; i++) {
            if (scan_table[i].in_use && memcmp(scan_table[i].mac, arp->arp_sha, 6) == 0) {
                uint32_t tip; memcpy(&tip, arp->arp_tpa, 4);
                int known = 0;
                for (int j = 0; j < 16; j++) if (scan_table[i].targets[j] == tip) { known = 1; break; }
                if (!known) {
                    for (int j = 0; j < 16; j++) if (scan_table[i].targets[j] == 0) { scan_table[i].targets[j] = tip; break; }
                    int unique = 0; for (int j = 0; j < 16; j++) if (scan_table[i].targets[j] != 0) unique++;
                    if (unique >= 10) {
                        printf("[Notice] %s sent ARP requests to %d+ unique targets (possible scan)\n", sha, unique);
                    }
                }
                goto scan_done;
            }
        }
        for (int i = 0; i < ARP_SEEN_MAX; i++) {
            if (!scan_table[i].in_use) {
                scan_table[i].in_use = 1;
                memcpy(scan_table[i].mac, arp->arp_sha, 6);
                memcpy(&scan_table[i].targets[0], arp->arp_tpa, 4);
                break;
            }
        }
scan_done:
    } else if (op == ARPOP_REPLY) {
        if (vlan_count == 1) printf("VLAN %d: ", vlan_ids[0]);
        else if (vlan_count == 2) printf("VLAN %d/%d: ", vlan_ids[0], vlan_ids[1]);
        printf("ARP %s is-at %s%s%s\n",
               src_ip,
               sha,
               gratuitous ? " [gratuitous]" : "",
               target_mac_zero ? " [warn: target MAC zero in reply]" : "");
        // Update seen table on replies
        uint32_t ip_be; memcpy(&ip_be, arp->arp_spa, 4);
        arp_seen_update(ip_be, arp->arp_sha);
        // MAC->IP observation (flag MAC claiming many different IPs)
        for (int i = 0; i < ARP_SEEN_MAX; i++) {
            if (mac_seen[i].in_use && memcmp(mac_seen[i].mac, arp->arp_sha, 6) == 0) {
                if (mac_seen[i].ip_be != ip_be) {
                    struct in_addr a; a.s_addr = mac_seen[i].ip_be;
                    printf("[Notice] %s now also claims %s (was %s)\n", sha, src_ip, inet_ntoa(a));
                    mac_seen[i].ip_be = ip_be;
                }
                goto mac_done;
            }
        }
        for (int i = 0; i < ARP_SEEN_MAX; i++) {
            if (!mac_seen[i].in_use) {
                mac_seen[i].in_use = 1;
                memcpy(mac_seen[i].mac, arp->arp_sha, 6);
                mac_seen[i].ip_be = ip_be;
                break;
            }
        }
mac_done:;
    } else {
        if (vlan_count == 1) printf("VLAN %d: ", vlan_ids[0]);
        else if (vlan_count == 2) printf("VLAN %d/%d: ", vlan_ids[0], vlan_ids[1]);
        printf("ARP op %u from %s (%s) to %s (%s)%s\n", op, src_ip, sha, dst_ip, tha, gratuitous ? " [gratuitous]" : "");
    }
}
