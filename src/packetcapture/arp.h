#ifndef ARP_H
#define ARP_H

#include <net/if.h> 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <fcntl.h>
#include <errno.h>
#include "device_scanner.h"

#define MAC_LEN 6
#define MAX_TARGETS 150

typedef struct {
    unsigned char mac[MAC_LEN];
    unsigned char ip[4];
    int active;
} target_info_t;

// Callback function type for packet capture
typedef void (*packet_callback_t)(const unsigned char *packet_data, int packet_len, int target_index);

extern unsigned char attacker_mac[MAC_LEN];
extern unsigned char spoof_ip[4];
extern char iface_name[IFNAMSIZ];
extern int ifindex;
extern target_info_t targets[MAX_TARGETS];
extern int target_count;
extern packet_callback_t packet_callback;

int parse_mac(const char *mac_str, unsigned char *mac_bytes);
void get_attacker_mac(const char *iface, unsigned char *mac);
void str_to_ip(const char *ip_str, unsigned char *ip_bytes);
void get_interface_index(const char *iface, int *index);
void setup_targets(scan_result_t *scan_result, int *target_indices, int count);
void set_packet_callback(packet_callback_t callback);
void request_arp_shutdown(void);
void *arp_spoof_thread(void *arg);
void *sniff_thread(void *arg);

#endif // ARP_H