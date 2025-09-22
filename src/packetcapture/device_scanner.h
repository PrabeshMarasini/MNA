#ifndef DEVICE_SCANNER_H
#define DEVICE_SCANNER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DEVICES 150
#define MAX_IP_LEN 16
#define MAC_LEN 6

typedef struct {
    char ip[MAX_IP_LEN];
    unsigned char mac[MAC_LEN];
    int is_gateway;
} device_t;

typedef struct {
    device_t devices[MAX_DEVICES];
    int count;
    char gateway_ip[MAX_IP_LEN];
    char interface[16];
} scan_result_t;

int run_lan_scan(scan_result_t *result);
void display_devices(scan_result_t *result);
int select_targets(scan_result_t *result, int *target_indices, int max_targets);
int parse_selection(const char *input, int *indices, int max_count);

#endif // DEVICE_SCANNER_H