#include "device_scanner.h"
#include <unistd.h>

int parse_mac_string(const char *mac_str, unsigned char *mac_bytes) {
    return sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac_bytes[0], &mac_bytes[1], &mac_bytes[2],
                  &mac_bytes[3], &mac_bytes[4], &mac_bytes[5]) == 6;
}

int run_lan_scan(scan_result_t *result) {
    FILE *fp;
    char line[256];
    int section = 0; // 0=your device, 1=gateway, 2=other devices
    
    result->count = 0;
    
    // Run the lan_scan.sh script
    fp = popen("src/packetcapture/lan_scan.sh", "r");
    if (fp == NULL) {
        printf("Error: Could not run lan_scan.sh\n");
        printf("Make sure lan_scan.sh is in the current directory and executable\n");
        return -1;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        // Skip empty lines and headers
        if (strstr(line, "Your Device:") || strstr(line, "IPV4") || 
            strstr(line, "Scan complete") || strlen(line) < 10) {
            continue;
        }
        
        if (strstr(line, "Gateway (Router):")) {
            section = 1;
            continue;
        }
        
        if (strstr(line, "Other Devices:")) {
            section = 2;
            continue;
        }
        
        // Parse IP and MAC from line
        char ip_str[MAX_IP_LEN];
        char mac_str[18];
        if (sscanf(line, "%15s %17s", ip_str, mac_str) == 2) {
            if (result->count < MAX_DEVICES) {
                strcpy(result->devices[result->count].ip, ip_str);
                if (parse_mac_string(mac_str, result->devices[result->count].mac)) {
                    result->devices[result->count].is_gateway = (section == 1);
                    if (section == 1) {
                        strcpy(result->gateway_ip, ip_str);
                    }
                    result->count++;
                }
            }
        }
    }
    
    pclose(fp);
    
    // Get interface name
    fp = popen("ip route | grep '^default' | awk '{print $5}' | head -n1", "r");
    if (fp && fgets(result->interface, sizeof(result->interface), fp)) {
        // Remove newline
        result->interface[strcspn(result->interface, "\n")] = 0;
    }
    if (fp) pclose(fp);
    
    return result->count;
}

void display_devices(scan_result_t *result) {
    printf("\n=== Available Devices ===\n");
    printf("Interface: %s\n", result->interface);
    printf("Gateway IP: %s\n\n", result->gateway_ip);
    
    for (int i = 0; i < result->count; i++) {
        printf("%d: %s", i + 1, result->devices[i].ip);
        printf(" (%02x:%02x:%02x:%02x:%02x:%02x)", 
               result->devices[i].mac[0], result->devices[i].mac[1],
               result->devices[i].mac[2], result->devices[i].mac[3],
               result->devices[i].mac[4], result->devices[i].mac[5]);
        if (result->devices[i].is_gateway) {
            printf(" [GATEWAY]");
        }
        printf("\n");
    }
    printf("%d: ALL DEVICES\n", result->count + 1);
}

int parse_selection(const char *input, int *indices, int max_count) {
    char *input_copy = strdup(input);
    if (!input_copy) return 0;
    
    char *token = strtok(input_copy, " ,");
    int count = 0;
    
    while (token && count < max_count) {
        int num = atoi(token);
        if (num > 0) {
            int index = num - 1; // Convert to 0-based index
            // Validate index bounds
            if (index >= 0 && index < MAX_DEVICES) {
                indices[count++] = index;
            }
        }
        token = strtok(NULL, " ,");
    }
    
    free(input_copy);
    return count;
}

int select_targets(scan_result_t *result, int *target_indices, int max_targets) {
    char input[256];
    
    printf("\nSelect targets (e.g., '1 3 5' or '1' or '%d' for all): ", result->count + 1);
    fflush(stdout);
    
    if (!fgets(input, sizeof(input), stdin)) {
        return 0;
    }
    
    // Remove newline
    input[strcspn(input, "\n")] = 0;
    
    // Check if user selected "all"
    int all_option = result->count + 1;
    if (atoi(input) == all_option) {
        int count_to_select = (result->count > max_targets) ? max_targets : result->count;
        for (int i = 0; i < count_to_select; i++) {
            target_indices[i] = i;
        }
        if (result->count > max_targets) {
            printf("Warning: Limited to %d targets (max supported)\n", max_targets);
        }
        return count_to_select;
    }
    
    // Parse individual selections
    int selected = parse_selection(input, target_indices, max_targets);
    if (selected > max_targets) {
        printf("Warning: Limited to %d targets (max supported)\n", max_targets);
        return max_targets;
    }
    return selected;
}