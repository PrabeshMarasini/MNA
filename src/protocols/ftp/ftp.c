#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include "ftp.h"

// Global statistics
static ftp_stats_t g_stats = {0};

// Sensitive FTP commands that should be redacted
static const char *sensitive_commands[] = {
    "PASS", "USER", "ACCT", "AUTH", "ADAT", "PROT", "PBSZ", "CCC", NULL
};

// Common FTP commands for analysis
static const char *ftp_commands[] __attribute__((unused)) = {
    "ABOR", "ACCT", "ADAT", "ALLO", "APPE", "AUTH", "CCC", "CDUP", "CWD", "DELE",
    "EPRT", "EPSV", "FEAT", "HELP", "LIST", "MDTM", "MKD", "MLSD", "MLST", "MODE",
    "NLST", "NOOP", "OPTS", "PASS", "PASV", "PBSZ", "PORT", "PROT", "PWD", "QUIT",
    "REIN", "REST", "RETR", "RMD", "RNFR", "RNTO", "SITE", "SIZE", "SMNT", "STAT",
    "STOR", "STOU", "STRU", "SYST", "TYPE", "USER", "XCUP", "XCWD", "XMKD", "XPWD",
    "XRMD", NULL
};

int is_printable_ascii(const u_char *data, int len) {
    if (len == 0) return 0;
    int printable_count = 0;
    for (int i = 0; i < len; i++) {
        if ((data[i] >= 32 && data[i] <= 126) || data[i] == '\r' || data[i] == '\n' || data[i] == '\t') {
            printable_count++;
        }
    }
    return (printable_count * 100 / len) > 80; // 80% printable threshold
}

int is_sensitive_command(const char *command) {
    for (int i = 0; sensitive_commands[i] != NULL; i++) {
        if (strcasecmp(command, sensitive_commands[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

void redact_sensitive_data(char *line, const char *command) {
    if (is_sensitive_command(command)) {
        char *space = strchr(line, ' ');
        if (space) {
            strcpy(space + 1, "<redacted>");
        }
    }
}

void parse_ftp_command(const char *line) {
    char command[16] = {0};
    char argument[256] = {0};
    
    // Extract command and argument
    if (sscanf(line, "%15s %255[^\r\n]", command, argument) >= 1) {
        // Convert command to uppercase
        for (int i = 0; command[i]; i++) {
            command[i] = toupper(command[i]);
        }
        
        printf("  Command: %s", command);
        
        if (strlen(argument) > 0) {
            if (is_sensitive_command(command)) {
                printf(" <redacted>\n");
                if (strcasecmp(command, "USER") == 0) {
                    strncpy(g_stats.last_user, argument, sizeof(g_stats.last_user) - 1);
                    g_stats.login_attempts++;
                }
            } else {
                printf(" %s\n", argument);
                
                // Track file operations
                if (strcasecmp(command, "RETR") == 0 || strcasecmp(command, "STOR") == 0) {
                    strncpy(g_stats.last_file, argument, sizeof(g_stats.last_file) - 1);
                    g_stats.file_transfers++;
                } else if (strcasecmp(command, "PORT") == 0 || strcasecmp(command, "PASV") == 0 || 
                          strcasecmp(command, "EPRT") == 0 || strcasecmp(command, "EPSV") == 0) {
                    g_stats.data_connections++;
                }
            }
        } else {
            printf("\n");
        }
        
        g_stats.client_commands++;
    } else {
        printf("  Raw: %s\n", line);
    }
}

void parse_ftp_response(const char *line) {
    int code = 0;
    char message[512] = {0};
    
    // Parse FTP response code
    if (sscanf(line, "%d %511[^\r\n]", &code, message) >= 1) {
        printf("  Response: %d", code);
        
        if (strlen(message) > 0) {
            printf(" %s\n", message);
        } else {
            printf("\n");
        }
        
        // Analyze response codes
        if (code >= 200 && code < 300) {
            printf("  Status: Success\n");
        } else if (code >= 300 && code < 400) {
            printf("  Status: Intermediate (more info needed)\n");
        } else if (code >= 400 && code < 500) {
            printf("  Status: Temporary failure\n");
        } else if (code >= 500 && code < 600) {
            printf("  Status: Permanent failure\n");
        }
        
        // Track login success/failure
        if (code == 230) {
            printf("  -> LOGIN SUCCESSFUL for user: %s\n", g_stats.last_user);
        } else if (code == 530) {
            printf("  -> LOGIN FAILED\n");
        }
        
        g_stats.server_responses++;
    } else {
        // Handle multiline responses or continuation
        if (strlen(line) > 3 && line[3] == '-') {
            printf("  Multiline: %s\n", line);
        } else {
            printf("  Raw: %s\n", line);
        }
    }
}

void parse_ftp(const u_char *payload, int payload_len, int src_port, int dst_port) {
    // FTP control channel runs on port 21
    if (src_port != 21 && dst_port != 21) return;
    
    if (!is_printable_ascii(payload, payload_len)) return;
    
    // Update statistics
    g_stats.total_packets++;
    
    // Print timestamp
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    printf("\n[%02d:%02d:%02d] ", tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
    
    printf("=== FTP Packet #%lu ===\n", g_stats.total_packets);
    
    // Determine direction
    int is_server_response = (src_port == 21);
    printf("Direction: %s\n", is_server_response ? "Server -> Client" : "Client -> Server");
    
    // Copy payload to buffer for processing
    char buffer[2048];
    int copy_len = (payload_len < 2047) ? payload_len : 2047;
    memcpy(buffer, payload, copy_len);
    buffer[copy_len] = '\0';
    
    // Process each line
    char *saveptr = NULL;
    char *line = strtok_r(buffer, "\r\n", &saveptr);
    while (line != NULL) {
        if (strlen(line) > 0) {
            if (is_server_response) {
                parse_ftp_response(line);
            } else {
                parse_ftp_command(line);
            }
        }
        line = strtok_r(NULL, "\r\n", &saveptr);
    }
    
    printf("========================\n");
}

void print_ftp_stats(void) {
    printf("\n--- FTP Traffic Statistics ---\n");
    printf("Total Packets: %lu\n", g_stats.total_packets);
    printf("Client Commands: %lu\n", g_stats.client_commands);
    printf("Server Responses: %lu\n", g_stats.server_responses);
    printf("Login Attempts: %lu\n", g_stats.login_attempts);
    printf("File Transfers: %lu\n", g_stats.file_transfers);
    printf("Data Connections: %lu\n", g_stats.data_connections);
    if (strlen(g_stats.last_user) > 0) {
        printf("Last User: %s\n", g_stats.last_user);
    }
    if (strlen(g_stats.last_file) > 0) {
        printf("Last File: %s\n", g_stats.last_file);
    }
    printf("-----------------------------\n\n");
}

void reset_ftp_stats(void) {
    memset(&g_stats, 0, sizeof(g_stats));
}
#ifdef FTP_STANDALONE
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>

#define SNAP_LEN 65535
#define TIMEOUT_MS 1000

static pcap_t *g_handle = NULL;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args;
    
    // Check minimum packet size
    if (header->caplen < sizeof(struct ether_header)) return;
    
    const struct ether_header *eth_header = (struct ether_header *)packet;
    
    // Check if it's IPv4
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) return;
    
    // Check minimum IP header size
    if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip)) return;
    
    const struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    
    // Validate IP version and protocol (TCP for FTP)
    if (ip_header->ip_v != 4 || ip_header->ip_p != IPPROTO_TCP) return;
    
    int ip_header_len = ip_header->ip_hl * 4;
    int tcp_offset = sizeof(struct ether_header) + ip_header_len;
    
    if (header->caplen < tcp_offset + sizeof(struct tcphdr)) return;
    
    const struct tcphdr *tcp_header = (struct tcphdr *)(packet + tcp_offset);
    int tcp_header_len = tcp_header->doff * 4;
    int payload_offset = tcp_offset + tcp_header_len;
    
    if (header->caplen <= payload_offset) return; // No payload
    
    const u_char *payload = packet + payload_offset;
    int payload_len = header->caplen - payload_offset;
    
    int src_port = ntohs(tcp_header->source);
    int dst_port = ntohs(tcp_header->dest);
    
    // Parse FTP packet
    parse_ftp(payload, payload_len, src_port, dst_port);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *device;
    
    // Find all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }
    
    // Use first device
    device = alldevs;
    if (!device) {
        fprintf(stderr, "No devices found.\n");
        return 1;
    }
    
    printf("Using device: %s\n", device->name);
    
    // Open device for capture
    g_handle = pcap_open_live(device->name, SNAP_LEN, 1, TIMEOUT_MS, errbuf);
    if (!g_handle) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device->name, errbuf);
        return 1;
    }
    
    // Filter only FTP packets (TCP port 21)
    struct bpf_program fp;
    if (pcap_compile(g_handle, &fp, "tcp port 21", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(g_handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter.\n");
        return 1;
    }
    
    printf("Listening for FTP packets on port 21...\n");
    
    // Initialize stats
    reset_ftp_stats();
    
    // Start packet capture loop (Ctrl+C to stop)
    pcap_loop(g_handle, 0, packet_handler, NULL);
    
    // Cleanup
    pcap_freealldevs(alldevs);
    pcap_close(g_handle);
    return 0;
}
#endif