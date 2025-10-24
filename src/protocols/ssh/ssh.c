#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "ssh.h"

// Global connection tracking (simplified for demo)
static ssh_connection_t ssh_connections[100] __attribute__((unused));
static int connection_count __attribute__((unused)) = 0;

// Main SSH parser function
void parse_ssh(const u_char *payload, int payload_len, int src_port, int dst_port) {
    if (src_port != SSH_PORT && dst_port != SSH_PORT) return;
    if (payload_len < 4) return;

    printf("=== SSH Packet ===\n");
    printf("Ports: %d -> %d\n", src_port, dst_port);
    printf("Length: %d bytes\n", payload_len);

    // Check if this is version exchange (plaintext)
    if (payload_len > 4 && memcmp(payload, "SSH-", 4) == 0) {
        parse_ssh_version_exchange(payload, payload_len, src_port, dst_port);
    } else if (payload_len >= SSH_PACKET_MIN_SIZE) {
        // Binary SSH packet (encrypted or key exchange)
        parse_ssh_binary_packet(payload, payload_len, src_port, dst_port);
    }

    printf("==================\n");
}

// Parse SSH version exchange
void parse_ssh_version_exchange(const u_char *payload, int payload_len, int src_port, int dst_port) {
    (void)dst_port; // Suppress unused parameter warning
    char version_string[SSH_VERSION_EXCHANGE_MAX + 1];
    int copy_len = (payload_len < SSH_VERSION_EXCHANGE_MAX) ? payload_len : SSH_VERSION_EXCHANGE_MAX;
    
    // Find end of line
    int line_end = 0;
    for (int i = 0; i < copy_len; i++) {
        if (payload[i] == '\r' || payload[i] == '\n') {
            line_end = i;
            break;
        }
    }
    if (line_end == 0) line_end = copy_len;

    memcpy(version_string, payload, line_end);
    version_string[line_end] = '\0';

    printf("Type: Version Exchange\n");
    printf("Direction: %s\n", (src_port == SSH_PORT) ? "Server -> Client" : "Client -> Server");
    printf("Version String: %s\n", version_string);

    // Parse version components
    if (strncmp(version_string, "SSH-2.0-", 8) == 0) {
        printf("Protocol Version: 2.0\n");
        printf("Software: %s\n", version_string + 8);
    } else if (strncmp(version_string, "SSH-1.99-", 9) == 0) {
        printf("Protocol Version: 1.99 (compatible with 2.0)\n");
        printf("Software: %s\n", version_string + 9);
    } else if (strncmp(version_string, "SSH-1.5-", 8) == 0) {
        printf("Protocol Version: 1.5 (deprecated)\n");
        printf("Software: %s\n", version_string + 8);
        printf("WARNING: SSH 1.5 has known security vulnerabilities\n");
    }

    // Detect common SSH implementations
    if (strstr(version_string, "OpenSSH")) {
        printf("Implementation: OpenSSH\n");
    } else if (strstr(version_string, "libssh")) {
        printf("Implementation: libssh\n");
    } else if (strstr(version_string, "PuTTY")) {
        printf("Implementation: PuTTY\n");
    } else if (strstr(version_string, "Cisco")) {
        printf("Implementation: Cisco SSH\n");
    }
}

// Parse SSH binary packet
void parse_ssh_binary_packet(const u_char *payload, int payload_len, int src_port, int dst_port) {
    (void)dst_port; // Suppress unused parameter warning
    // SSH binary packet format:
    // uint32 packet_length
    // byte padding_length
    // byte[n1] payload
    // byte[n2] random padding

    if (payload_len < 5) return;

    uint32_t packet_length = ntohl(*(uint32_t*)payload);
    uint8_t padding_length = payload[4];

    printf("Type: Binary Packet\n");
    printf("Direction: %s\n", (src_port == SSH_PORT) ? "Server -> Client" : "Client -> Server");
    printf("Packet Length: %u\n", packet_length);
    printf("Padding Length: %u\n", padding_length);

    // Calculate payload length
    int ssh_payload_len = packet_length - padding_length - 1;
    if (ssh_payload_len <= 0 || ssh_payload_len > payload_len - 5) {
        printf("Status: Encrypted/Invalid packet structure\n");
        return;
    }

    // Get message type (first byte of payload)
    uint8_t msg_type = payload[5];
    printf("Message Type: %u (%s)\n", msg_type, get_ssh_message_type_name(msg_type));

    // Parse specific message types
    switch (msg_type) {
        case SSH_MSG_KEXINIT:
            parse_ssh_kexinit(payload + 5, ssh_payload_len);
            break;
        case SSH_MSG_USERAUTH_REQUEST:
        case SSH_MSG_USERAUTH_FAILURE:
        case SSH_MSG_USERAUTH_SUCCESS:
            parse_ssh_userauth(payload + 5, ssh_payload_len, msg_type);
            break;
        case SSH_MSG_CHANNEL_DATA:
        case SSH_MSG_CHANNEL_EXTENDED_DATA:
            parse_ssh_channel_data(payload + 5, ssh_payload_len);
            break;
        case SSH_MSG_DISCONNECT:
            if (ssh_payload_len >= 5) {
                uint32_t reason = ntohl(*(uint32_t*)(payload + 6));
                printf("Disconnect Reason: %u (%s)\n", reason, get_ssh_disconnect_reason(reason));
            }
            break;
    }
}

// Parse SSH KEXINIT message
void parse_ssh_kexinit(const u_char *payload, int payload_len) {
    if (payload_len < 17) return; // Minimum KEXINIT size

    printf("Key Exchange Initialization:\n");
    
    // Skip message type (1 byte) and random bytes (16 bytes)
    const u_char *data = payload + 17;
    int remaining = payload_len - 17;

    // Parse algorithm lists
    const char* algorithm_types[] = {
        "Key Exchange", "Server Host Key", "Encryption C->S", "Encryption S->C",
        "MAC C->S", "MAC S->C", "Compression C->S", "Compression S->C",
        "Languages C->S", "Languages S->C"
    };

    for (int i = 0; i < 10 && remaining >= 4; i++) {
        uint32_t list_len = ntohl(*(uint32_t*)data);
        data += 4;
        remaining -= 4;

        if (list_len > 0 && list_len <= (uint32_t)remaining) {
            print_ssh_algorithms(data, list_len, algorithm_types[i]);
            data += list_len;
            remaining -= list_len;
        }
    }
}

// Parse SSH authentication messages
void parse_ssh_userauth(const u_char *payload, int payload_len, uint8_t msg_type) {
    if (payload_len < 2) return;

    switch (msg_type) {
        case SSH_MSG_USERAUTH_REQUEST:
            printf("Authentication Request:\n");
            // Parse username, service, method
            if (payload_len > 5) {
                const u_char *data = payload + 1;
                int remaining = payload_len - 1;
                
                // Username length and value
                if (remaining >= 4) {
                    uint32_t username_len = ntohl(*(uint32_t*)data);
                    data += 4;
                    remaining -= 4;
                    
                    if (username_len > 0 && username_len <= (uint32_t)remaining && username_len < 64) {
                        char username[65];
                        memcpy(username, data, username_len);
                        username[username_len] = '\0';
                        printf("  Username: %s\n", username);
                        data += username_len;
                        remaining -= username_len;
                    }
                }
                
                // Service name
                if (remaining >= 4) {
                    uint32_t service_len = ntohl(*(uint32_t*)data);
                    data += 4;
                    remaining -= 4;
                    
                    if (service_len > 0 && service_len <= (uint32_t)remaining && service_len < 32) {
                        char service[33];
                        memcpy(service, data, service_len);
                        service[service_len] = '\0';
                        printf("  Service: %s\n", service);
                        data += service_len;
                        remaining -= service_len;
                    }
                }
                
                // Authentication method
                if (remaining >= 4) {
                    uint32_t method_len = ntohl(*(uint32_t*)data);
                    data += 4;
                    remaining -= 4;
                    
                    if (method_len > 0 && method_len <= (uint32_t)remaining && method_len < 32) {
                        char method[33];
                        memcpy(method, data, method_len);
                        method[method_len] = '\0';
                        printf("  Method: %s\n", method);
                    }
                }
            }
            break;
            
        case SSH_MSG_USERAUTH_FAILURE:
            printf("Authentication Failed\n");
            if (payload_len > 5) {
                const u_char *data = payload + 1;
                uint32_t methods_len = ntohl(*(uint32_t*)data);
                if (methods_len > 0 && methods_len < (uint32_t)(payload_len - 5)) {
                    char methods[256];
                    int copy_len = (methods_len < 255) ? methods_len : 255;
                    memcpy(methods, data + 4, copy_len);
                    methods[copy_len] = '\0';
                    printf("  Available Methods: %s\n", methods);
                }
            }
            break;
            
        case SSH_MSG_USERAUTH_SUCCESS:
            printf("Authentication Successful\n");
            break;
    }
}

// Parse SSH channel data
void parse_ssh_channel_data(const u_char *payload, int payload_len) {
    if (payload_len < 9) return;

    uint32_t channel = ntohl(*(uint32_t*)(payload + 1));
    uint32_t data_len = ntohl(*(uint32_t*)(payload + 5));

    printf("Channel Data:\n");
    printf("  Channel: %u\n", channel);
    printf("  Data Length: %u bytes\n", data_len);

    if (data_len > 0 && data_len <= (uint32_t)(payload_len - 9)) {
        printf("  Data Preview: ");
        int preview_len = (data_len < 32) ? data_len : 32;
        for (int i = 0; i < preview_len; i++) {
            char c = payload[9 + i];
            if (c >= 32 && c <= 126) {
                printf("%c", c);
            } else {
                printf(".");
            }
        }
        if (data_len > 32) printf("...");
        printf("\n");
    }
}

// Get SSH message type name
const char* get_ssh_message_type_name(uint8_t msg_type) {
    switch (msg_type) {
        case SSH_MSG_DISCONNECT: return "DISCONNECT";
        case SSH_MSG_IGNORE: return "IGNORE";
        case SSH_MSG_UNIMPLEMENTED: return "UNIMPLEMENTED";
        case SSH_MSG_DEBUG: return "DEBUG";
        case SSH_MSG_SERVICE_REQUEST: return "SERVICE_REQUEST";
        case SSH_MSG_SERVICE_ACCEPT: return "SERVICE_ACCEPT";
        case SSH_MSG_KEXINIT: return "KEXINIT";
        case SSH_MSG_NEWKEYS: return "NEWKEYS";
        case SSH_MSG_KEXDH_INIT: return "KEXDH_INIT";
        case SSH_MSG_KEXDH_REPLY: return "KEXDH_REPLY";
        case SSH_MSG_USERAUTH_REQUEST: return "USERAUTH_REQUEST";
        case SSH_MSG_USERAUTH_FAILURE: return "USERAUTH_FAILURE";
        case SSH_MSG_USERAUTH_SUCCESS: return "USERAUTH_SUCCESS";
        case SSH_MSG_USERAUTH_BANNER: return "USERAUTH_BANNER";
        case SSH_MSG_GLOBAL_REQUEST: return "GLOBAL_REQUEST";
        case SSH_MSG_REQUEST_SUCCESS: return "REQUEST_SUCCESS";
        case SSH_MSG_REQUEST_FAILURE: return "REQUEST_FAILURE";
        case SSH_MSG_CHANNEL_OPEN: return "CHANNEL_OPEN";
        case SSH_MSG_CHANNEL_OPEN_CONFIRMATION: return "CHANNEL_OPEN_CONFIRMATION";
        case SSH_MSG_CHANNEL_OPEN_FAILURE: return "CHANNEL_OPEN_FAILURE";
        case SSH_MSG_CHANNEL_WINDOW_ADJUST: return "CHANNEL_WINDOW_ADJUST";
        case SSH_MSG_CHANNEL_DATA: return "CHANNEL_DATA";
        case SSH_MSG_CHANNEL_EXTENDED_DATA: return "CHANNEL_EXTENDED_DATA";
        case SSH_MSG_CHANNEL_EOF: return "CHANNEL_EOF";
        case SSH_MSG_CHANNEL_CLOSE: return "CHANNEL_CLOSE";
        case SSH_MSG_CHANNEL_REQUEST: return "CHANNEL_REQUEST";
        case SSH_MSG_CHANNEL_SUCCESS: return "CHANNEL_SUCCESS";
        case SSH_MSG_CHANNEL_FAILURE: return "CHANNEL_FAILURE";
        default: return "UNKNOWN";
    }
}

// Get SSH disconnect reason
const char* get_ssh_disconnect_reason(uint32_t reason_code) {
    switch (reason_code) {
        case 1: return "HOST_NOT_ALLOWED_TO_CONNECT";
        case 2: return "PROTOCOL_ERROR";
        case 3: return "KEY_EXCHANGE_FAILED";
        case 4: return "RESERVED";
        case 5: return "MAC_ERROR";
        case 6: return "COMPRESSION_ERROR";
        case 7: return "SERVICE_NOT_AVAILABLE";
        case 8: return "PROTOCOL_VERSION_NOT_SUPPORTED";
        case 9: return "HOST_KEY_NOT_VERIFIABLE";
        case 10: return "CONNECTION_LOST";
        case 11: return "BY_APPLICATION";
        case 12: return "TOO_MANY_CONNECTIONS";
        case 13: return "AUTH_CANCELLED_BY_USER";
        case 14: return "NO_MORE_AUTH_METHODS_AVAILABLE";
        case 15: return "ILLEGAL_USER_NAME";
        default: return "UNKNOWN";
    }
}

// Print SSH algorithm lists
void print_ssh_algorithms(const u_char *data, int len, const char *type) {
    if (len <= 0) return;
    
    char algorithms[512];
    int copy_len = (len < 511) ? len : 511;
    memcpy(algorithms, data, copy_len);
    algorithms[copy_len] = '\0';
    
    printf("  %s: %s\n", type, algorithms);
}

// Redact sensitive SSH data
void redact_sensitive_ssh_data(char *data, int len) {
    // Simple redaction for passwords and keys
    for (int i = 0; i < len - 8; i++) {
        if (strncasecmp(data + i, "password", 8) == 0) {
            memset(data + i, '*', 8);
        }
    }
}

#ifdef SSH_STANDALONE
// Standalone mode for testing
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        
        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));
            
            int src_port = ntohs(tcp_header->th_sport);
            int dst_port = ntohs(tcp_header->th_dport);
            
            if (src_port == SSH_PORT || dst_port == SSH_PORT) {
                int tcp_header_len = tcp_header->th_off * 4;
                const u_char *payload = packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4) + tcp_header_len;
                int payload_len = ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4) - tcp_header_len;
                
                if (payload_len > 0) {
                    parse_ssh(payload, payload_len, src_port, dst_port);
                }
            }
        }
    }
}

int main(int argc, char *argv[]) {
    printf("SSH Protocol Analyzer - Standalone Mode\n");
    printf("Listening for SSH traffic on port %d...\n\n", SSH_PORT);
    
    if (argc > 1) {
        // Test with sample SSH version exchange
        printf("Testing with sample SSH version exchange:\n");
        const char *sample_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1";
        parse_ssh((const u_char*)sample_version, strlen(sample_version), 12345, SSH_PORT);
        
        // Test with sample binary packet (KEXINIT simulation)
        printf("\nTesting with sample SSH binary packet:\n");
        u_char sample_packet[] = {
            0x00, 0x00, 0x01, 0x2c,  // packet length (300)
            0x06,                     // padding length
            0x14,                     // SSH_MSG_KEXINIT
            // 16 random bytes
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            // Algorithm lists (simplified)
            0x00, 0x00, 0x00, 0x20,  // kex algorithms length
            'd', 'i', 'f', 'f', 'i', 'e', '-', 'h', 'e', 'l', 'l', 'm', 'a', 'n', '-', 'g',
            'r', 'o', 'u', 'p', '1', '4', '-', 's', 'h', 'a', '2', '5', '6', ',', 'e', 'c'
        };
        parse_ssh(sample_packet, sizeof(sample_packet), SSH_PORT, 54321);
        return 0;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    
    if (handle == NULL) {
        printf("Error opening device: %s\n", errbuf);
        return 1;
    }
    
    struct bpf_program fp;
    char filter_exp[] = "tcp port 22";
    
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("Error compiling filter\n");
        return 1;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        printf("Error setting filter\n");
        return 1;
    }
    
    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_close(handle);
    
    return 0;
}
#endif