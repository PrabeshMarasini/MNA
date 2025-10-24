#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "tcp.h"

// Global connection tracking (simplified for demo)
static tcp_connection_t tcp_connections[100] __attribute__((unused));
static int connection_count __attribute__((unused)) = 0;

// Main TCP parser function
void parse_tcp(const u_char *payload, int payload_len) {
    parse_tcp_with_context(payload, payload_len, 0, 0);
}

// TCP parser with IP context
void parse_tcp_with_context(const u_char *payload, int payload_len, uint32_t src_ip, uint32_t dst_ip) {
    if (payload_len < TCP_MIN_HEADER_SIZE) {
        printf("=== TCP Segment ===\n");
        printf("Error: Packet too short (%d bytes, minimum %d)\n", payload_len, TCP_MIN_HEADER_SIZE);
        printf("===================\n");
        return;
    }

    struct tcphdr *tcp_hdr = (struct tcphdr *)payload;
    int header_len = tcp_hdr->doff * 4;
    
    if (header_len < TCP_MIN_HEADER_SIZE || header_len > payload_len) {
        printf("=== TCP Segment ===\n");
        printf("Error: Invalid header length (%d bytes)\n", header_len);
        printf("===================\n");
        return;
    }

    printf("=== TCP Segment ===\n");
    
    // Basic header information
    uint16_t src_port = ntohs(tcp_hdr->source);
    uint16_t dst_port = ntohs(tcp_hdr->dest);
    
    printf("Ports: %u -> %u\n", src_port, dst_port);
    
    if (src_ip && dst_ip) {
        struct in_addr src_addr = {src_ip};
        struct in_addr dst_addr = {dst_ip};
        printf("Addresses: %s:%u -> %s:%u\n", 
               inet_ntoa(src_addr), src_port,
               inet_ntoa(dst_addr), dst_port);
    }
    
    // Detect application protocol
    const char* app_protocol = detect_application_protocol(src_port, dst_port, 
                                                          payload + header_len, 
                                                          payload_len - header_len);
    if (app_protocol) {
        printf("Application Protocol: %s\n", app_protocol);
    }
    
    // Parse TCP header
    parse_tcp_header(tcp_hdr, header_len);
    
    // Parse TCP options if present
    if (header_len > TCP_MIN_HEADER_SIZE) {
        parse_tcp_options(payload + TCP_MIN_HEADER_SIZE, header_len - TCP_MIN_HEADER_SIZE);
    }
    
    // Analyze flags
    analyze_tcp_flags(tcp_hdr->th_flags);
    
    // Performance analysis
    analyze_tcp_performance(tcp_hdr, payload_len - header_len);
    
    // Security analysis
    analyze_tcp_security(tcp_hdr, src_port, dst_port);
    
    // Parse payload if present
    int payload_data_len = payload_len - header_len;
    if (payload_data_len > 0) {
        parse_tcp_payload(payload + header_len, payload_data_len, src_port, dst_port);
    }
    
    printf("===================\n");
}

// Parse TCP header details
void parse_tcp_header(const struct tcphdr *tcp_hdr, int header_len) {
    printf("TCP Header:\n");
    printf("  Sequence Number: %u (0x%08x)\n", ntohl(tcp_hdr->seq), ntohl(tcp_hdr->seq));
    printf("  Acknowledgment Number: %u (0x%08x)\n", ntohl(tcp_hdr->ack_seq), ntohl(tcp_hdr->ack_seq));
    printf("  Header Length: %d bytes (%d words)\n", header_len, tcp_hdr->doff);
    printf("  Flags: %s (0x%02x)\n", get_tcp_flag_string(tcp_hdr->th_flags), tcp_hdr->th_flags);
    printf("  Window Size: %u bytes\n", ntohs(tcp_hdr->window));
    printf("  Checksum: 0x%04x\n", ntohs(tcp_hdr->check));
    
    if (tcp_hdr->urg) {
        printf("  Urgent Pointer: %u\n", ntohs(tcp_hdr->urg_ptr));
    }
}

// Parse TCP options
void parse_tcp_options(const u_char *options, int options_len) {
    printf("TCP Options (%d bytes):\n", options_len);
    
    int i = 0;
    while (i < options_len) {
        uint8_t kind = options[i];
        
        if (kind == TCP_OPT_EOL) {
            printf("  End of Option List\n");
            break;
        }
        
        if (kind == TCP_OPT_NOP) {
            printf("  No Operation\n");
            i++;
            continue;
        }
        
        if (i + 1 >= options_len) break;
        
        uint8_t length = options[i + 1];
        if (length < 2 || i + length > options_len) {
            printf("  Invalid option length\n");
            break;
        }
        
        printf("  %s: ", get_tcp_option_name(kind));
        
        switch (kind) {
            case TCP_OPT_MSS:
                if (length == 4) {
                    uint16_t mss = ntohs(*(uint16_t*)(options + i + 2));
                    printf("MSS = %u bytes\n", mss);
                } else {
                    printf("Invalid MSS option\n");
                }
                break;
                
            case TCP_OPT_WINDOW_SCALE:
                if (length == 3) {
                    uint8_t scale = options[i + 2];
                    printf("Window Scale = %u (multiplier: %u)\n", scale, 1 << scale);
                } else {
                    printf("Invalid Window Scale option\n");
                }
                break;
                
            case TCP_OPT_SACK_PERMITTED:
                printf("SACK Permitted\n");
                break;
                
            case TCP_OPT_TIMESTAMP:
                if (length == 10) {
                    uint32_t ts_val = ntohl(*(uint32_t*)(options + i + 2));
                    uint32_t ts_ecr = ntohl(*(uint32_t*)(options + i + 6));
                    printf("TSval = %u, TSecr = %u\n", ts_val, ts_ecr);
                } else {
                    printf("Invalid Timestamp option\n");
                }
                break;
                
            default:
                printf("Unknown option (kind=%u, length=%u)\n", kind, length);
                break;
        }
        
        i += length;
    }
}

// Parse TCP payload
void parse_tcp_payload(const u_char *payload, int payload_len, uint16_t src_port, uint16_t dst_port) {
    printf("Payload: %d bytes\n", payload_len);
    
    if (payload_len > 0) {
        printf("  Data Preview: ");
        int preview_len = (payload_len < 32) ? payload_len : 32;
        
        // Try to show printable characters
        int printable_count = 0;
        for (int i = 0; i < preview_len; i++) {
            if (payload[i] >= 32 && payload[i] <= 126) {
                printable_count++;
            }
        }
        
        if (printable_count > preview_len / 2) {
            // Mostly printable - show as text
            for (int i = 0; i < preview_len; i++) {
                char c = payload[i];
                if (c >= 32 && c <= 126) {
                    printf("%c", c);
                } else {
                    printf(".");
                }
            }
        } else {
            // Mostly binary - show as hex
            for (int i = 0; i < preview_len; i++) {
                printf("%02x ", payload[i]);
            }
        }
        
        if (payload_len > 32) printf("...");
        printf("\n");
        
        // Protocol-specific analysis
        if (src_port == 80 || dst_port == 80) {
            if (strncmp((char*)payload, "GET ", 4) == 0 || 
                strncmp((char*)payload, "POST ", 5) == 0 ||
                strncmp((char*)payload, "HTTP/", 5) == 0) {
                printf("  HTTP Traffic Detected\n");
            }
        } else if (src_port == 443 || dst_port == 443) {
            if (payload[0] == 0x16 && payload[1] == 0x03) {
                printf("  TLS/SSL Handshake Detected\n");
            }
        } else if (src_port == 22 || dst_port == 22) {
            if (strncmp((char*)payload, "SSH-", 4) == 0) {
                printf("  SSH Protocol Version Exchange\n");
            }
        }
    }
}

// Analyze TCP flags
void analyze_tcp_flags(uint8_t flags) {
    printf("Flag Analysis:\n");
    
    if (flags & TCP_FLAG_SYN) {
        if (flags & TCP_FLAG_ACK) {
            printf("  SYN+ACK: Connection establishment response\n");
        } else {
            printf("  SYN: Connection establishment request\n");
        }
    }
    
    if (flags & TCP_FLAG_FIN) {
        printf("  FIN: Connection termination\n");
    }
    
    if (flags & TCP_FLAG_RST) {
        printf("  RST: Connection reset (abrupt termination)\n");
    }
    
    if (flags & TCP_FLAG_PSH) {
        printf("  PSH: Push data to application immediately\n");
    }
    
    if (flags & TCP_FLAG_URG) {
        printf("  URG: Urgent data present\n");
    }
    
    if (flags & TCP_FLAG_ECE) {
        printf("  ECE: ECN Echo (congestion notification)\n");
    }
    
    if (flags & TCP_FLAG_CWR) {
        printf("  CWR: Congestion Window Reduced\n");
    }
    
    // Determine connection state
    tcp_state_t state = determine_tcp_state(flags, 0);
    printf("  Connection State: %s\n", get_tcp_state_name(state));
}

// Analyze TCP performance
void analyze_tcp_performance(const struct tcphdr *tcp_hdr, int payload_len) {
    printf("Performance Analysis:\n");
    
    uint16_t window = ntohs(tcp_hdr->window);
    printf("  Window Size: %u bytes", window);
    
    if (window == 0) {
        printf(" (ZERO WINDOW - receiver buffer full!)");
    } else if (window < 1024) {
        printf(" (small window - potential performance issue)");
    } else if (window >= 65535) {
        printf(" (maximum window - good performance)");
    }
    printf("\n");
    
    if (payload_len > 0) {
        printf("  Payload Size: %d bytes", payload_len);
        if (payload_len == 1) {
            printf(" (possible keep-alive or interactive traffic)");
        } else if (payload_len >= 1460) {
            printf(" (full-sized segment - good efficiency)");
        }
        printf("\n");
    }
    
    // Check for potential issues
    if ((tcp_hdr->th_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == TCP_FLAG_SYN && payload_len > 0) {
        printf("  ⚠ Data in SYN packet (unusual)\n");
    }
}

// Analyze TCP security
void analyze_tcp_security(const struct tcphdr *tcp_hdr, uint16_t src_port, uint16_t dst_port) {
    printf("Security Analysis:\n");
    
    // Check for common vulnerable ports
    if (src_port == 23 || dst_port == 23) {
        printf("  ⚠ Telnet (port 23) - unencrypted protocol\n");
    } else if (src_port == 21 || dst_port == 21) {
        printf("  ⚠ FTP (port 21) - unencrypted control channel\n");
    } else if (src_port == 80 || dst_port == 80) {
        printf("  ⚠ HTTP (port 80) - unencrypted web traffic\n");
    } else if (src_port == 443 || dst_port == 443) {
        printf("  ✓ HTTPS (port 443) - encrypted web traffic\n");
    } else if (src_port == 22 || dst_port == 22) {
        printf("  ✓ SSH (port 22) - encrypted remote access\n");
    }
    
    // Check for suspicious flags
    if (tcp_hdr->th_flags == 0) {
        printf("  ⚠ NULL scan detected (all flags clear)\n");
    } else if ((tcp_hdr->th_flags & (TCP_FLAG_FIN | TCP_FLAG_URG | TCP_FLAG_PSH)) == 
               (TCP_FLAG_FIN | TCP_FLAG_URG | TCP_FLAG_PSH)) {
        printf("  ⚠ XMAS scan detected (FIN+URG+PSH flags)\n");
    } else if (tcp_hdr->th_flags & TCP_FLAG_RST && tcp_hdr->th_flags & TCP_FLAG_SYN) {
        printf("  ⚠ Unusual flag combination (RST+SYN)\n");
    }
    
    // Check sequence numbers
    uint32_t seq = ntohl(tcp_hdr->seq);
    if (seq == 0 && !(tcp_hdr->th_flags & TCP_FLAG_SYN)) {
        printf("  ⚠ Zero sequence number without SYN flag\n");
    }
}

// Get TCP flag string representation
const char* get_tcp_flag_string(uint8_t flags) {
    static char flag_str[64];
    flag_str[0] = '\0';
    
    if (flags & TCP_FLAG_CWR) strcat(flag_str, "CWR ");
    if (flags & TCP_FLAG_ECE) strcat(flag_str, "ECE ");
    if (flags & TCP_FLAG_URG) strcat(flag_str, "URG ");
    if (flags & TCP_FLAG_ACK) strcat(flag_str, "ACK ");
    if (flags & TCP_FLAG_PSH) strcat(flag_str, "PSH ");
    if (flags & TCP_FLAG_RST) strcat(flag_str, "RST ");
    if (flags & TCP_FLAG_SYN) strcat(flag_str, "SYN ");
    if (flags & TCP_FLAG_FIN) strcat(flag_str, "FIN ");
    
    // Remove trailing space
    int len = strlen(flag_str);
    if (len > 0 && flag_str[len-1] == ' ') {
        flag_str[len-1] = '\0';
    }
    
    return flag_str;
}

// Get TCP state name
const char* get_tcp_state_name(tcp_state_t state) {
    switch (state) {
        case TCP_STATE_CLOSED: return "CLOSED";
        case TCP_STATE_LISTEN: return "LISTEN";
        case TCP_STATE_SYN_SENT: return "SYN_SENT";
        case TCP_STATE_SYN_RECEIVED: return "SYN_RECEIVED";
        case TCP_STATE_ESTABLISHED: return "ESTABLISHED";
        case TCP_STATE_FIN_WAIT_1: return "FIN_WAIT_1";
        case TCP_STATE_FIN_WAIT_2: return "FIN_WAIT_2";
        case TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case TCP_STATE_CLOSING: return "CLOSING";
        case TCP_STATE_LAST_ACK: return "LAST_ACK";
        case TCP_STATE_TIME_WAIT: return "TIME_WAIT";
        default: return "UNKNOWN";
    }
}

// Get TCP option name
const char* get_tcp_option_name(uint8_t option_kind) {
    switch (option_kind) {
        case TCP_OPT_EOL: return "End of Option List";
        case TCP_OPT_NOP: return "No Operation";
        case TCP_OPT_MSS: return "Maximum Segment Size";
        case TCP_OPT_WINDOW_SCALE: return "Window Scale";
        case TCP_OPT_SACK_PERMITTED: return "SACK Permitted";
        case TCP_OPT_SACK: return "SACK";
        case TCP_OPT_TIMESTAMP: return "Timestamp";
        default: return "Unknown Option";
    }
}

// Detect application protocol
const char* detect_application_protocol(uint16_t src_port, uint16_t dst_port, const u_char *payload, int len) {
    // Check well-known ports first
    if (src_port == 80 || dst_port == 80) return "HTTP";
    if (src_port == 443 || dst_port == 443) return "HTTPS/TLS";
    if (src_port == 22 || dst_port == 22) return "SSH";
    if (src_port == 21 || dst_port == 21) return "FTP";
    if (src_port == 23 || dst_port == 23) return "Telnet";
    if (src_port == 25 || dst_port == 25) return "SMTP";
    if (src_port == 53 || dst_port == 53) return "DNS";
    if (src_port == 110 || dst_port == 110) return "POP3";
    if (src_port == 143 || dst_port == 143) return "IMAP";
    if (src_port == 993 || dst_port == 993) return "IMAPS";
    if (src_port == 995 || dst_port == 995) return "POP3S";
    
    // Try to detect by payload content
    if (len > 4) {
        if (strncmp((char*)payload, "GET ", 4) == 0 || 
            strncmp((char*)payload, "POST ", 5) == 0 ||
            strncmp((char*)payload, "HTTP/", 5) == 0) {
            return "HTTP";
        }
        if (strncmp((char*)payload, "SSH-", 4) == 0) {
            return "SSH";
        }
        if (payload[0] == 0x16 && payload[1] == 0x03) {
            return "TLS/SSL";
        }
    }
    
    return NULL;
}

// Determine TCP connection state
tcp_state_t determine_tcp_state(uint8_t flags, int is_response) {
    (void)is_response; // Suppress unused parameter warning
    if (flags & TCP_FLAG_RST) {
        return TCP_STATE_CLOSED;
    }
    
    if (flags & TCP_FLAG_SYN) {
        if (flags & TCP_FLAG_ACK) {
            return TCP_STATE_SYN_RECEIVED;
        } else {
            return TCP_STATE_SYN_SENT;
        }
    }
    
    if (flags & TCP_FLAG_FIN) {
        if (flags & TCP_FLAG_ACK) {
            return TCP_STATE_LAST_ACK;
        } else {
            return TCP_STATE_FIN_WAIT_1;
        }
    }
    
    if (flags & TCP_FLAG_ACK) {
        return TCP_STATE_ESTABLISHED;
    }
    
    return TCP_STATE_CLOSED;
}
#ifdef TCP_STANDALONE
// Standalone mode for testing and live capture
#include <netinet/ip.h>
#include <netinet/if_ether.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        
        if (ip_header->ip_p == IPPROTO_TCP) {
            const u_char *tcp_payload = packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4);
            int tcp_payload_len = ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4);
            
            if (tcp_payload_len > 0) {
                parse_tcp_with_context(tcp_payload, tcp_payload_len, 
                                     ip_header->ip_src.s_addr, ip_header->ip_dst.s_addr);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    printf("TCP Protocol Analyzer - Standalone Mode\n");
    printf("Analyzing TCP segments with comprehensive header and payload analysis\n\n");
    
    if (argc > 1) {
        // Test with sample TCP packets
        printf("Testing with sample TCP SYN packet:\n");
        
        // Sample TCP SYN packet with options
        u_char sample_syn[] = {
            // TCP Header (20 bytes + 12 bytes options = 32 bytes total)
            0x12, 0x34,                     // Source port (4660)
            0x00, 0x50,                     // Destination port (80 - HTTP)
            0x12, 0x34, 0x56, 0x78,        // Sequence number
            0x00, 0x00, 0x00, 0x00,        // Acknowledgment number (0 for SYN)
            0x80,                           // Header length (8 * 4 = 32 bytes) + reserved
            0x02,                           // Flags (SYN)
            0xFF, 0xFF,                     // Window size (65535)
            0x12, 0x34,                     // Checksum
            0x00, 0x00,                     // Urgent pointer
            // TCP Options (12 bytes)
            0x02, 0x04, 0x05, 0xB4,        // MSS option (1460 bytes)
            0x04, 0x02,                     // SACK permitted
            0x08, 0x0A, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00 // Timestamp
        };
        
        parse_tcp(sample_syn, sizeof(sample_syn));
        
        printf("\nTesting with sample TCP SYN+ACK packet:\n");
        
        // Sample TCP SYN+ACK packet
        u_char sample_synack[] = {
            0x00, 0x50,                     // Source port (80 - HTTP)
            0x12, 0x34,                     // Destination port (4660)
            0x87, 0x65, 0x43, 0x21,        // Sequence number
            0x12, 0x34, 0x56, 0x79,        // Acknowledgment number (seq + 1)
            0x60,                           // Header length (6 * 4 = 24 bytes) + reserved
            0x12,                           // Flags (SYN + ACK)
            0x20, 0x00,                     // Window size (8192)
            0x56, 0x78,                     // Checksum
            0x00, 0x00,                     // Urgent pointer
            // TCP Options (4 bytes)
            0x02, 0x04, 0x05, 0xB4         // MSS option (1460 bytes)
        };
        
        parse_tcp(sample_synack, sizeof(sample_synack));
        
        printf("\nTesting with sample TCP data packet with HTTP payload:\n");
        
        // Sample TCP packet with HTTP GET request
        u_char sample_http[] = {
            0x12, 0x34,                     // Source port (4660)
            0x00, 0x50,                     // Destination port (80 - HTTP)
            0x12, 0x34, 0x56, 0x79,        // Sequence number
            0x87, 0x65, 0x43, 0x22,        // Acknowledgment number
            0x50,                           // Header length (5 * 4 = 20 bytes) + reserved
            0x18,                           // Flags (PSH + ACK)
            0x20, 0x00,                     // Window size (8192)
            0x9A, 0xBC,                     // Checksum
            0x00, 0x00,                     // Urgent pointer
            // HTTP GET request payload
            'G', 'E', 'T', ' ', '/', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1', '\r', '\n',
            'H', 'o', 's', 't', ':', ' ', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', '\r', '\n',
            '\r', '\n'
        };
        
        parse_tcp(sample_http, sizeof(sample_http));
        
        printf("\nTesting with sample TCP FIN packet:\n");
        
        // Sample TCP FIN packet
        u_char sample_fin[] = {
            0x12, 0x34,                     // Source port (4660)
            0x00, 0x50,                     // Destination port (80 - HTTP)
            0x12, 0x34, 0x57, 0x00,        // Sequence number
            0x87, 0x65, 0x44, 0x00,        // Acknowledgment number
            0x50,                           // Header length (5 * 4 = 20 bytes) + reserved
            0x11,                           // Flags (FIN + ACK)
            0x20, 0x00,                     // Window size (8192)
            0xDE, 0xF0,                     // Checksum
            0x00, 0x00                      // Urgent pointer
        };
        
        parse_tcp(sample_fin, sizeof(sample_fin));
        
        return 0;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    
    if (handle == NULL) {
        printf("Error opening device: %s\n", errbuf);
        printf("Try running as root: sudo ./tcp_analyzer\n");
        return 1;
    }
    
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("Error compiling filter\n");
        return 1;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        printf("Error setting filter\n");
        return 1;
    }
    
    printf("Capturing TCP packets... Press Ctrl+C to stop\n");
    printf("Try browsing websites, SSH connections, or any TCP-based applications\n\n");
    
    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_close(handle);
    
    return 0;
}
#endif