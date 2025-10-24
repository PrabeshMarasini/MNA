#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "quic.h"

// Main QUIC parser function
void parse_quic(const u_char *payload, int payload_len, int src_port, int dst_port) {
    if (payload_len <= 0) return;
    
    // Only check content-based detection for QUIC
    if (!detect_quic_packet(payload, payload_len)) {
        return;
    }

    printf("=== QUIC Packet ===\n");
    printf("Ports: %d -> %d\n", src_port, dst_port);
    printf("Length: %d bytes\n", payload_len);

    if (payload_len < 1) {
        printf("Error: Packet too short\n");
        printf("===================\n");
        return;
    }

    uint8_t first_byte = payload[0];
    int is_long_header = first_byte & 0x80;

    if (is_long_header) {
        parse_quic_long_header(payload, payload_len, first_byte);
    } else {
        parse_quic_short_header(payload, payload_len, first_byte);
    }

    printf("===================\n");
}

// Parse QUIC long header packets
void parse_quic_long_header(const u_char *data, int len, uint8_t first_byte) {
    const u_char *ptr = data + 1;
    const u_char *end = data + len;

    printf("Header Type: Long Header\n");

    // Extract packet type
    uint8_t packet_type = (first_byte & 0x30) >> 4;
    printf("Packet Type: %s\n", get_quic_packet_type_name(packet_type));

    // Version (4 bytes)
    if (ptr + 4 > end) return;
    uint32_t version = ntohl(*(uint32_t*)ptr);
    printf("Version: 0x%08x (%s)\n", version, get_quic_version_name(version));
    ptr += 4;

    // Version negotiation packet
    if (version == QUIC_VERSION_NEGOTIATION) {
        printf("Version Negotiation Packet\n");
        printf("Supported Versions:\n");
        while (ptr + 4 <= end) {
            uint32_t supported_version = ntohl(*(uint32_t*)ptr);
            printf("  0x%08x (%s)\n", supported_version, get_quic_version_name(supported_version));
            ptr += 4;
        }
        return;
    }

    // Destination Connection ID
    if (ptr >= end) return;
    uint8_t dcid_len = *ptr++;
    if (dcid_len > QUIC_MAX_CID_LENGTH || ptr + dcid_len > end) return;
    print_quic_connection_id(ptr, dcid_len, "Destination Connection ID");
    ptr += dcid_len;

    // Source Connection ID
    if (ptr >= end) return;
    uint8_t scid_len = *ptr++;
    if (scid_len > QUIC_MAX_CID_LENGTH || ptr + scid_len > end) return;
    print_quic_connection_id(ptr, scid_len, "Source Connection ID");
    ptr += scid_len;

    // Type-specific fields
    if (packet_type == QUIC_PACKET_INITIAL) {
        // Token Length and Token
        uint64_t token_len;
        int token_len_bytes = read_quic_varint(ptr, end - ptr, &token_len);
        if (token_len_bytes < 0) return;
        ptr += token_len_bytes;

        printf("Token Length: %llu\n", (unsigned long long)token_len);
        if (token_len > 0) {
            if (ptr + token_len > end) return;
            printf("Token: ");
            int preview_len = (token_len < 16) ? token_len : 16;
            for (int i = 0; i < preview_len; i++) {
                printf("%02x", ptr[i]);
            }
            if (token_len > 16) printf("...");
            printf("\n");
            ptr += token_len;
        }
    } else if (packet_type == QUIC_PACKET_RETRY) {
        printf("Retry Token: ");
        int remaining = end - ptr;
        if (remaining > 16) remaining = 16;
        for (int i = 0; i < remaining; i++) {
            printf("%02x", ptr[i]);
        }
        printf("\n");
        return;
    }

    // Length field (varint)
    uint64_t length;
    int length_bytes = read_quic_varint(ptr, end - ptr, &length);
    if (length_bytes < 0) return;
    ptr += length_bytes;
    printf("Payload Length: %llu\n", (unsigned long long)length);

    // Packet Number
    int pn_length = (first_byte & 0x03) + 1;
    if (ptr + pn_length > end) return;
    printf("Packet Number Length: %d bytes\n", pn_length);
    printf("Packet Number: ");
    for (int i = 0; i < pn_length; i++) {
        printf("%02x", ptr[i]);
    }
    printf("\n");
    ptr += pn_length;

    // Payload analysis
    int payload_remaining = end - ptr;
    printf("Payload: %d bytes ", payload_remaining);

    if (packet_type == QUIC_PACKET_INITIAL || packet_type == QUIC_PACKET_HANDSHAKE) {
        printf("(TLS handshake data)\n");
        
        // Try to detect TLS handshake messages
        if (payload_remaining > 4) {
            if (ptr[0] == 0x01 && ptr[1] == 0x00) {
                printf("Detected: TLS Client Hello\n");
            } else if (ptr[0] == 0x02 && ptr[1] == 0x00) {
                printf("Detected: TLS Server Hello\n");
            } else if (ptr[0] == 0x0b && ptr[1] == 0x00) {
                printf("Detected: TLS Certificate\n");
            }
        }
    } else {
        printf("(encrypted application data)\n");
    }

    // Security analysis
    if (version == QUIC_VERSION_1) {
        printf("Security: ✓ QUIC v1 (RFC 9000) - Latest stable\n");
    } else if (version == QUIC_VERSION_NEGOTIATION) {
        printf("Security: ⚠ Version negotiation in progress\n");
    } else if ((version & 0xFF000000) == 0xFF000000) {
        printf("Security: ⚠ Draft version - may have issues\n");
    }
}

// Parse QUIC short header packets
void parse_quic_short_header(const u_char *data, int len, uint8_t first_byte) {
    const u_char *ptr = data + 1;
    const u_char *end = data + len;

    printf("Header Type: Short Header (1-RTT)\n");

    // Key phase bit
    int key_phase = (first_byte & 0x04) ? 1 : 0;
    printf("Key Phase: %d\n", key_phase);

    // Spin bit (for RTT measurement)
    int spin_bit = (first_byte & 0x20) ? 1 : 0;
    printf("Spin Bit: %d\n", spin_bit);

    // Packet Number
    int pn_length = (first_byte & 0x03) + 1;
    printf("Packet Number Length: %d bytes\n", pn_length);
    
    if (ptr + pn_length > end) return;
    printf("Packet Number: ");
    for (int i = 0; i < pn_length; i++) {
        printf("%02x", ptr[i]);
    }
    printf("\n");
    ptr += pn_length;

    // Encrypted payload
    int payload_len = end - ptr;
    printf("Encrypted Payload: %d bytes\n", payload_len);
    printf("Status: Application data (encrypted)\n");
}

// Read QUIC variable-length integer
int read_quic_varint(const u_char *data, int len, uint64_t *value_out) {
    if (len <= 0) return -1;

    uint8_t first = data[0];
    int varint_len;
    uint64_t value = 0;

    // Determine length from first two bits
    if ((first & 0xC0) == 0x00) varint_len = 1;
    else if ((first & 0xC0) == 0x40) varint_len = 2;
    else if ((first & 0xC0) == 0x80) varint_len = 4;
    else if ((first & 0xC0) == 0xC0) varint_len = 8;
    else return -1;

    if (varint_len > len) return -1;

    // Decode value
    value = first & (0xFF >> 2); // Remove length prefix
    for (int i = 1; i < varint_len; i++) {
        value = (value << 8) | data[i];
    }

    *value_out = value;
    return varint_len;
}

// Get QUIC packet type name
const char* get_quic_packet_type_name(uint8_t packet_type) {
    switch (packet_type) {
        case QUIC_PACKET_INITIAL: return "Initial";
        case QUIC_PACKET_0RTT: return "0-RTT";
        case QUIC_PACKET_HANDSHAKE: return "Handshake";
        case QUIC_PACKET_RETRY: return "Retry";
        default: return "Unknown";
    }
}

// Get QUIC version name
const char* get_quic_version_name(uint32_t version) {
    switch (version) {
        case QUIC_VERSION_1: return "QUIC v1 (RFC 9000)";
        case QUIC_VERSION_DRAFT_29: return "Draft-29";
        case QUIC_VERSION_NEGOTIATION: return "Version Negotiation";
        case 0x6b3343cf: return "Google QUIC";
        case 0x51303530: return "Q050";
        case 0x51303436: return "Q046";
        default: return "Unknown/Custom";
    }
}

// Print QUIC connection ID
void print_quic_connection_id(const uint8_t *cid, int len, const char *label) {
    printf("%s (%d bytes): ", label, len);
    if (len == 0) {
        printf("(empty)");
    } else {
        for (int i = 0; i < len; i++) {
            printf("%02x", cid[i]);
        }
    }
    printf("\n");
}

// Strict QUIC packet detection
int detect_quic_packet(const u_char *payload, int payload_len) {
    if (payload_len < 5) return 0;
    
    uint8_t first_byte = payload[0];
    
    // Long header packets - these are distinctive
    if (first_byte & 0x80) {
        if (payload_len < 6) return 0;
        
        // Check version field at offset 1-4
        uint32_t version = ntohl(*(uint32_t*)(payload + 1));
        
        // Only match known QUIC versions
        if (version == QUIC_VERSION_1 || 
            version == QUIC_VERSION_DRAFT_29 || 
            version == QUIC_VERSION_NEGOTIATION ||
            version == 0x6b3343cf ||
            version == 0x51303530 ||
            version == 0x51303436) {
            return 1;
        }
        
        // Also accept versions in draft range (0xFF000000)
        if ((version & 0xFF000000) == 0xFF000000) {
            return 1;
        }
        
        return 0;
    }
    
    // Short header packets - harder to detect
    // Only accept if structure looks valid
    if (!(first_byte & 0x80)) {
        // Short header must have fixed bit set (bit 6)
        if (!(first_byte & 0x40)) {
            return 0;
        }
        
        int pn_len = (first_byte & 0x03) + 1;
        
        // Check if packet is long enough for packet number + some payload
        if (payload_len > pn_len + 4) {
            return 1;
        }
    }
    
    return 0;
}

#ifdef QUIC_STANDALONE
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        
        if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));
            
            int src_port = ntohs(udp_header->uh_sport);
            int dst_port = ntohs(udp_header->uh_dport);
            
            const u_char *payload = packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4) + sizeof(struct udphdr);
            int payload_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);
            
            if (payload_len > 0) {
                parse_quic(payload, payload_len, src_port, dst_port);
            }
        }
    }
}

int main(int argc, char *argv[]) {
    printf("QUIC Protocol Analyzer - Standalone Mode\n");
    printf("Listening for QUIC traffic...\n\n");
    
    if (argc > 1) {
        printf("Testing with sample QUIC Initial packet:\n");
        
        u_char sample_initial[] = {
            0xc0,                           // Long header, Initial packet
            0x00, 0x00, 0x00, 0x01,        // Version 1
            0x08,                           // DCID length
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x08,                           // SCID length  
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x00,                           // Token length (0)
            0x44, 0x3a,                     // Length (varint)
            0x00, 0x00, 0x00, 0x01,        // Packet number
            0x01, 0x00, 0x00, 0x56, 0x03, 0x03
        };
        
        parse_quic(sample_initial, sizeof(sample_initial), 12345, 443);
        
        printf("\nTesting with sample QUIC Short Header (1-RTT):\n");
        u_char sample_short[] = {
            0x41,                           // Short header, key phase 0
            0x12, 0x34, 0x56, 0x78,        // Packet number
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe
        };
        
        parse_quic(sample_short, sizeof(sample_short), 443, 12345);
        
        return 0;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("any", 65535, 1, 1000, errbuf);
    
    if (handle == NULL) {
        printf("Error opening device: %s\n", errbuf);
        printf("Try running as root: sudo ./quic_analyzer\n");
        return 1;
    }
    
    struct bpf_program fp;
    // Strict filter for UDP only - QUIC detection will filter further
    char filter_exp[] = "udp";
    
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("Error compiling filter\n");
        return 1;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        printf("Error setting filter\n");
        return 1;
    }
    
    printf("Capturing UDP packets...\n");
    printf("Analyzing with strict QUIC detection\n");
    printf("Press Ctrl+C to stop\n\n");
    
    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_close(handle);
    
    return 0;
}
#endif