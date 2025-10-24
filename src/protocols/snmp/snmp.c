#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "snmp.h"

// Main SNMP parser function
void parse_snmp(const u_char *payload, int payload_len, int src_port, int dst_port) {
    if (!is_snmp_traffic(src_port, dst_port)) return;
    if (payload_len < 10) return; // Minimum SNMP message size

    printf("=== SNMP Packet ===\n");
    printf("Ports: %d -> %d\n", src_port, dst_port);
    printf("Length: %d bytes\n", payload_len);

    // Determine direction and type
    if (dst_port == SNMP_PORT) {
        printf("Direction: Client -> SNMP Agent (Request)\n");
    } else if (src_port == SNMP_PORT) {
        printf("Direction: SNMP Agent -> Client (Response)\n");
    } else if (src_port == SNMP_TRAP_PORT || dst_port == SNMP_TRAP_PORT) {
        printf("Direction: SNMP Trap/Inform\n");
    }

    // Parse SNMP message
    snmp_message_t msg;
    memset(&msg, 0, sizeof(msg));
    
    if (parse_snmp_message(payload, payload_len, &msg)) {
        printf("Version: %s\n", get_snmp_version_name(msg.version));
        
        if (msg.version != SNMP_VERSION_3) {
            printf("Community: %s\n", msg.community);
        }
        
        printf("PDU Type: %s\n", get_snmp_pdu_type_name(msg.pdu_type));
        printf("Request ID: %u\n", msg.request_id);
        
        if (msg.error_status != SNMP_ERROR_NO_ERROR) {
            printf("Error Status: %s (%u)\n", get_snmp_error_name(msg.error_status), msg.error_status);
            printf("Error Index: %u\n", msg.error_index);
        } else {
            printf("Error Status: No Error\n");
        }
        
        printf("Variable Bindings: %d\n", msg.varbind_count);
        
        // Security analysis
        analyze_snmp_security(&msg);
    } else {
        printf("Status: Failed to parse SNMP message\n");
        printf("Raw Data: ");
        for (int i = 0; i < (payload_len < 32 ? payload_len : 32); i++) {
            printf("%02x ", payload[i]);
        }
        if (payload_len > 32) printf("...");
        printf("\n");
    }

    printf("===================\n");
}

// Parse complete SNMP message
int parse_snmp_message(const u_char *data, int len, snmp_message_t *msg) {
    if (len < 2 || data[0] != ASN1_SEQUENCE) return 0;
    
    const u_char *ptr = data + 1;
    int remaining = len - 1;
    
    // Parse message length
    int length_bytes;
    int msg_length = parse_asn1_length(ptr, remaining, &length_bytes);
    if (msg_length < 0) return 0;
    
    ptr += length_bytes;
    remaining -= length_bytes;
    
    // Parse version
    if (remaining < 3 || ptr[0] != ASN1_INTEGER) return 0;
    int version_len = ptr[1];
    if (version_len != 1 || remaining < 3 + version_len) return 0;
    
    msg->version = ptr[2];
    ptr += 3;
    remaining -= 3;
    
    // Parse community string (for v1 and v2c)
    if (msg->version != SNMP_VERSION_3) {
        if (remaining < 2 || ptr[0] != ASN1_OCTET_STRING) return 0;
        
        int community_len = ptr[1];
        if (community_len > SNMP_MAX_COMMUNITY_LEN || remaining < 2 + community_len) return 0;
        
        memcpy(msg->community, ptr + 2, community_len);
        msg->community[community_len] = '\0';
        
        ptr += 2 + community_len;
        remaining -= 2 + community_len;
    } else {
        strcpy(msg->community, "[SNMPv3 - encrypted]");
        // For SNMPv3, we'd need to parse the msgGlobalData, msgSecurityParameters, etc.
        // This is complex and beyond basic parsing
    }
    
    // Parse PDU
    return parse_snmp_pdu(ptr, remaining, msg);
}

// Parse ASN.1 length field
int parse_asn1_length(const u_char *data, int len, int *length_bytes) {
    if (len < 1) return -1;
    
    *length_bytes = 1;
    
    if (data[0] & 0x80) {
        // Long form
        int num_octets = data[0] & 0x7F;
        if (num_octets == 0 || num_octets > 4 || len < 1 + num_octets) return -1;
        
        *length_bytes = 1 + num_octets;
        int length = 0;
        
        for (int i = 1; i <= num_octets; i++) {
            length = (length << 8) | data[i];
        }
        
        return length;
    } else {
        // Short form
        return data[0];
    }
}

// Parse ASN.1 integer
int parse_asn1_integer(const u_char *data, int len, int32_t *value) {
    if (len < 2 || data[0] != ASN1_INTEGER) return 0;
    
    int int_len = data[1];
    if (int_len > 4 || len < 2 + int_len) return 0;
    
    *value = 0;
    for (int i = 0; i < int_len; i++) {
        *value = (*value << 8) | data[2 + i];
    }
    
    // Handle sign extension for negative numbers
    if (int_len > 0 && (data[2] & 0x80)) {
        for (int i = int_len; i < 4; i++) {
            *value |= (0xFF << (8 * (3 - i)));
        }
    }
    
    return 2 + int_len;
}

// Parse ASN.1 octet string
int parse_asn1_string(const u_char *data, int len, char *buffer, int buf_size) {
    if (len < 2 || data[0] != ASN1_OCTET_STRING) return 0;
    
    int str_len = data[1];
    if (str_len >= buf_size || len < 2 + str_len) return 0;
    
    memcpy(buffer, data + 2, str_len);
    buffer[str_len] = '\0';
    
    return 2 + str_len;
}

// Parse ASN.1 Object Identifier
int parse_asn1_oid(const u_char *data, int len, char *oid_str, int oid_size) {
    if (len < 2 || data[0] != ASN1_OBJECT_IDENTIFIER) return 0;
    
    int oid_len = data[1];
    if (len < 2 + oid_len) return 0;
    
    const u_char *oid_data = data + 2;
    char temp[256];
    int pos = 0;
    
    if (oid_len > 0) {
        // First two sub-identifiers are encoded in the first byte
        int first = oid_data[0] / 40;
        int second = oid_data[0] % 40;
        pos += snprintf(temp + pos, sizeof(temp) - pos, "%d.%d", first, second);
        
        // Parse remaining sub-identifiers
        for (int i = 1; i < oid_len; i++) {
            uint32_t subid = 0;
            
            // Handle multi-byte sub-identifiers
            do {
                subid = (subid << 7) | (oid_data[i] & 0x7F);
                if ((oid_data[i] & 0x80) == 0) break;
                i++;
            } while (i < oid_len);
            
            pos += snprintf(temp + pos, sizeof(temp) - pos, ".%u", subid);
        }
    }
    
    strncpy(oid_str, temp, oid_size - 1);
    oid_str[oid_size - 1] = '\0';
    
    return 2 + oid_len;
}

// Parse SNMP PDU
int parse_snmp_pdu(const u_char *data, int len, snmp_message_t *msg) {
    if (len < 2) return 0;
    
    msg->pdu_type = data[0];
    
    // Parse PDU length
    int length_bytes;
    int pdu_length = parse_asn1_length(data + 1, len - 1, &length_bytes);
    if (pdu_length < 0) return 0;
    
    const u_char *ptr = data + 1 + length_bytes;
    int remaining = len - 1 - length_bytes;
    
    // Parse request ID
    int consumed = parse_asn1_integer(ptr, remaining, (int32_t*)&msg->request_id);
    if (consumed == 0) return 0;
    ptr += consumed;
    remaining -= consumed;
    
    // Parse error status
    consumed = parse_asn1_integer(ptr, remaining, (int32_t*)&msg->error_status);
    if (consumed == 0) return 0;
    ptr += consumed;
    remaining -= consumed;
    
    // Parse error index
    consumed = parse_asn1_integer(ptr, remaining, (int32_t*)&msg->error_index);
    if (consumed == 0) return 0;
    ptr += consumed;
    remaining -= consumed;
    
    // Parse variable bindings list
    if (remaining >= 2 && ptr[0] == ASN1_SEQUENCE) {
        msg->varbind_count = 0;
        // Count variable bindings (simplified)
        const u_char *vb_ptr = ptr + 2;
        int vb_remaining = ptr[1];
        
        while (vb_remaining > 0 && msg->varbind_count < 10) {
            if (vb_ptr[0] == ASN1_SEQUENCE) {
                msg->varbind_count++;
                int vb_len = vb_ptr[1];
                vb_ptr += 2 + vb_len;
                vb_remaining -= 2 + vb_len;
            } else {
                break;
            }
        }
    }
    
    return 1;
}

// Get SNMP version name
const char* get_snmp_version_name(int version) {
    switch (version) {
        case SNMP_VERSION_1: return "SNMPv1";
        case SNMP_VERSION_2C: return "SNMPv2c";
        case SNMP_VERSION_3: return "SNMPv3";
        default: return "Unknown";
    }
}

// Get SNMP PDU type name
const char* get_snmp_pdu_type_name(uint8_t pdu_type) {
    switch (pdu_type) {
        case SNMP_PDU_GET_REQUEST: return "GetRequest";
        case SNMP_PDU_GET_NEXT_REQUEST: return "GetNextRequest";
        case SNMP_PDU_GET_RESPONSE: return "GetResponse";
        case SNMP_PDU_SET_REQUEST: return "SetRequest";
        case SNMP_PDU_TRAP_V1: return "Trap (v1)";
        case SNMP_PDU_GET_BULK_REQUEST: return "GetBulkRequest";
        case SNMP_PDU_INFORM_REQUEST: return "InformRequest";
        case SNMP_PDU_TRAP_V2: return "Trap (v2)";
        case SNMP_PDU_REPORT: return "Report";
        default: return "Unknown PDU";
    }
}

// Get SNMP error name
const char* get_snmp_error_name(uint32_t error_code) {
    switch (error_code) {
        case SNMP_ERROR_NO_ERROR: return "No Error";
        case SNMP_ERROR_TOO_BIG: return "Too Big";
        case SNMP_ERROR_NO_SUCH_NAME: return "No Such Name";
        case SNMP_ERROR_BAD_VALUE: return "Bad Value";
        case SNMP_ERROR_READ_ONLY: return "Read Only";
        case SNMP_ERROR_GEN_ERR: return "General Error";
        case SNMP_ERROR_NO_ACCESS: return "No Access";
        case SNMP_ERROR_WRONG_TYPE: return "Wrong Type";
        case SNMP_ERROR_WRONG_LENGTH: return "Wrong Length";
        case SNMP_ERROR_WRONG_ENCODING: return "Wrong Encoding";
        case SNMP_ERROR_WRONG_VALUE: return "Wrong Value";
        case SNMP_ERROR_NO_CREATION: return "No Creation";
        case SNMP_ERROR_INCONSISTENT_VALUE: return "Inconsistent Value";
        case SNMP_ERROR_RESOURCE_UNAVAILABLE: return "Resource Unavailable";
        case SNMP_ERROR_COMMIT_FAILED: return "Commit Failed";
        case SNMP_ERROR_UNDO_FAILED: return "Undo Failed";
        case SNMP_ERROR_AUTHORIZATION_ERROR: return "Authorization Error";
        case SNMP_ERROR_NOT_WRITABLE: return "Not Writable";
        case SNMP_ERROR_INCONSISTENT_NAME: return "Inconsistent Name";
        default: return "Unknown Error";
    }
}

// Get ASN.1 type name
const char* get_asn1_type_name(uint8_t type) {
    switch (type) {
        case ASN1_INTEGER: return "INTEGER";
        case ASN1_OCTET_STRING: return "OCTET STRING";
        case ASN1_NULL: return "NULL";
        case ASN1_OBJECT_IDENTIFIER: return "OBJECT IDENTIFIER";
        case ASN1_COUNTER32: return "Counter32";
        case ASN1_GAUGE32: return "Gauge32";
        case ASN1_TIMETICKS: return "TimeTicks";
        case ASN1_OPAQUE: return "Opaque";
        case ASN1_COUNTER64: return "Counter64";
        default: return "Unknown Type";
    }
}

// Resolve common OID names
const char* resolve_oid_name(const char *oid) {
    if (strncmp(oid, "1.3.6.1.2.1.1.1", 15) == 0) return "sysDescr";
    if (strncmp(oid, "1.3.6.1.2.1.1.2", 15) == 0) return "sysObjectID";
    if (strncmp(oid, "1.3.6.1.2.1.1.3", 15) == 0) return "sysUpTime";
    if (strncmp(oid, "1.3.6.1.2.1.1.4", 15) == 0) return "sysContact";
    if (strncmp(oid, "1.3.6.1.2.1.1.5", 15) == 0) return "sysName";
    if (strncmp(oid, "1.3.6.1.2.1.1.6", 15) == 0) return "sysLocation";
    if (strncmp(oid, "1.3.6.1.2.1.2.1", 15) == 0) return "ifNumber";
    if (strncmp(oid, "1.3.6.1.2.1.2.2.1.1", 19) == 0) return "ifIndex";
    if (strncmp(oid, "1.3.6.1.2.1.2.2.1.2", 19) == 0) return "ifDescr";
    if (strncmp(oid, "1.3.6.1.2.1.2.2.1.10", 20) == 0) return "ifInOctets";
    if (strncmp(oid, "1.3.6.1.2.1.2.2.1.16", 20) == 0) return "ifOutOctets";
    return oid;
}

// Analyze SNMP security
void analyze_snmp_security(const snmp_message_t *msg) {
    printf("Security Analysis:\n");
    
    switch (msg->version) {
        case SNMP_VERSION_1:
            printf("  ⚠ SNMPv1 - No encryption, plaintext community\n");
            if (strcmp(msg->community, "public") == 0) {
                printf("  ⚠ Using default 'public' community - SECURITY RISK\n");
            } else if (strcmp(msg->community, "private") == 0) {
                printf("  ⚠ Using default 'private' community - SECURITY RISK\n");
            }
            break;
            
        case SNMP_VERSION_2C:
            printf("  ⚠ SNMPv2c - No encryption, plaintext community\n");
            if (strcmp(msg->community, "public") == 0) {
                printf("  ⚠ Using default 'public' community - SECURITY RISK\n");
            } else if (strcmp(msg->community, "private") == 0) {
                printf("  ⚠ Using default 'private' community - SECURITY RISK\n");
            }
            break;
            
        case SNMP_VERSION_3:
            printf("  ✓ SNMPv3 - Supports authentication and encryption\n");
            break;
            
        default:
            printf("  ⚠ Unknown SNMP version\n");
            break;
    }
    
    // Check for write operations
    if (msg->pdu_type == SNMP_PDU_SET_REQUEST) {
        printf("  ⚠ SET operation detected - potential configuration change\n");
    }
}

// Check if traffic is SNMP
int is_snmp_traffic(int src_port, int dst_port) {
    return (src_port == SNMP_PORT || dst_port == SNMP_PORT ||
            src_port == SNMP_TRAP_PORT || dst_port == SNMP_TRAP_PORT);
}
#ifdef SNMP_STANDALONE
// Standalone mode for testing and live capture
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
            
            if (is_snmp_traffic(src_port, dst_port)) {
                const u_char *payload = packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4) + sizeof(struct udphdr);
                int payload_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);
                
                if (payload_len > 0) {
                    parse_snmp(payload, payload_len, src_port, dst_port);
                }
            }
        }
    }
}

int main(int argc, char *argv[]) {
    printf("SNMP Protocol Analyzer - Standalone Mode\n");
    printf("Listening for SNMP traffic on ports %d and %d...\n\n", SNMP_PORT, SNMP_TRAP_PORT);
    
    if (argc > 1) {
        // Test with sample SNMP packets
        printf("Testing with sample SNMP GetRequest:\n");
        
        // Sample SNMPv2c GetRequest for sysDescr (1.3.6.1.2.1.1.1.0)
        u_char sample_get[] = {
            0x30, 0x29,                     // SEQUENCE, length 41
            0x02, 0x01, 0x01,              // INTEGER version (SNMPv2c = 1)
            0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // OCTET STRING community "public"
            0xA0, 0x1C,                     // GetRequest PDU, length 28
            0x02, 0x04, 0x12, 0x34, 0x56, 0x78, // INTEGER request-id
            0x02, 0x01, 0x00,              // INTEGER error-status (0)
            0x02, 0x01, 0x00,              // INTEGER error-index (0)
            0x30, 0x0E,                     // SEQUENCE varbind list, length 14
            0x30, 0x0C,                     // SEQUENCE varbind, length 12
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID 1.3.6.1.2.1.1.1.0
            0x05, 0x00                      // NULL value
        };
        
        parse_snmp(sample_get, sizeof(sample_get), 12345, SNMP_PORT);
        
        printf("\nTesting with sample SNMP GetResponse:\n");
        
        // Sample SNMPv1 GetResponse
        u_char sample_response[] = {
            0x30, 0x39,                     // SEQUENCE, length 57
            0x02, 0x01, 0x00,              // INTEGER version (SNMPv1 = 0)
            0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // OCTET STRING community "public"
            0xA2, 0x2C,                     // GetResponse PDU, length 44
            0x02, 0x04, 0x12, 0x34, 0x56, 0x78, // INTEGER request-id
            0x02, 0x01, 0x00,              // INTEGER error-status (0)
            0x02, 0x01, 0x00,              // INTEGER error-index (0)
            0x30, 0x1E,                     // SEQUENCE varbind list, length 30
            0x30, 0x1C,                     // SEQUENCE varbind, length 28
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID 1.3.6.1.2.1.1.1.0
            0x04, 0x10, 'L', 'i', 'n', 'u', 'x', ' ', 'R', 'o', 'u', 't', 'e', 'r', ' ', 'v', '1', '0' // OCTET STRING value
        };
        
        parse_snmp(sample_response, sizeof(sample_response), SNMP_PORT, 54321);
        
        printf("\nTesting with sample SNMP Trap:\n");
        
        // Sample SNMPv1 Trap
        u_char sample_trap[] = {
            0x30, 0x3A,                     // SEQUENCE, length 58
            0x02, 0x01, 0x00,              // INTEGER version (SNMPv1 = 0)
            0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // OCTET STRING community "public"
            0xA4, 0x2D,                     // Trap PDU, length 45
            0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID enterprise
            0x40, 0x04, 0xC0, 0xA8, 0x01, 0x01, // IpAddress agent-addr (192.168.1.1)
            0x02, 0x01, 0x06,              // INTEGER generic-trap (6 = enterpriseSpecific)
            0x02, 0x01, 0x01,              // INTEGER specific-trap (1)
            0x43, 0x03, 0x12, 0x34, 0x56,  // TimeTicks time-stamp
            0x30, 0x00                      // SEQUENCE varbind list (empty)
        };
        
        parse_snmp(sample_trap, sizeof(sample_trap), SNMP_TRAP_PORT, 12345);
        
        return 0;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("any", BUFSIZ, 1, 1000, errbuf);
    
    if (handle == NULL) {
        printf("Error opening device: %s\n", errbuf);
        printf("Try running as root: sudo ./snmp_analyzer\n");
        return 1;
    }
    
    struct bpf_program fp;
    char filter_exp[] = "udp port 161 or udp port 162";
    
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        printf("Error compiling filter\n");
        return 1;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        printf("Error setting filter\n");
        return 1;
    }
    
    printf("Capturing SNMP packets... Press Ctrl+C to stop\n");
    printf("Try running SNMP commands like: snmpget, snmpwalk, or snmptrap\n\n");
    
    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_close(handle);
    
    return 0;
}
#endif