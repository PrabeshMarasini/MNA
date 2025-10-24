#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include "https.h"

// TLS record types
#define TLS_HANDSHAKE 22

// Statistics tracking
static struct {
    int client_hellos;
    int server_hellos;
    int weak_ciphers;
    int weak_versions;
    int tls_versions[10];
    time_t start_time;
} tls_stats = {0};

// Get TLS version name
const char* get_tls_version_name(uint16_t version) {
    switch (version) {
        case 0x0300: return "SSL 3.0";
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        default: return "Unknown";
    }
}

// Check if TLS version is weak/deprecated
int is_weak_tls_version(uint16_t version) {
    switch (version) {
        case 0x0300: // SSL 3.0
        case 0x0301: // TLS 1.0
        case 0x0302: // TLS 1.1
            return 1;
        default:
            return 0;
    }
}

// Get cipher suite name
const char* get_cipher_suite_name(uint16_t cipher_suite) {
    switch (cipher_suite) {
        // TLS 1.3 cipher suites
        case 0x1301: return "TLS_AES_128_GCM_SHA256";
        case 0x1302: return "TLS_AES_256_GCM_SHA384";
        case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
        case 0x1304: return "TLS_AES_128_CCM_SHA256";
        case 0x1305: return "TLS_AES_128_CCM_8_SHA256";
        
        // TLS 1.2 cipher suites
        case 0x009C: return "TLS_RSA_WITH_AES_128_GCM_SHA256";
        case 0x009D: return "TLS_RSA_WITH_AES_256_GCM_SHA384";
        case 0x002F: return "TLS_RSA_WITH_AES_128_CBC_SHA";
        case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA";
        case 0x003C: return "TLS_RSA_WITH_AES_128_CBC_SHA256";
        case 0x003D: return "TLS_RSA_WITH_AES_256_CBC_SHA256";
        
        // ECDHE cipher suites
        case 0xC02B: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
        case 0xC02C: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
        case 0xC02F: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        case 0xC030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
        case 0xC00A: return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
        case 0xC009: return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
        case 0xC013: return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
        case 0xC014: return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
        
        // ChaCha20 cipher suites
        case 0xCCA8: return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
        case 0xCCA9: return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
        
        // Weak/deprecated cipher suites
        case 0x0000: return "TLS_NULL_WITH_NULL_NULL";
        case 0x0001: return "TLS_RSA_WITH_NULL_MD5";
        case 0x0002: return "TLS_RSA_WITH_NULL_SHA";
        case 0x0003: return "TLS_RSA_EXPORT_WITH_RC4_40_MD5";
        case 0x0004: return "TLS_RSA_WITH_RC4_128_MD5";
        case 0x0005: return "TLS_RSA_WITH_RC4_128_SHA";
        case 0x000A: return "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
        
        default: return "Unknown";
    }
}

// Check if cipher suite is weak/deprecated
int is_weak_cipher_suite(uint16_t cipher_suite) {
    switch (cipher_suite) {
        // NULL ciphers
        case 0x0000: case 0x0001: case 0x0002:
        // RC4 ciphers (deprecated)
        case 0x0003: case 0x0004: case 0x0005:
        // 3DES (deprecated)
        case 0x000A:
            return 1;
        default:
            return 0;
    }
}

// Helper to print hex
__attribute__((unused))
static void print_hex(const u_char *data, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
}

// Parse TLS ClientHello to extract version, cipher suites, and SNI (if present)
void parse_tls_client_hello(const u_char *payload, int payload_len) {
    if (payload_len < 5) {
        printf("TLS packet too short\n");
        return;
    }

    // TLS record header: ContentType(1), Version(2), Length(2)
    uint8_t content_type = payload[0];
    uint16_t version = ntohs(*(uint16_t *)(payload + 1));
    uint16_t record_len = ntohs(*(uint16_t *)(payload + 3));

    if (content_type != TLS_HANDSHAKE) {
        printf("Not a TLS handshake record\n");
        return;
    }

    if (record_len + 5 > payload_len) {
        printf("Incomplete TLS record\n");
        return;
    }

    // Handshake header starts at payload+5
    const u_char *handshake = payload + 5;
    int handshake_len = record_len;

    if (handshake_len < 4) {
        printf("Handshake message too short\n");
        return;
    }

    uint8_t handshake_type = handshake[0];
    // Handshake length is 3 bytes
    uint32_t hs_len __attribute__((unused)) = (handshake[1] << 16) | (handshake[2] << 8) | handshake[3];

    if (handshake_type != 1) {
        printf("Not a ClientHello handshake message\n");
        return;
    }

    printf("=== TLS ClientHello ===\n");
    printf("TLS Version: 0x%04x (%s)\n", version, get_tls_version_name(version));
    if (is_weak_tls_version(version)) {
        printf("⚠️  WARNING: Weak TLS version detected!\n");
        tls_stats.weak_versions++;
    }

    // Skip past handshake header (4 bytes)
    int pos = 4;

    if (pos + 2 > handshake_len) return;
    uint16_t client_version = ntohs(*(uint16_t *)(handshake + pos));
    pos += 2;
    printf("Client Version: 0x%04x (%s)\n", client_version, get_tls_version_name(client_version));
    tls_stats.client_hellos++;

    // Skip Random (32 bytes)
    pos += 32;

    // Session ID
    if (pos + 1 > handshake_len) return;
    uint8_t session_id_len = handshake[pos];
    pos += 1 + session_id_len;

    if (pos + 2 > handshake_len) return;

    // Cipher Suites
    uint16_t cipher_suites_len = ntohs(*(uint16_t *)(handshake + pos));
    pos += 2;

    if (pos + cipher_suites_len > handshake_len) return;

    printf("Cipher Suites Offered (%d bytes):\n", cipher_suites_len);
    for (int i = 0; i < cipher_suites_len; i += 2) {
        uint16_t cs = ntohs(*(uint16_t *)(handshake + pos + i));
        const char* cs_name = get_cipher_suite_name(cs);
        printf("  0x%04x - %s", cs, cs_name);
        if (is_weak_cipher_suite(cs)) {
            printf(" ⚠️  WEAK");
            tls_stats.weak_ciphers++;
        }
        printf("\n");
    }
    pos += cipher_suites_len;

    // Compression Methods
    if (pos + 1 > handshake_len) return;
    uint8_t comp_methods_len = handshake[pos];
    pos += 1 + comp_methods_len;

    // Extensions
    if (pos + 2 > handshake_len) return;
    uint16_t ext_len = ntohs(*(uint16_t *)(handshake + pos));
    pos += 2;

    int ext_end = pos + ext_len;
    if (ext_end > handshake_len) return;

    printf("Extensions:\n");

    while (pos + 4 <= ext_end) {
        uint16_t ext_type = ntohs(*(uint16_t *)(handshake + pos));
        uint16_t ext_size = ntohs(*(uint16_t *)(handshake + pos + 2));
        pos += 4;

        if (pos + ext_size > ext_end) break;

        if (ext_type == 0x00) { // Server Name Indication (SNI)
            // SNI format: list length (2 bytes), then hostname length(2 bytes) + hostname
            int sni_pos = pos;
            if (sni_pos + 2 > ext_end) break;
            uint16_t sni_list_len __attribute__((unused)) = ntohs(*(uint16_t *)(handshake + sni_pos));
            sni_pos += 2;

            while (sni_pos + 3 <= pos + ext_size) {
                uint8_t name_type = handshake[sni_pos];
                sni_pos++;
                uint16_t name_len = ntohs(*(uint16_t *)(handshake + sni_pos));
                sni_pos += 2;

                if (sni_pos + name_len > pos + ext_size) break;

                if (name_type == 0) { // host_name
                    char server_name[256];
                    if (name_len >= sizeof(server_name)) name_len = sizeof(server_name) - 1;
                    memcpy(server_name, handshake + sni_pos, name_len);
                    server_name[name_len] = '\0';
                    printf("  SNI (Server Name): %s\n", server_name);
                }
                sni_pos += name_len;
            }
        } else {
            printf("  Extension type: 0x%04x, length %d\n", ext_type, ext_size);
        }

        pos += ext_size;
    }
    printf("========================\n");
}

// Parse TLS ServerHello message
void parse_tls_server_hello(const u_char *payload, int payload_len) {
    if (payload_len < 9) {
        printf("TLS ServerHello packet too short\n");
        return;
    }
    
    // Skip TLS record header (5 bytes) and handshake header (4 bytes)
    const u_char *handshake = payload + 5;
    int handshake_len = payload_len - 5;
    
    if (handshake_len < 4) {
        printf("Handshake message too short\n");
        return;
    }
    
    // Skip handshake type and length (4 bytes)
    const u_char *server_hello = handshake + 4;
    int server_hello_len = handshake_len - 4;
    
    if (server_hello_len < 38) { // Minimum ServerHello size
        printf("ServerHello message too short\n");
        return;
    }
    
    // Parse ServerHello
    uint16_t version = ntohs(*(uint16_t *)server_hello);
    printf("  TLS Version: %s (0x%04x)\n", get_tls_version_name(version), version);
    
    if (is_weak_tls_version(version)) {
        printf("  WARNING: Weak TLS version detected!\n");
        tls_stats.weak_versions++;
    }
    
    // Skip random (32 bytes) and session ID length (1 byte)
    int pos = 2 + 32 + 1;
    if (pos < server_hello_len) {
        pos += server_hello[pos - 1]; // Skip session ID
    }
    
    // Parse cipher suite (2 bytes)
    if (pos + 2 <= server_hello_len) {
        uint16_t cipher_suite = ntohs(*(uint16_t *)(server_hello + pos));
        printf("  Selected Cipher Suite: %s (0x%04x)\n", 
               get_cipher_suite_name(cipher_suite), cipher_suite);
        
        if (is_weak_cipher_suite(cipher_suite)) {
            printf("  WARNING: Weak cipher suite selected!\n");
            tls_stats.weak_ciphers++;
        }
        pos += 2;
    }
    
    // Parse compression method (1 byte)
    if (pos + 1 <= server_hello_len) {
        uint8_t compression = server_hello[pos];
        printf("  Compression Method: %d\n", compression);
        pos += 1;
    }
    
    tls_stats.server_hellos++;
    printf("========================\n");
}

// Parse TLS handshake messages
void parse_tls_handshake(const u_char *payload, int payload_len) {
    if (payload_len < 5) {
        printf("TLS packet too short for handshake\n");
        return;
    }
    
    // TLS record header: type(1) + version(2) + length(2)
    uint8_t content_type = payload[0];
    uint16_t version = ntohs(*(uint16_t *)(payload + 1));
    uint16_t length = ntohs(*(uint16_t *)(payload + 3));
    
    printf("TLS Record - Type: 0x%02x, Version: %s, Length: %d\n", 
           content_type, get_tls_version_name(version), length);
    
    if (content_type == TLS_HANDSHAKE && payload_len >= 9) {
        // Handshake message: type(1) + length(3) + data
        uint8_t handshake_type = payload[5];
        
        switch (handshake_type) {
            case 1: // ClientHello
                printf("TLS ClientHello detected\n");
                parse_tls_client_hello(payload, payload_len);
                break;
            case 2: // ServerHello
                printf("TLS ServerHello detected\n");
                parse_tls_server_hello(payload, payload_len);
                break;
            case 11: // Certificate
                printf("TLS Certificate message\n");
                break;
            case 12: // ServerKeyExchange
                printf("TLS ServerKeyExchange message\n");
                break;
            case 14: // ServerHelloDone
                printf("TLS ServerHelloDone message\n");
                break;
            case 16: // ClientKeyExchange
                printf("TLS ClientKeyExchange message\n");
                break;
            case 20: // Finished
                printf("TLS Finished message\n");
                break;
            default:
                printf("TLS Handshake message type: %d\n", handshake_type);
                break;
        }
    }
}

// Print TLS statistics
void print_tls_statistics(void) {
    printf("\n=== TLS Statistics ===\n");
    printf("Client Hellos: %d\n", tls_stats.client_hellos);
    printf("Server Hellos: %d\n", tls_stats.server_hellos);
    printf("Weak Ciphers Detected: %d\n", tls_stats.weak_ciphers);
    printf("Weak TLS Versions: %d\n", tls_stats.weak_versions);
    printf("=====================\n");
}
