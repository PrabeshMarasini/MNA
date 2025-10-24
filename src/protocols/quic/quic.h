#ifndef QUIC_H
#define QUIC_H

#include <stdint.h>
#include <pcap.h>

// QUIC Protocol Constants
#define QUIC_PORT 443
#define QUIC_ALT_PORT 80
#define QUIC_MAX_CID_LENGTH 20

// QUIC Versions
#define QUIC_VERSION_1 0x00000001
#define QUIC_VERSION_DRAFT_29 0xff00001d
#define QUIC_VERSION_NEGOTIATION 0x00000000

// QUIC Packet Types
#define QUIC_PACKET_INITIAL 0x0
#define QUIC_PACKET_0RTT 0x1
#define QUIC_PACKET_HANDSHAKE 0x2
#define QUIC_PACKET_RETRY 0x3

// Function declarations
void parse_quic(const u_char *payload, int payload_len, int src_port, int dst_port);
void parse_quic_long_header(const u_char *data, int len, uint8_t first_byte);
void parse_quic_short_header(const u_char *data, int len, uint8_t first_byte);
int read_quic_varint(const u_char *data, int len, uint64_t *value_out);
const char* get_quic_packet_type_name(uint8_t packet_type);
const char* get_quic_version_name(uint32_t version);
void print_quic_connection_id(const uint8_t *cid, int len, const char *label);
int is_quic_traffic(int src_port, int dst_port);
int detect_quic_packet(const u_char *payload, int payload_len);

#endif // QUIC_H