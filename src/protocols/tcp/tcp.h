#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include <pcap.h>
#include <netinet/tcp.h>

// TCP Protocol Constants
#define TCP_MIN_HEADER_SIZE 20
#define TCP_MAX_HEADER_SIZE 60
#define TCP_MAX_WINDOW_SIZE 65535
#define TCP_MAX_PAYLOAD_SIZE 65495

// TCP Flags
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20
#define TCP_FLAG_ECE 0x40
#define TCP_FLAG_CWR 0x80

// TCP Options
#define TCP_OPT_EOL 0
#define TCP_OPT_NOP 1
#define TCP_OPT_MSS 2
#define TCP_OPT_WINDOW_SCALE 3
#define TCP_OPT_SACK_PERMITTED 4
#define TCP_OPT_SACK 5
#define TCP_OPT_TIMESTAMP 8

// TCP Connection States
typedef enum {
    TCP_STATE_CLOSED,
    TCP_STATE_LISTEN,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECEIVED,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_CLOSING,
    TCP_STATE_LAST_ACK,
    TCP_STATE_TIME_WAIT
} tcp_state_t;

// TCP Connection Info
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    tcp_state_t state;
    uint16_t window_size;
    uint16_t mss;
    uint8_t window_scale;
    int sack_permitted;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    int retransmissions;
} tcp_connection_t;

// TCP Option Structure
typedef struct {
    uint8_t kind;
    uint8_t length;
    uint8_t data[40];
} tcp_option_t;

// Function declarations
void parse_tcp(const u_char *payload, int payload_len);
void parse_tcp_with_context(const u_char *payload, int payload_len, uint32_t src_ip, uint32_t dst_ip);
void parse_tcp_header(const struct tcphdr *tcp_hdr, int header_len);
void parse_tcp_options(const u_char *options, int options_len);
void parse_tcp_payload(const u_char *payload, int payload_len, uint16_t src_port, uint16_t dst_port);
void analyze_tcp_flags(uint8_t flags);
void analyze_tcp_performance(const struct tcphdr *tcp_hdr, int payload_len);
void analyze_tcp_security(const struct tcphdr *tcp_hdr, uint16_t src_port, uint16_t dst_port);
const char* get_tcp_flag_string(uint8_t flags);
const char* get_tcp_state_name(tcp_state_t state);
const char* get_tcp_option_name(uint8_t option_kind);
const char* detect_application_protocol(uint16_t src_port, uint16_t dst_port, const u_char *payload, int len);
tcp_state_t determine_tcp_state(uint8_t flags, int is_response);
int is_tcp_retransmission(uint32_t seq, uint32_t last_seq, int payload_len);
void print_tcp_statistics(const tcp_connection_t *conn);

#endif // TCP_H
