#ifndef SSH_H
#define SSH_H

#include <stdint.h>
#include <pcap.h>  // for u_char

// SSH Protocol Constants
#define SSH_PORT 22
#define SSH_VERSION_EXCHANGE_MAX 255
#define SSH_PACKET_MIN_SIZE 5

// SSH Message Types (RFC 4253)
#define SSH_MSG_DISCONNECT 1
#define SSH_MSG_IGNORE 2
#define SSH_MSG_UNIMPLEMENTED 3
#define SSH_MSG_DEBUG 4
#define SSH_MSG_SERVICE_REQUEST 5
#define SSH_MSG_SERVICE_ACCEPT 6
#define SSH_MSG_KEXINIT 20
#define SSH_MSG_NEWKEYS 21
#define SSH_MSG_KEXDH_INIT 30
#define SSH_MSG_KEXDH_REPLY 31
#define SSH_MSG_USERAUTH_REQUEST 50
#define SSH_MSG_USERAUTH_FAILURE 51
#define SSH_MSG_USERAUTH_SUCCESS 52
#define SSH_MSG_USERAUTH_BANNER 53
#define SSH_MSG_GLOBAL_REQUEST 80
#define SSH_MSG_REQUEST_SUCCESS 81
#define SSH_MSG_REQUEST_FAILURE 82
#define SSH_MSG_CHANNEL_OPEN 90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION 91
#define SSH_MSG_CHANNEL_OPEN_FAILURE 92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST 93
#define SSH_MSG_CHANNEL_DATA 94
#define SSH_MSG_CHANNEL_EXTENDED_DATA 95
#define SSH_MSG_CHANNEL_EOF 96
#define SSH_MSG_CHANNEL_CLOSE 97
#define SSH_MSG_CHANNEL_REQUEST 98
#define SSH_MSG_CHANNEL_SUCCESS 99
#define SSH_MSG_CHANNEL_FAILURE 100

// SSH Connection States
typedef enum {
    SSH_STATE_VERSION_EXCHANGE,
    SSH_STATE_KEY_EXCHANGE,
    SSH_STATE_AUTHENTICATION,
    SSH_STATE_ENCRYPTED_SESSION,
    SSH_STATE_DISCONNECTED
} ssh_state_t;

// SSH Connection Info
typedef struct {
    ssh_state_t state;
    char client_version[256];
    char server_version[256];
    int client_port;
    int server_port;
    uint32_t client_ip;
    uint32_t server_ip;
    int auth_attempts;
    char username[64];
    char auth_method[32];
    int key_exchange_done;
} ssh_connection_t;

// Function declarations
void parse_ssh(const u_char *payload, int payload_len, int src_port, int dst_port);
void parse_ssh_version_exchange(const u_char *payload, int payload_len, int src_port, int dst_port);
void parse_ssh_binary_packet(const u_char *payload, int payload_len, int src_port, int dst_port);
void parse_ssh_kexinit(const u_char *payload, int payload_len);
void parse_ssh_userauth(const u_char *payload, int payload_len, uint8_t msg_type);
void parse_ssh_channel_data(const u_char *payload, int payload_len);
const char* get_ssh_message_type_name(uint8_t msg_type);
const char* get_ssh_disconnect_reason(uint32_t reason_code);
void print_ssh_algorithms(const u_char *data, int len, const char *type);
void redact_sensitive_ssh_data(char *data, int len);

#endif // SSH_H