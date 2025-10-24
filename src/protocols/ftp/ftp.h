#ifndef FTP_H
#define FTP_H

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#include <stdint.h>
#include <sys/types.h>
#include <pcap.h>

// FTP command structure
typedef struct {
    char command[16];
    char argument[256];
    int is_sensitive;
} ftp_command_t;

// FTP response structure
typedef struct {
    int code;
    char message[512];
    int is_multiline;
} ftp_response_t;

// FTP session statistics
typedef struct {
    uint64_t total_packets;
    uint64_t client_commands;
    uint64_t server_responses;
    uint64_t login_attempts;
    uint64_t file_transfers;
    uint64_t data_connections;
    char last_user[64];
    char last_file[256];
} ftp_stats_t;

// Function declarations
void parse_ftp(const u_char *payload, int payload_len, int src_port, int dst_port);
void parse_ftp_command(const char *line);
void parse_ftp_response(const char *line);
void print_ftp_stats(void);
void reset_ftp_stats(void);
int is_printable_ascii(const u_char *data, int len);
int is_sensitive_command(const char *command);
void redact_sensitive_data(char *line, const char *command);

#endif // FTP_H
