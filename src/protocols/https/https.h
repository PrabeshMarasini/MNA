#ifndef HTTPS_H
#define HTTPS_H

#include <pcap.h>
#include <stdint.h>

// Function declarations
void parse_tls_client_hello(const u_char *payload, int payload_len);
void parse_tls_server_hello(const u_char *payload, int payload_len);
void parse_tls_handshake(const u_char *payload, int payload_len);
const char* get_cipher_suite_name(uint16_t cipher_suite);
const char* get_tls_version_name(uint16_t version);
int is_weak_cipher_suite(uint16_t cipher_suite);
int is_weak_tls_version(uint16_t version);
void print_tls_statistics(void);

#endif