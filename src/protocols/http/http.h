#ifndef HTTP_H
#define HTTP_H

#include <pcap.h>
#include <stdint.h>

// Function declarations
void parse_http(const u_char *payload, int payload_len);
void parse_http_request(const char *data, int len);
void parse_http_response(const char *data, int len);
const char* get_http_method_name(const char *method);
const char* get_status_code_description(int status_code);
int is_security_header(const char *header_name);
void print_http_statistics(void);

#endif // HTTP_H
