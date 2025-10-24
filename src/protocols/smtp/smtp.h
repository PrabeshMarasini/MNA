#ifndef SMTP_H
#define SMTP_H

#include <stdint.h>
#include <pcap.h>  // for u_char

// Parse SMTP traffic
void parse_smtp(const u_char *payload, int payload_len, int src_port, int dst_port);

#endif // SMTP_H
