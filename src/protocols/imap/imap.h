#ifndef IMAP_H
#define IMAP_H

#include <pcap.h>  // for u_char

// Parse IMAP packet
void parse_imap(const u_char *payload, int payload_len, int src_port, int dst_port);

#endif // IMAP_H
