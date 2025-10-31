#ifndef DNS_H
#define DNS_H

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MAX_DNS_RECORDS 50
#define MAX_RECORD_LENGTH 512
#define DEFAULT_DNS_TIMEOUT 5

typedef struct {
    char type[16];           // Record type (A, AAAA, MX, etc.)
    char data[MAX_RECORD_LENGTH];  // Record data
    int priority;            // Priority (for MX records)
    unsigned int ttl;        // Time to live
} DnsRecord;

typedef struct {
    char hostname[256];
    char query_type[16];
    int record_count;
    DnsRecord records[MAX_DNS_RECORDS];
    char dns_server[INET6_ADDRSTRLEN];
    double query_time_ms;
    int status;              // 0 = success, -1 = error
    char error_message[256];
} DnsLookupResult;

int run_dns_lookup(const char* target);
int perform_dns_lookup(const char* target, const char* record_type, DnsLookupResult* results);
void print_dns_results(const DnsLookupResult* results);
int resolve_hostname(const char* hostname, struct in_addr* addr);
int reverse_dns_lookup(const char* ip_address, char* hostname, size_t hostname_size);

#endif