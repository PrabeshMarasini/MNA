#ifndef TRACEROUTE_H
#define TRACEROUTE_H

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MAX_HOPS 30
#define MAX_PROBES 3
#define DEFAULT_TIMEOUT 3
#define DEFAULT_MAX_TTL 30
#define PACKET_SIZE 64

typedef struct {
    int hop_number;
    char ip_address[INET6_ADDRSTRLEN];
    char hostname[256];
    double response_times[MAX_PROBES];
    int status[MAX_PROBES]; // 0 = success, 1 = timeout, 2 = unreachable
    int probe_count;
} TracerouteHop;

typedef struct {
    char target_host[256];
    char target_ip[INET6_ADDRSTRLEN];
    int total_hops;
    TracerouteHop hops[MAX_HOPS];
    double total_time;
} TracerouteResult;

int run_traceroute(const char* target_host);
int perform_traceroute(const char* target_host, TracerouteResult* results);
void print_traceroute_results(const TracerouteResult* results);
int resolve_hostname(const char* hostname, struct in_addr* addr);

#endif