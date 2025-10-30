#ifndef LATENCY_H
#define LATENCY_H

double test_dns_latency(const char *hostname);
double test_udp_latency(const char *hostname, int port);
double test_https_latency(const char *hostname, int port);
int run_latency_tests(void);

#endif