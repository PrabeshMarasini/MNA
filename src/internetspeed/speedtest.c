#include "speedtest.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>

#define BUFFER_SIZE 8192
#define DOWNLOAD_TIMEOUT_SECONDS 30
#define UPLOAD_TIMEOUT_SECONDS 60

typedef struct {
    const char *hostname;
    int port;
    const char *path;
    const char *name;
    int file_size_mb;
} ServerInfo;

// List of test servers
static const ServerInfo download_servers[] = {
    {"cachefly.cachefly.net", 80, "/1mb.test", "Cachefly", 1},
    {"speedtest.tele2.net", 80, "/1MB.zip", "Tele2", 1},
    {"ipv4.download.thinkbroadband.com", 80, "/1MB.zip", "ThinkBroadband", 1},
    {NULL, 0, NULL, NULL, 0} // Terminator
};

static const ServerInfo upload_servers[] = {
    {"httpbin.org", 80, "/post", "HTTPBin", 0},
    {"postman-echo.com", 80, "/post", "PostmanEcho", 0},
    {"requestbin.com", 80, "/api/v1/bin", "RequestBin", 0},
    {NULL, 0, NULL, NULL, 0} // Terminator
};

// Get time in milliseconds
static long long get_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// Resolve hostname to IP address
static int resolve_hostname(const char *hostname, struct in_addr *addr) {
    struct hostent *he = gethostbyname(hostname);
    if (he == NULL) {
        return -1;
    }
    memcpy(addr, he->h_addr_list[0], sizeof(struct in_addr));
    return 0;
}

// Create HTTP GET request
static char* create_http_get_request(const char *hostname, const char *path) {
    static char request[1024];
    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: SpeedTest/1.0\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, hostname);
    return request;
}

// Create HTTP POST request
static char* create_http_post_request(const char *hostname, const char *path, size_t content_length) {
    static char request[1024];
    snprintf(request, sizeof(request),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: SpeedTest/1.0\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, hostname, content_length);
    return request;
}

// Parse HTTP response and skip headers
static int skip_http_headers(int sock, char *buffer, size_t buffer_size) {
    size_t total_received = 0;
    int headers_found = 0;
    char *body_start = NULL;
    
    while (!headers_found && total_received < buffer_size - 1) {
        ssize_t received = recv(sock, buffer + total_received, buffer_size - total_received - 1, 0);
        if (received <= 0) {
            return -1;
        }
        
        total_received += received;
        buffer[total_received] = '\0';
        
        // Look for end of headers
        body_start = strstr(buffer, "\r\n\r\n");
        if (body_start != NULL) {
            headers_found = 1;
            body_start += 4; // Skip \r\n\r\n
        }
    }
    
    if (!headers_found) {
        return -1;
    }
    
    // Calculate how much actual data we have after headers
    size_t body_length = total_received - (body_start - buffer);
    
    // Move body data to beginning of buffer
    if (body_length > 0) {
        memmove(buffer, body_start, body_length);
        return body_length;
    }
    
    return 0;
}

// Test download speed using raw sockets
static double test_socket_download(const ServerInfo *server) {
    int sock = -1;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    size_t total_bytes = 0;
    long long start_time, end_time;
    double speed_mbps = -1.0;
    
    printf("Testing download from %s...\n", server->name);
    
    // Resolve hostname
    if (resolve_hostname(server->hostname, &server_addr.sin_addr) < 0) {
        printf("Failed to resolve hostname: %s\n", server->hostname);
        return -1.0;
    }
    
    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("Failed to create socket\n");
        return -1.0;
    }
    
    // Set up server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server->port);
    
    // Connect to server
    printf("Connecting to %s:%d...\n", server->hostname, server->port);
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("Failed to connect to server\n");
        close(sock);
        return -1.0;
    }
    
    // Create and send HTTP request
    char *request = create_http_get_request(server->hostname, server->path);
    if (send(sock, request, strlen(request), 0) < 0) {
        printf("Failed to send request\n");
        close(sock);
        return -1.0;
    }
    
    printf("Downloading file...\n");
    
    // Skip HTTP headers
    int body_bytes = skip_http_headers(sock, buffer, BUFFER_SIZE);
    if (body_bytes < 0) {
        printf("Failed to parse HTTP headers\n");
        close(sock);
        return -1.0;
    }
    
    total_bytes = body_bytes;
    
    // Start timing
    start_time = get_time_ms();
    
    // Receive data
    while (1) {
        ssize_t received = recv(sock, buffer, BUFFER_SIZE, 0);
        if (received <= 0) {
            break;
        }
        total_bytes += received;
        
        // Check timeout
        if ((get_time_ms() - start_time) > (DOWNLOAD_TIMEOUT_SECONDS * 1000)) {
            printf("Download timeout reached\n");
            break;
        }
    }
    
    // End timing
    end_time = get_time_ms();
    
    // Calculate speed
    double time_seconds = (end_time - start_time) / 1000.0;
    if (time_seconds > 0) {
        speed_mbps = (total_bytes * 8.0) / (time_seconds * 1000000.0);
        printf("Downloaded: %.2f MB in %.2f seconds\n", total_bytes / (1024.0 * 1024.0), time_seconds);
    }
    
    close(sock);
    return speed_mbps;
}

// Generate random data for upload testing
static void generate_random_data(char *buffer, size_t size) {
    for (size_t i = 0; i < size; i++) {
        buffer[i] = rand() % 256;
    }
}

// Test upload speed using raw sockets
static double test_socket_upload(const ServerInfo *server) {
    int sock = -1;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    size_t total_bytes = 0;
    size_t upload_size = 10 * 1024 * 1024; // 10MB
    long long start_time, end_time;
    double speed_mbps = -1.0;
    
    printf("Testing upload to %s...\n", server->name);
    
    // Resolve hostname
    if (resolve_hostname(server->hostname, &server_addr.sin_addr) < 0) {
        printf("Failed to resolve hostname: %s\n", server->hostname);
        return -1.0;
    }
    
    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("Failed to create socket\n");
        return -1.0;
    }
    
    // Set socket send timeout to prevent hanging
    struct timeval send_timeout;
    send_timeout.tv_sec = 10;
    send_timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout));
    
    // Set socket receive timeout to prevent hanging
    struct timeval recv_timeout;
    recv_timeout.tv_sec = 10;
    recv_timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof(recv_timeout));
    
    // Set up server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server->port);
    
    // Connect to server with timeout
    printf("Connecting to %s:%d...\n", server->hostname, server->port);
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("Failed to connect to server\n");
        close(sock);
        return -1.0;
    }
    
    // Create and send HTTP POST request
    char *request = create_http_post_request(server->hostname, server->path, upload_size);
    if (send(sock, request, strlen(request), 0) < 0) {
        printf("Failed to send request\n");
        close(sock);
        return -1.0;
    }
    
    printf("Uploading %zu MB of data...\n", upload_size / (1024 * 1024));
    
    // Start timing
    start_time = get_time_ms();
    
    // Send data
    size_t remaining = upload_size;
    while (remaining > 0) {
        size_t to_send = (remaining < BUFFER_SIZE) ? remaining : BUFFER_SIZE;
        
        // Generate random data
        generate_random_data(buffer, to_send);
        
        ssize_t sent = send(sock, buffer, to_send, 0);
        if (sent <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("Send timeout\n");
            } else {
                printf("Failed to send data (errno: %d)\n", errno);
            }
            break;
        }
        
        total_bytes += sent;
        remaining -= sent;
        
        // Check timeout
        if ((get_time_ms() - start_time) > (UPLOAD_TIMEOUT_SECONDS * 1000)) {
            printf("Upload timeout reached\n");
            break;
        }
    }
    
    // End timing
    end_time = get_time_ms();
    
    // Receive response (and discard it)
    printf("Receiving server response...\n");
    long long response_start = get_time_ms();
    while (1) {
        ssize_t received = recv(sock, buffer, BUFFER_SIZE, 0);
        if (received <= 0) {
            // Break on error or timeout
            if (received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    printf("Receive timeout\n");
                } else {
                    printf("Error receiving response: %d\n", errno);
                }
            }
            break;
        }
        
        // Check timeout for response
        if ((get_time_ms() - response_start) > (10 * 1000)) { // 10 second timeout for response
            printf("Response timeout reached\n");
            break;
        }
    }
    
    // Calculate speed
    double time_seconds = (end_time - start_time) / 1000.0;
    if (time_seconds > 0) {
        speed_mbps = (total_bytes * 8.0) / (time_seconds * 1000000.0);
        printf("Uploaded: %.2f MB in %.2f seconds\n", total_bytes / (1024.0 * 1024.0), time_seconds);
    }
    
    close(sock);
    return speed_mbps;
}

// Test download speed with multiple servers
double test_download_speed(void) {
    double best_speed = -1.0;
    const ServerInfo *best_server = NULL;
    
    printf("Testing download speed using raw sockets...\n\n");
    
    // Try each server
    for (int i = 0; download_servers[i].hostname != NULL; i++) {
        double speed = test_socket_download(&download_servers[i]);
        if (speed > best_speed) {
            best_speed = speed;
            best_server = &download_servers[i];
        }
        printf("\n");
        sleep(1); // Small delay between tests
    }
    
    if (best_speed > 0 && best_server != NULL) {
        printf("Best download speed: %.2f Mbps from %s\n", best_speed, best_server->name);
    }
    
    return best_speed;
}

// Test upload speed with multiple servers
double test_upload_speed(void) {
    double best_speed = -1.0;
    const ServerInfo *best_server = NULL;
    
    printf("\nTesting upload speed using raw sockets...\n\n");
    
    // Try each server
    for (int i = 0; upload_servers[i].hostname != NULL; i++) {
        double speed = test_socket_upload(&upload_servers[i]);
        if (speed > best_speed) {
            best_speed = speed;
            best_server = &upload_servers[i];
        }
        printf("\n");
        sleep(1); // Small delay between tests
    }
    
    if (best_speed > 0 && best_server != NULL) {
        printf("Best upload speed: %.2f Mbps to %s\n", best_speed, best_server->name);
    }
    
    return best_speed;
}

int run_speedtest(void) {
    double download_speed, upload_speed;
    
    printf("=== Internet Speed Test (Socket Version) ===\n\n");
    
    // Seed random number generator
    srand(time(NULL));
    
    // Test download speed
    download_speed = test_download_speed();
    
    if (download_speed > 0) {
        printf("Download Speed: %.2f Mbps\n", download_speed);
    } else {
        printf("Download test failed!\n");
    }
    
    // Test upload speed
    upload_speed = test_upload_speed();
    
    if (upload_speed > 0) {
        printf("Upload Speed: %.2f Mbps\n", upload_speed);
    } else {
        printf("Upload test failed!\n");
    }
    
    printf("\n=== Results ===\n");
    if (download_speed > 0) {
        printf("Download: %.2f Mbps (%.2f MB/s)\n", download_speed, download_speed / 8.0);
    }
    if (upload_speed > 0) {
        printf("Upload: %.2f Mbps (%.2f MB/s)\n", upload_speed, upload_speed / 8.0);
    }
    
    return (download_speed > 0 && upload_speed > 0) ? 0 : 1;
}

int main() {
    return run_speedtest();
}