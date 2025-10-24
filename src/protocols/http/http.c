#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "http.h"

// Statistics tracking
static struct {
    int requests;
    int responses;
    int get_requests;
    int post_requests;
    int status_200;
    int status_404;
    int status_500;
    int security_headers_missing;
    time_t start_time;
} http_stats = {0};

// Get HTTP method name
const char* get_http_method_name(const char *method) {
    if (strcmp(method, "GET") == 0) return "GET";
    if (strcmp(method, "POST") == 0) return "POST";
    if (strcmp(method, "PUT") == 0) return "PUT";
    if (strcmp(method, "DELETE") == 0) return "DELETE";
    if (strcmp(method, "HEAD") == 0) return "HEAD";
    if (strcmp(method, "OPTIONS") == 0) return "OPTIONS";
    if (strcmp(method, "PATCH") == 0) return "PATCH";
    return "UNKNOWN";
}

// Get status code description
const char* get_status_code_description(int status_code) {
    switch (status_code) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 500: return "Internal Server Error";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        default: return "Unknown";
    }
}

// Check if header is a security header
int is_security_header(const char *header_name) {
    const char *security_headers[] = {
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "x-xss-protection",
        "referrer-policy",
        "permissions-policy"
    };
    
    for (int i = 0; i < 7; i++) {
        if (strcasecmp(header_name, security_headers[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

// Print HTTP statistics
void print_http_statistics(void) {
    printf("\n=== HTTP Statistics ===\n");
    printf("Total Requests: %d\n", http_stats.requests);
    printf("Total Responses: %d\n", http_stats.responses);
    printf("GET Requests: %d\n", http_stats.get_requests);
    printf("POST Requests: %d\n", http_stats.post_requests);
    printf("200 OK Responses: %d\n", http_stats.status_200);
    printf("404 Not Found: %d\n", http_stats.status_404);
    printf("500 Server Error: %d\n", http_stats.status_500);
    printf("Missing Security Headers: %d\n", http_stats.security_headers_missing);
    printf("======================\n");
}

void parse_http(const u_char *payload, int payload_len) {
    if (payload_len <= 0) return;

    const char *data = (const char *)payload;
    
    // Check if it's a request or response
    if (strncmp(data, "HTTP/", 5) == 0) {
        // It's a response
        parse_http_response(data, payload_len);
    } else {
        // It's a request
        parse_http_request(data, payload_len);
    }
}

// Parse HTTP request
void parse_http_request(const char *data, int len) {
    if (len <= 0) return;
    
    const char *end = data + len;
    const char *line_start = data;
    
    // Find end of first line
    while (data < end && *data != '\r' && *data != '\n') {
        data++;
    }
    
    // Parse request line: METHOD URI HTTP/VERSION
    char method[16], uri[512], version[16];
    if (sscanf(line_start, "%15s %511s %15s", method, uri, version) == 3) {
        printf("=== HTTP Request ===\n");
        printf("Method: %s (%s)\n", method, get_http_method_name(method));
        printf("URI: %s\n", uri);
        printf("Version: %s\n", version);
        
        // Update statistics
        http_stats.requests++;
        if (strcmp(method, "GET") == 0) http_stats.get_requests++;
        if (strcmp(method, "POST") == 0) http_stats.post_requests++;
        
        // Check for sensitive data in URL
        if (strstr(uri, "password") || strstr(uri, "token") || strstr(uri, "key")) {
            printf("⚠️  WARNING: Sensitive data in URL!\n");
        }
    }
    
    // Parse headers
    printf("Headers:\n");
    data = line_start;
    while (data < end) {
        // Skip to next line
        while (data < end && *data != '\r' && *data != '\n') data++;
        while (data < end && (*data == '\r' || *data == '\n')) data++;
        
        if (data >= end) break;
        
        const char *header_start = data;
        while (data < end && *data != '\r' && *data != '\n') data++;
        
        // Extract header name
        char header_name[64];
        const char *colon = strchr(header_start, ':');
        if (colon && colon < data) {
            int name_len = colon - header_start;
            if (name_len < (int)sizeof(header_name)) {
                strncpy(header_name, header_start, name_len);
                header_name[name_len] = '\0';
                
                // Check if it's a security header
                if (is_security_header(header_name)) {
                    printf("  %.*s 🔒\n", (int)(data - header_start), header_start);
                } else {
                    printf("  %.*s\n", (int)(data - header_start), header_start);
                }
            }
        }
    }
    printf("====================\n");
}

// Parse HTTP response
void parse_http_response(const char *data, int len) {
    if (len <= 0) return;
    
    const char *end = data + len;
    const char *line_start = data;
    
    // Find end of first line
    while (data < end && *data != '\r' && *data != '\n') {
        data++;
    }
    
    // Parse response line: HTTP/VERSION STATUS_CODE REASON_PHRASE
    char version[16], reason[128];
    int status_code;
    if (sscanf(line_start, "%15s %d %127s", version, &status_code, reason) == 3) {
        printf("=== HTTP Response ===\n");
        printf("Version: %s\n", version);
        printf("Status: %d (%s)\n", status_code, get_status_code_description(status_code));
        printf("Reason: %s\n", reason);
        
        // Update statistics
        http_stats.responses++;
        if (status_code == 200) http_stats.status_200++;
        if (status_code == 404) http_stats.status_404++;
        if (status_code >= 500) http_stats.status_500++;
        
        // Security warnings
        if (status_code == 301 || status_code == 302) {
            printf("⚠️  WARNING: HTTP redirect detected!\n");
        }
    }
    
    // Parse headers
    printf("Headers:\n");
    data = line_start;
    int security_headers_found = 0;
    while (data < end) {
        // Skip to next line
        while (data < end && *data != '\r' && *data != '\n') data++;
        while (data < end && (*data == '\r' || *data == '\n')) data++;
        
        if (data >= end) break;
        
        const char *header_start = data;
        while (data < end && *data != '\r' && *data != '\n') data++;
        
        // Extract header name
        char header_name[64];
        const char *colon = strchr(header_start, ':');
        if (colon && colon < data) {
            int name_len = colon - header_start;
            if (name_len < (int)sizeof(header_name)) {
                strncpy(header_name, header_start, name_len);
                header_name[name_len] = '\0';
                
                // Check if it's a security header
                if (is_security_header(header_name)) {
                    printf("  %.*s 🔒\n", (int)(data - header_start), header_start);
                    security_headers_found++;
                } else {
                    printf("  %.*s\n", (int)(data - header_start), header_start);
                }
            }
        }
    }
    
    // Check for missing security headers
    if (security_headers_found == 0) {
        printf("⚠️  WARNING: No security headers found!\n");
        http_stats.security_headers_missing++;
    }
    
    printf("=====================\n");
}
