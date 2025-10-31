#include "mac.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <curl/curl.h>

// Structure to hold HTTP response data
struct MemoryStruct {
    char *memory;
    size_t size;
};

// Callback function to write HTTP response data
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, struct MemoryStruct *userp) {
    size_t realsize = size * nmemb;
    char *ptr = realloc(userp->memory, userp->size + realsize + 1);
    if (ptr == NULL) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    userp->memory = ptr;
    memcpy(&(userp->memory[userp->size]), contents, realsize);
    userp->size += realsize;
    userp->memory[userp->size] = 0;

    return realsize;
}

// Function to validate MAC address format
int validate_mac_address(const char* mac_address) {
    if (mac_address == NULL) {
        return 0;
    }

    int len = strlen(mac_address);
    if (len != 17) {
        return 0;
    }

    // Check format XX:XX:XX:XX:XX:XX
    for (int i = 0; i < 17; i++) {
        if (i % 3 == 2) {
            if (mac_address[i] != ':') {
                return 0;
            }
        } else {
            if (!isxdigit(mac_address[i])) {
                return 0;
            }
        }
    }

    return 1;
}

// Normalize MAC address to uppercase
void normalize_mac_address(const char* input, char* output) {
    for (int i = 0; i < 17; i++) {
        output[i] = toupper(input[i]);
    }
    output[17] = '\0';
}

// Lookup MAC address vendor using macvendors.co API
int lookup_mac_vendor_macvendors(const char* mac_address, MacVendorInfo* info) {
    CURL *curl_handle;
    CURLcode res;
    struct MemoryStruct chunk;
    long http_code = 0;
    
    chunk.memory = malloc(1);
    chunk.size = 0;

    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();

    if (curl_handle) {
        char url[256];
        snprintf(url, sizeof(url), "https://api.macvendors.com/%s", mac_address);
        
        curl_easy_setopt(curl_handle, CURLOPT_URL, url);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
        curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 10L);

        res = curl_easy_perform(curl_handle);
        
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            curl_easy_cleanup(curl_handle);
            curl_global_cleanup();
            free(chunk.memory);
            return -1;
        }
        
        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);
        
        if (http_code == 200 && chunk.size > 0) {
            strncpy(info->vendor_name, chunk.memory, sizeof(info->vendor_name) - 1);
            info->vendor_name[sizeof(info->vendor_name) - 1] = '\0';
            curl_easy_cleanup(curl_handle);
            curl_global_cleanup();
            free(chunk.memory);
            return 0;
        }
    }
    
    curl_easy_cleanup(curl_handle);
    curl_global_cleanup();
    free(chunk.memory);
    return -1;
}

// Main function to lookup MAC address vendor
int lookup_mac_vendor(const char* mac_address, MacVendorInfo* info) {
    if (!validate_mac_address(mac_address)) {
        return -1;
    }
    
    // Initialize the structure
    memset(info, 0, sizeof(MacVendorInfo));
    normalize_mac_address(mac_address, info->mac_address);
    
    // Try macvendors.co API
    printf("Looking up vendor for MAC address: %s\n", info->mac_address);
    
    if (lookup_mac_vendor_macvendors(info->mac_address, info) == 0) {
        printf("Vendor found: %s\n", info->vendor_name);
        return 0;
    } else {
        printf("Vendor information not found for MAC address: %s\n", info->mac_address);
        strncpy(info->vendor_name, "Unknown vendor", sizeof(info->vendor_name) - 1);
        return -1;
    }
}

// Main function to run MAC address lookup
int run_mac_lookup(const char* mac_address) {
    MacVendorInfo info;
    
    printf("=== MAC Address Vendor Lookup ===\n\n");
    
    int result = lookup_mac_vendor(mac_address, &info);
    
    if (result == 0) {
        printf("\n=== Results ===\n");
        printf("MAC Address: %s\n", info.mac_address);
        printf("Vendor: %s\n", info.vendor_name);
        if (strlen(info.vendor_address) > 0) {
            printf("Address: %s\n", info.vendor_address);
        }
    } else {
        printf("\n=== Results ===\n");
        printf("MAC Address: %s\n", mac_address);
        printf("Vendor: Unknown\n");
        printf("Error: Could not retrieve vendor information\n");
        return 1;
    }
    
    return 0;
}