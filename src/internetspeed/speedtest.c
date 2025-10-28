#include "speedtest.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <time.h>
#include <math.h>

// Callback function for download which counts bytes
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    MemoryStruct *mem = (MemoryStruct *)userp;
    mem->size += realsize;
    (void)contents; // Unused parameter
    return realsize;
}

// Callback function for upload - provides data
static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp) {
    size_t *upload_size = (size_t *)userp;
    size_t max = size * nmemb;
    
    if (*upload_size == 0) {
        return 0; // Done uploading
    }
    
    size_t to_send = (*upload_size < max) ? *upload_size : max;
    
    // Fill with random data
    for (size_t i = 0; i < to_send; i++) {
        ((char *)ptr)[i] = rand() % 256;
    }
    
    *upload_size -= to_send;
    return to_send;
}

// Test download speed
double test_download_speed(void) {
    CURL *curl;
    CURLcode res;
    MemoryStruct chunk;
    struct timespec start, end;
    double time_spent, speed_mbps;
    
    chunk.size = 0;
    
    // 10MB test file from public server
    const char *url = "http://speedtest.tele2.net/10MB.zip";
    
    printf("Testing download speed...\n");
    printf("Downloading 10MB test file...\n");
    
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl\n");
        return -1;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    
    // Start timer
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    // Perform download
    res = curl_easy_perform(curl);
    
    // Stop timer
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    if (res != CURLE_OK) {
        fprintf(stderr, "Download failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return -1;
    }
    
    curl_easy_cleanup(curl);
    
    // Calculate time in seconds
    time_spent = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    
    // Calculate speed in Mbps (Megabits per second)
    speed_mbps = (chunk.size * 8.0) / (time_spent * 1000000.0);
    
    printf("Downloaded: %.2f MB in %.2f seconds\n", chunk.size / (1024.0 * 1024.0), time_spent);
    
    return speed_mbps;
}

// Test upload speed
double test_upload_speed(void) {
    CURL *curl;
    CURLcode res;
    struct timespec start, end;
    double time_spent, speed_mbps;
    size_t upload_size = 10 * 1024 * 1024; // 10MB
    size_t original_size = upload_size;
    
    // Using httpbin.org for upload test
    const char *url = "https://httpbin.org/post";
    
    printf("\nTesting upload speed...\n");
    printf("Uploading 10MB test data...\n");
    
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl\n");
        return -1;
    }
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl, CURLOPT_READDATA, &upload_size);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)original_size);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    
    // Discard server response
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    MemoryStruct dummy = {0};
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&dummy);
    
    // Start timer
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    // Perform upload
    res = curl_easy_perform(curl);
    
    // Stop timer
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    if (res != CURLE_OK) {
        fprintf(stderr, "Upload failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return -1;
    }
    
    curl_easy_cleanup(curl);
    
    // Calculate time in seconds
    time_spent = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    
    // Calculate speed in Mbps
    speed_mbps = (original_size * 8.0) / (time_spent * 1000000.0);
    
    printf("Uploaded: %.2f MB in %.2f seconds\n", original_size / (1024.0 * 1024.0), time_spent);
    
    return speed_mbps;
}

int run_speedtest(void) {
    double download_speed, upload_speed;
    
    printf("=== Internet Speed Test ===\n\n");
    
    // Initialize curl globally
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Seed random number generator for upload data
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
    
    // Cleanup
    curl_global_cleanup();
    
    return (download_speed > 0 && upload_speed > 0) ? 0 : 1;
}

int main() {
    return run_speedtest();
}