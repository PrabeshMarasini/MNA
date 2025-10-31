#ifndef MAC_H
#define MAC_H

// Structure to hold MAC address vendor information
typedef struct {
    char mac_address[18];  // Format: "00:00:00:00:00:00"
    char vendor_name[256];
    char vendor_address[512];
} MacVendorInfo;

// Function to lookup MAC address vendor using free API
int lookup_mac_vendor(const char* mac_address, MacVendorInfo* info);

// Function to validate MAC address format
int validate_mac_address(const char* mac_address);

// Main function to run MAC address lookup
int run_mac_lookup(const char* mac_address);

#endif