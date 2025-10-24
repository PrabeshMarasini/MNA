#!/bin/bash
# Check if arp-scan is installed
if ! command -v arp-scan &> /dev/null; then
    echo "arp-scan is not installed. Install it with: sudo pacman -S arp-scan"
    exit 1
fi

# Detect default network interface
iface=$(ip route | grep '^default' | awk '{print $5}' | head -n1)
if [ -z "$iface" ]; then
    echo "Could not detect network interface."
    exit 1
fi

# Get own IP and MAC
my_ip=$(ip -4 addr show "$iface" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
my_mac=$(cat /sys/class/net/"$iface"/address)

# Get gateway IP
gateway_ip=$(ip route | grep '^default' | awk '{print $3}' | head -n1)

echo "Your Device:"
echo -e "IPV4\t\tMAC Address"
echo -e "$my_ip\t$my_mac"
echo

# Scan LAN using arp-scan and store results (filter out summary lines)
scan_results=$(sudo arp-scan --localnet --interface="$iface" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')

# Find gateway MAC
gateway_mac=""
if [ -n "$gateway_ip" ]; then
    gateway_mac=$(echo "$scan_results" | awk -v gw="$gateway_ip" '$1 == gw {print $2}')
fi

echo "Gateway (Router):"
echo -e "IPV4\t\tMAC Address"
if [ -n "$gateway_ip" ] && [ -n "$gateway_mac" ]; then
    echo -e "$gateway_ip\t$gateway_mac"
else
    echo "Gateway not found in scan results"
fi
echo

echo "Other Devices:"
echo -e "IPV4\t\tMAC Address"
echo "$scan_results" | awk -v my_ip="$my_ip" -v gw_ip="$gateway_ip" '{ 
    if ($1 != my_ip && $1 != gw_ip) 
        printf "%-16s %s\n", $1, $2 
}'

echo "Scan complete."