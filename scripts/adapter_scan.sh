#!/bin/bash

echo -e "Network Adapters on this device:\n"
printf "%-15s %-20s %-17s %-10s\n" "Interface" "IP Address" "MAC Address" "State"
echo "----------------------------------------------------------------------------"

for iface in $(ls /sys/class/net); do
    ip=$(ip -4 addr show "$iface" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "N/A")
    mac=$(cat /sys/class/net/$iface/address)
    state=$(cat /sys/class/net/$iface/operstate)
    printf "%-15s %-20s %-17s %-10s\n" "$iface" "$ip" "$mac" "$state"
done
