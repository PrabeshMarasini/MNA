#!/bin/bash

own_ip=$(hostname -I | awk '{print $1}')
own_mac=$(ip link show | awk '/ether/ {print $2}' | head -n 1)
own_host=$(hostname)

echo -e "Your Device:"
echo -e "IPV4\t\tMAC Address\t\tDevice Name"
echo -e "$own_ip\t$own_mac\t$own_host"
echo

echo "Scanning LAN for other devices..."
echo -e "Other Devices:"
echo -e "IPV4\t\tMAC Address\t\tDevice Name"

subnet=$(ip -4 route show default | awk '{print $3}' | cut -d'.' -f1-3).0/24

for ip in $(seq 1 254); do
    ping -c 1 -W 1 192.168.1.$ip > /dev/null &
done wait

arp -n | grep -v "incomplete" | while read -r line; do
    ip=$(echo $line | awk '{print $1}')
    mac=$(echo $line | awk '{print $3}')
    name=$(getent hosts $ip | awk '{print $2}')
    [ "$ip" != "$own_ip" ] && echo -e "$ip\t$mac\t$name"
done