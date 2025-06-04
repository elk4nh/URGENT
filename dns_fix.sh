#!/bin/bash

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Backup resolv.conf
cp /etc/resolv.conf /etc/resolv.conf.backup

# Use Google DNS and Cloudflare DNS
echo "nameserver 8.8.8.8
nameserver 1.1.1.1" > /etc/resolv.conf

# Restart networking and DNS services
systemctl restart systemd-resolved 2>/dev/null
resolvconf -u 2>/dev/null

# Check Tor connectivity
echo "[*] Testing Tor connectivity..."
if systemctl is-active --quiet tor; then
    systemctl restart tor
    sleep 2
    if curl --socks5 127.0.0.1:9050 -s https://check.torproject.org/ | grep -q "Congratulations"; then
        echo "[+] Tor is working correctly!"
    else
        echo "[!] Tor is running but connection test failed"
    fi
else
    echo "[!] Tor service is not running"
    systemctl start tor
    echo "[*] Started Tor service"
fi
