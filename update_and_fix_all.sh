#!/bin/bash

# Script untuk memperbaiki semua masalah dalam project Tor Proxy Manager
echo "Tor Proxy Manager - Fix and Update Script"

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Terminate any running processes that might interfere
echo "Stopping any running processes..."
pkill -f "tor_proxy_setup.py"
pkill -f "multi_sqlmap_runner.py"
pkill -f "proxy_tester.py"

# Fix any permission issues
echo "Fixing permissions..."
chmod +x *.sh *.py

# Fix imports in Python files
echo "Checking and fixing Python imports..."

# Function to ensure a file has socket imported
fix_socket_import() {
    file=$1
    if [ -f "$file" ]; then
        if ! grep -q "import socket" "$file"; then
            echo "Adding socket import to $file"
            sed -i '/import random/a import socket' "$file"
        fi
    fi
}

# Add socket import to all main Python files
fix_socket_import "multi_sqlmap_runner.py"
fix_socket_import "proxy_tester.py"
fix_socket_import "browser_leak_test.py"
fix_socket_import "tor_proxy_setup.py"

# Run our dedicated fix script
echo "Running multi_sqlmap_runner fix script..."
python3 fix_multi_sqlmap_runner.py

# Install all dependencies
echo "Installing/updating dependencies..."
pip3 install -r requirements.txt
./install_dependencies.sh

# Fix DNS issues
./dns_fix.sh

# Restart Tor service
echo "Restarting Tor service..."
systemctl restart tor

# Run a quick test
echo "Testing Tor connection..."
if command -v /usr/local/bin/test-tor &> /dev/null; then
    /usr/local/bin/test-tor
else
    python3 tor_proxy_setup.py --create-test
    /usr/local/bin/test-tor
fi

echo "All fixes applied. Your Tor Proxy Manager should now be working correctly."
echo "If you're still experiencing issues, please try running the full setup script:"
echo "sudo ./setup.sh"
