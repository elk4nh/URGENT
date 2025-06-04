#!/bin/bash
#!/bin/bash

# Make all Python scripts executable
chmod +x *.py

# Make all shell scripts executable
chmod +x *.sh

# Fix permissions for Tor configuration directory
if [ -d "/etc/tor" ]; then
    chmod 755 /etc/tor
    chown -R debian-tor:debian-tor /etc/tor
fi

# Set proper permissions for data directories
if [ -d "./tor_data" ]; then
    chmod -R 700 ./tor_data
    chown -R debian-tor:debian-tor ./tor_data
fi

echo "[+] Permissions fixed"

# Check script permissions
ls -la *.py *.sh

echo "[*] You can now run the setup script: sudo ./setup.sh"
# Make all Python scripts executable
chmod +x *.py

# Make all shell scripts executable
chmod +x *.sh

# Fix permissions for Tor configuration directory
if [ -d "/etc/tor" ]; then
    chmod 755 /etc/tor
    chown -R debian-tor:debian-tor /etc/tor
fi

# Set proper permissions for data directories
if [ -d "./tor_data" ]; then
    chmod -R 700 ./tor_data
    chown -R debian-tor:debian-tor ./tor_data
fi

echo "[+] Permissions fixed"

# Check script permissions
ls -la *.py *.sh

echo "[*] You can now run the setup script: sudo ./setup.sh"
