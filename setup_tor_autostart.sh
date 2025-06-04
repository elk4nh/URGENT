#!/bin/bash

# setup_tor_autostart.sh - Script to setup automatic starting of Tor proxy and monitoring

MONITOR_SCRIPT="/tor_monitor.sh"
PROXY_SCRIPT="/tor_proxy_setup.py"

# Make scripts executable
chmod +x "$MONITOR_SCRIPT"
chmod +x "$PROXY_SCRIPT"

# First, install required packages if not already installed
echo "[*] Installing necessary packages..."
sudo python3 "$PROXY_SCRIPT" --install

# Setup Firefox proxy configuration
echo "[*] Setting up Firefox proxy configuration..."
sudo python3 "$PROXY_SCRIPT" --setup-firefox

# Create a systemd service file for the monitor script
echo "[*] Creating systemd service for Tor monitor..."

cat > /tmp/tor-monitor.service << EOF
[Unit]
Description=Tor Proxy Monitor Service
After=network.target tor.service

[Service]
Type=simple
ExecStart=/bin/bash $MONITOR_SCRIPT
Restart=always
RestartSec=5
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

# Move the service file to systemd directory
sudo mv /tmp/tor-monitor.service /etc/systemd/system/

# Reload systemd, enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable tor-monitor.service
sudo systemctl start tor-monitor.service

# Setup a cron job to check and ensure the monitor is running every 10 minutes
echo "[*] Setting up cron job to ensure monitor is running..."

# Create a temporary cron file
cat > /tmp/tor-monitor-cron << EOF
# Check and restart tor-monitor service every 10 minutes
*/10 * * * * root systemctl is-active --quiet tor-monitor.service || systemctl restart tor-monitor.service
EOF

# Install the cron job
sudo mv /tmp/tor-monitor-cron /etc/cron.d/tor-monitor
sudo chmod 644 /etc/cron.d/tor-monitor

echo "[+] Setup completed successfully!"
echo "[+] The Tor proxy service is now running and will automatically restart if stopped."
echo "[+] You can check the status with: sudo systemctl status tor-monitor.service"
echo "[+] Monitor logs are available at: /var/log/tor_monitor.log"
