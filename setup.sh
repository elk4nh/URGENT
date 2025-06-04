#!/bin/bash

# Simple setup script for tor_proxy_setup.py

# Make sure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

SCRIPT_PATH="$(pwd)/tor_proxy_setup.py"

# Check if the script exists
if [ ! -f "$SCRIPT_PATH" ]; then
    echo "Error: tor_proxy_setup.py not found in the current directory"
    exit 1
fi

# Check Python3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Python3 is not installed. Installing..."
    apt update && apt install -y python3
    if [ $? -ne 0 ]; then
        echo "Failed to install Python3. Please install it manually."
        exit 1
    fi
fi

# Make script executable
chmod +x "$SCRIPT_PATH"

# ASCII Art Banner
cat << "EOF"
  _______            ______                      
 /_  __(_)__  ___   / ____/___ ___  _____  ___  
  / / / / _ \/ _ \ / / __/ __ \/ _ \/ __ \/ _ \ 
 / / / /  __/ /_/ / /_/ / /_/ /  __/ / / /  __/ 
/_/ /_/\___/\___/ \____/ .___/\___/_/ /_/\___/  
                      /_/                       
EOF

echo "======= Tor Proxy Manager Setup ======="
echo "This script will set up Tor as a proxy with automatic IP rotation."
echo "Perfect for CLI-only VPS systems!"
echo ""

# Ask for interval time
read -p "Enter IP rotation interval in seconds (default: 60): " INTERVAL
INTERVAL=${INTERVAL:-60}

# Validate interval input is a number
if ! [[ "$INTERVAL" =~ ^[0-9]+$ ]]; then
    echo "Error: Interval must be a number. Setting to default: 60"
    INTERVAL=60
fi

# Warn if interval is too short
if [ "$INTERVAL" -lt 10 ]; then
    echo "Warning: A very short interval (less than 10 seconds) may cause performance issues."
    read -p "Continue anyway? (y/n): " CONTINUE
    if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
        echo "Setup aborted. Please run again with a longer interval."
        exit 0
    fi
fi

# Ask for number of Tor instances
read -p "Enter number of Tor instances to set up (1-10, default: 1): " NUM_INSTANCES
NUM_INSTANCES=${NUM_INSTANCES:-1}

# Validate number of instances
if ! [[ "$NUM_INSTANCES" =~ ^[0-9]+$ ]]; then
    echo "Error: Number of instances must be a number. Setting to default: 1"
    NUM_INSTANCES=1
fi

if [ "$NUM_INSTANCES" -lt 1 ]; then
    echo "Error: Number of instances must be at least 1. Setting to default: 1"
    NUM_INSTANCES=1
fi

if [ "$NUM_INSTANCES" -gt 10 ]; then
    echo "Warning: A large number of instances may consume significant resources."
    read -p "Continue anyway? (y/n): " CONTINUE
    if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
        echo "Setup aborted. Please run again with fewer instances."
        exit 0
    fi
fi

# Perform installation and setup
echo "[*] Installing and configuring Tor, proxychains4, sqlmap, and curl..."
python3 "$SCRIPT_PATH" --install

if [ $? -ne 0 ]; then
    echo "[!] Setup encountered an error. Please check the output above."
    exit 1
fi

# Setup Firefox proxy
python3 "$SCRIPT_PATH" --setup-firefox

# Create test script
python3 "$SCRIPT_PATH" --create-test

# Setup auto-restart
python3 "$SCRIPT_PATH" --auto-restart --interval "$INTERVAL"

# Set up multiple Tor instances if requested
if [ "$NUM_INSTANCES" -gt 1 ]; then
    echo "[*] Setting up $NUM_INSTANCES Tor instances..."
    python3 "$SCRIPT_PATH" --multi-tor "$NUM_INSTANCES"

    # Make multi_sqlmap_runner.py and recover_sqlmap.sh executable
    if [ -f "./multi_sqlmap_runner.py" ]; then
        chmod +x ./multi_sqlmap_runner.py
    fi

    if [ -f "./recover_sqlmap.sh" ]; then
        chmod +x ./recover_sqlmap.sh
    fi

    # Start daemon for all instances
    echo "[*] Starting IP rotation daemon for all instances..."
    nohup python3 "$SCRIPT_PATH" --multi-tor "$NUM_INSTANCES" --daemon --interval "$INTERVAL" > /tmp/tor_rotation.log 2>&1 &
else
    # Start standard daemon
    echo "[*] Starting IP rotation daemon..."
    nohup python3 "$SCRIPT_PATH" --daemon --interval "$INTERVAL" > /tmp/tor_rotation.log 2>&1 &
fi

# Display success message and usage instructions
echo "\n======= Setup Completed Successfully! ======="
echo "Tor proxy is now running with IP rotation every $INTERVAL seconds"
echo ""
echo "Quick Usage Guide:"
echo "  • Run commands through Tor:    proxychains4 <command>"
echo "  • Test your connection:        /usr/local/bin/test-tor"
echo "  • Start Firefox with Tor:      /usr/local/bin/firefox-tor"
echo "  • Check current Tor IP:        sudo python3 $SCRIPT_PATH --status"
echo "  • Manually rotate IP:          sudo python3 $SCRIPT_PATH --rotate"
echo ""
if [ "$NUM_INSTANCES" -gt 1 ]; then
    echo "Multi-Tor Configuration:"
    echo "  • Test all proxies:            sudo python3 proxy_tester.py --test"
    echo "  • Run comprehensive tests:      sudo python3 proxy_tester.py --test --verbose"
    echo "  • List all proxy instances:     sudo python3 proxy_tester.py --list"
    echo "  • Browser leak testing:         sudo python3 browser_leak_test.py --list"
    echo "  • Run SQLMap on all instances:  sudo python3 multi_sqlmap_runner.py -i $NUM_INSTANCES -u <url>"
fi
echo ""
echo "The service will automatically restart if it stops running."
echo "=================================================="

# Offer to run the test script
read -p "Would you like to test your Tor connection now? (y/n): " TEST_NOW
if [[ "$TEST_NOW" =~ ^[Yy]$ ]]; then
    /usr/local/bin/test-tor
fi
