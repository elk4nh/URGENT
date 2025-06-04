#!/bin/bash

# tor_monitor.sh - Script to monitor and restart the Tor proxy setup script if it stops

SCRIPT_PATH="/tor_proxy_setup.py"
LOG_FILE="/var/log/tor_monitor.log"
INTERVAL=60 # Rotation interval in seconds

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Check if the script exists
if [ ! -f "$SCRIPT_PATH" ]; then
    log_message "Error: Script not found at $SCRIPT_PATH"
    exit 1
fi

# Make sure the script is executable
chmod +x "$SCRIPT_PATH"

# Function to check if the script is running
check_script_running() {
    pgrep -f "python3 $SCRIPT_PATH --daemon" > /dev/null
    return $?
}

# Function to start the script
start_script() {
    log_message "Starting Tor proxy script with interval $INTERVAL seconds..."
    python3 "$SCRIPT_PATH" --daemon --interval "$INTERVAL" >> "$LOG_FILE" 2>&1 &
    sleep 5
    if check_script_running; then
        log_message "Tor proxy script started successfully."
    else
        log_message "Failed to start Tor proxy script."
    fi
}

# Main monitoring loop
log_message "Starting monitor for Tor proxy script"

while true; do
    if ! check_script_running; then
        log_message "Tor proxy script is not running. Restarting..."
        start_script
    else
        log_message "Tor proxy script is running."
    fi

    # Check again after 5 minutes
    sleep 300
done
