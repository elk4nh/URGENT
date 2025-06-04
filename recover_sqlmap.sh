#!/bin/bash

# Script to monitor and restart sqlmap processes if they die

# Configuration
TARGET_URL="$1"
SQLMAP_ARGS="$2"
TOR_INSTANCE="$3"
LOG_DIR="/tmp/sqlmap_logs"
ROTATE_INTERVAL=60  # Seconds

# Check if required arguments are provided
if [ -z "$TARGET_URL" ]; then
    echo "Error: Target URL is required"
    echo "Usage: $0 <target_url> [sqlmap_args] [tor_instance]"
    exit 1
fi

# Create log directory
mkdir -p "$LOG_DIR"

# Determine which Tor instance to use
if [ -z "$TOR_INSTANCE" ]; then
    PROXY_PORT=9050
    PROXY_CONFIG="/etc/proxychains4.conf"
else
    PROXY_PORT=$((9050 + TOR_INSTANCE))
    PROXY_CONFIG="/etc/proxychains4.conf.$PROXY_PORT"
fi

# Prepare command
CMD="proxychains4 -f $PROXY_CONFIG sqlmap -u \"$TARGET_URL\" --batch --random-agent $SQLMAP_ARGS"
LOG_FILE="$LOG_DIR/sqlmap_instance_${TOR_INSTANCE:-main}_$(date +%Y%m%d_%H%M%S).log"

echo "Starting sqlmap with the following configuration:"
echo "Target URL: $TARGET_URL"
echo "SQLMap Args: $SQLMAP_ARGS"
echo "Tor Instance: ${TOR_INSTANCE:-main}"
echo "Proxy Port: $PROXY_PORT"
echo "Log File: $LOG_FILE"
echo "Command: $CMD"
echo ""

# Function to rotate Tor IP
rotate_tor_ip() {
    echo "[$(date)] Rotating Tor IP for instance ${TOR_INSTANCE:-main}..."
    if [ -z "$TOR_INSTANCE" ]; then
        sudo python3 ./tor_proxy_setup.py --rotate
    else
        sudo python3 ./tor_proxy_setup.py --rotate --instance $TOR_INSTANCE
    fi
}

# Function to monitor and restart sqlmap
monitor_sqlmap() {
    while true; do
        echo "[$(date)] Starting sqlmap process..." | tee -a "$LOG_FILE"
        echo "Command: $CMD" | tee -a "$LOG_FILE"

        # Start sqlmap and get its PID
        $CMD >> "$LOG_FILE" 2>&1 &
        SQLMAP_PID=$!

        echo "[$(date)] sqlmap started with PID: $SQLMAP_PID" | tee -a "$LOG_FILE"

        # Monitor the process
        LAST_ROTATE=$(date +%s)
        while kill -0 $SQLMAP_PID 2>/dev/null; do
            NOW=$(date +%s)
            # Check if it's time to rotate IP
            if [ $((NOW - LAST_ROTATE)) -ge $ROTATE_INTERVAL ]; then
                rotate_tor_ip
                LAST_ROTATE=$NOW
            fi
            sleep 5
        done

        # Process died, check exit status
        wait $SQLMAP_PID
        EXIT_STATUS=$?

        echo "[$(date)] sqlmap process exited with status: $EXIT_STATUS" | tee -a "$LOG_FILE"

        if [ $EXIT_STATUS -eq 0 ]; then
            echo "[$(date)] sqlmap completed successfully." | tee -a "$LOG_FILE"
            break
        else
            echo "[$(date)] sqlmap failed or was interrupted. Restarting in 5 seconds..." | tee -a "$LOG_FILE"
            sleep 5
        fi
    done
}

# Start monitoring in the background so this script can be run with nohup
monitor_sqlmap &

echo "[$(date)] Monitor started in background. Check $LOG_FILE for output."
echo "You can safely close this terminal."
