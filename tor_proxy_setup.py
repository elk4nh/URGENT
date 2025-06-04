#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import argparse
import re
import threading
import random
import signal
from datetime import datetime

def run_command(command):
    """Run a shell command and return the output"""
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {command}")
        print(f"Error message: {e.stderr}")
        return None

def install_packages():
    """Install required packages: tor, proxychains4, sqlmap, curl and utilities"""
    print("[*] Updating package lists...")
    run_command("sudo apt update")

    print("[*] Installing tor, proxychains4, sqlmap, curl and needed utilities...")
    run_command("sudo apt install -y tor proxychains4 sqlmap curl netcat-openbsd python3-pip screen")

    # Check if Firefox is installed, if not suggest installing it
    firefox_installed = run_command("which firefox")
    if not firefox_installed:
        print("[!] Firefox is not installed. It's recommended for the proxy setup.")
        install_firefox = input("Do you want to install Firefox? (y/n): ").strip().lower()
        if install_firefox == 'y':
            print("[*] Installing Firefox...")
            run_command("sudo apt install -y firefox-esr")

    # Configure tor for IP rotation
    print("[*] Configuring Tor for IP rotation...")
    torrc_path = "/etc/tor/torrc"

    # Backup original torrc if it exists
    if os.path.exists(torrc_path):
        run_command(f"sudo cp {torrc_path} {torrc_path}.backup")

    # Add necessary configurations to torrc
    tor_config = """
# Configuration for IP rotation
ControlPort 9051
CookieAuthentication 1
SocksPort 9050
"""

    with open("/tmp/torrc_addition", "w") as f:
        f.write(tor_config)

    run_command(f"sudo bash -c 'cat /tmp/torrc_addition >> {torrc_path}'")

    # Configure proxychains to use Tor
    print("[*] Configuring proxychains to use Tor...")
    proxychains_path = "/etc/proxychains4.conf"

    # Backup original proxychains.conf if it exists
    if os.path.exists(proxychains_path):
        run_command(f"sudo cp {proxychains_path} {proxychains_path}.backup")

    # Make sure proxychains is configured to use Tor
    proxychains_config = """
# Add tor proxy
socks5 127.0.0.1 9050
"""

    with open("/tmp/proxychains_addition", "w") as f:
        f.write(proxychains_config)

    # Ensure the dynamic_chain option is enabled
    run_command(f"sudo sed -i 's/^#dynamic_chain/dynamic_chain/' {proxychains_path}")
    run_command(f"sudo sed -i 's/^strict_chain/#strict_chain/' {proxychains_path}")

    # Check if the socks5 line already exists, if not append it
    check_socks = run_command(f"grep -q 'socks5 127.0.0.1 9050' {proxychains_path} && echo 'exists' || echo 'not exists'")
    if check_socks == "not exists":
        run_command(f"sudo bash -c 'cat /tmp/proxychains_addition >> {proxychains_path}'")

    # Enable and start tor service
    print("[*] Starting Tor service...")
    run_command("sudo systemctl enable tor")
    run_command("sudo systemctl restart tor")

    # Wait for Tor to initialize
    print("[*] Waiting for Tor to initialize...")
    time.sleep(5)

    print("[+] Installation and configuration completed successfully!")

def check_tor_status():
    """Check if Tor service is running"""
    status = run_command("systemctl is-active tor")
    return status == "active"

def restart_tor(instance_num=None):
    """Restart the Tor service"""
    if instance_num is None:
        print("[*] Restarting main Tor service...")
        run_command("sudo systemctl restart tor")
        time.sleep(5)  # Wait for Tor to initialize
        print("[+] Tor service restarted")
    else:
        print(f"[*] Restarting Tor instance {instance_num}...")
        # Kill the specific Tor instance and restart it
        run_command(f"pkill -f 'tor --SocksPort {9050 + instance_num}'")
        time.sleep(1)
        start_tor_instance(instance_num)
        time.sleep(5)  # Wait for Tor to initialize
        print(f"[+] Tor instance {instance_num} restarted")

def get_current_ip(proxy_port=9050):
    """Get current Tor IP address using specific proxy port"""
    cmd = f"proxychains4 -f /etc/proxychains4.conf.{proxy_port} curl -s https://api.ipify.org"
    ip = run_command(cmd)
    if ip and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return ip
    return "Unknown"

def start_tor_instance(instance_num):
    """Start a separate Tor instance with a unique port"""
    socks_port = 9050 + instance_num
    control_port = 9051 + instance_num
    data_dir = f"/tmp/tor-data-{instance_num}"

    # Create data directory if it doesn't exist
    run_command(f"mkdir -p {data_dir}")

    # Start Tor with the specified ports
    cmd = f"tor --SocksPort {socks_port} --ControlPort {control_port} --DataDirectory {data_dir} --RunAsDaemon 1 --CookieAuthentication 1"
    result = run_command(cmd)

    # Create a custom proxychains configuration file for this instance
    proxychains_conf = f"/etc/proxychains4.conf.{socks_port}"
    run_command(f"cp /etc/proxychains4.conf {proxychains_conf}")

    # Update the socks5 line in the config
    run_command(f"sudo sed -i '/^socks5/d' {proxychains_conf}")
    run_command(f"echo 'socks5 127.0.0.1 {socks_port}' | sudo tee -a {proxychains_conf} > /dev/null")

    return socks_port, control_port

def setup_multiple_tor_instances(num_instances=5):
    """Setup multiple Tor instances with different ports"""
    print(f"[*] Setting up {num_instances} Tor instances...")

    # Create directory for Tor data
    run_command("mkdir -p /tmp/tor-data")

    instance_info = []
    for i in range(1, num_instances+1):
        print(f"[*] Setting up Tor instance {i}...")
        socks_port, control_port = start_tor_instance(i)
        instance_info.append({"instance": i, "socks_port": socks_port, "control_port": control_port})
        time.sleep(2)  # Give some time between instance starts

    # Wait for all instances to initialize
    print("[*] Waiting for all Tor instances to initialize...")
    time.sleep(10)

    # Verify all instances are working
    for instance in instance_info:
        i = instance["instance"]
        port = instance["socks_port"]
        ip = get_current_ip(port)
        print(f"[+] Tor instance {i} (port {port}) IP: {ip}")

    print(f"[+] Successfully set up {num_instances} Tor instances")
    return instance_info

    def verify_tor_connection():
    """Verify that Tor connection is working properly"""
    print("[*] Verifying Tor connection...")

    # Check if Tor service is running
    if not check_tor_status():
        print("[!] Tor service is not running. Starting it...")
        restart_tor()

    # Try to get IP through Tor
    ip = get_current_ip()
    if ip == "Unknown":
        print("[!] Could not connect through Tor. Trying to fix...")
        # Check if proxychains is configured correctly
        run_command("sudo sed -i 's/^#dynamic_chain/dynamic_chain/' /etc/proxychains4.conf")
        run_command("sudo sed -i 's/^strict_chain/#strict_chain/' /etc/proxychains4.conf")
        # Restart Tor and try again
        restart_tor()
        ip = get_current_ip()
        if ip == "Unknown":
            print("[!] Tor connection still failing. Please check your network configuration.")
            return False

    # Check if IP is different from direct connection
    direct_ip_cmd = "curl -s https://api.ipify.org"
    direct_ip = run_command(direct_ip_cmd)

    if direct_ip and ip and direct_ip == ip:
        print("[!] Warning: Your Tor IP matches your direct IP. Tor may not be working correctly.")
        return False

    print(f"[+] Tor connection verified! Your Tor IP is: {ip}")
    return True

    def rotate_ip(instance_num=None, control_port=9051):
    """Rotate Tor IP address for a specific instance or main Tor"""
    socks_port = 9050
    if instance_num is not None:
        socks_port = 9050 + instance_num
        control_port = 9051 + instance_num

    old_ip = get_current_ip(socks_port)
    print(f"[*] Current IP for port {socks_port}: {old_ip}")
    print(f"[*] Rotating IP address for port {socks_port}...")

    # Try different methods to send NEWNYM signal to Tor
    # First try with nc (netcat) which is more commonly available
    nc_result = run_command("which nc")
    if nc_result:
        # Password-less authentication (default configuration)
        run_command(f"echo -e 'AUTHENTICATE \"\"\nSIGNAL NEWNYM\nQUIT' | nc 127.0.0.1 {control_port}")
    else:
        # If nc is not available, try with socat
        socat_result = run_command("which socat")
        if socat_result:
            run_command(f"echo 'AUTHENTICATE \"\"\nSIGNAL NEWNYM\nQUIT' | socat - UNIX-CONNECT:/var/run/tor/control.{instance_num if instance_num else ''}")
        else:
            # Last resort, try to install netcat
            print("[!] Neither nc nor socat found. Attempting to install netcat...")
            run_command("sudo apt install -y netcat")
            run_command(f"echo -e 'AUTHENTICATE \"\"\nSIGNAL NEWNYM\nQUIT' | nc 127.0.0.1 {control_port}")

    # Wait for IP to change
    time.sleep(3)

    new_ip = get_current_ip(socks_port)
    print(f"[+] New IP for port {socks_port}: {new_ip}")

    # If IP didn't change, restart the Tor instance
    if old_ip == new_ip and old_ip != "Unknown":
        print(f"[!] IP rotation failed for port {socks_port}. Restarting Tor...")
        restart_tor(instance_num)
        time.sleep(3)
        new_ip = get_current_ip(socks_port)
        print(f"[+] New IP after restart for port {socks_port}: {new_ip}")

    return new_ip

def setup_firefox_proxy():
    """Configure Firefox to use Tor as proxy"""
    print("[*] Setting up Firefox to use Tor proxy...")

    # Create a script to launch Firefox with Tor proxy
    firefox_script_path = "/usr/local/bin/firefox-tor"
    firefox_script = """#!/bin/bash
# Script to launch Firefox with Tor proxy
firefox -no-remote -profile "$(mktemp -d)" \
    -P "TorProfile" \
    -preferences \
    -purgecaches \
    -new-instance \
    -proxy-server="socks5://127.0.0.1:9050" $@
"""

    with open("/tmp/firefox-tor", "w") as f:
        f.write(firefox_script)

    run_command("sudo mv /tmp/firefox-tor " + firefox_script_path)
    run_command(f"sudo chmod +x {firefox_script_path}")

    print(f"[+] Firefox proxy setup completed. Run '{firefox_script_path}' to launch Firefox with Tor proxy.")
    print("[+] Note: This is a CLI-only solution for VPS as requested.")

def create_test_script():
    """Create a script to test Tor connection and show IP info"""
    print("[*] Creating test connection script...")

    test_script_path = "/usr/local/bin/test-tor"
    test_script = """#!/bin/bash
# Script to test Tor connection and show IP information

# Function to measure latency
measure_latency() {
    local url=$1
    local proxy=$2
    local proxy_cmd=""
    local sum=0
    local count=3
    local timeout=10

    if [ -n "$proxy" ]; then
        proxy_cmd="proxychains4 -f $proxy"
    fi

    echo "Testing latency to $url..."
    for i in $(seq 1 $count); do
        start=$(date +%s.%N)
        $proxy_cmd curl -s -o /dev/null -m $timeout $url >/dev/null 2>&1
        exit_code=$?
        end=$(date +%s.%N)

        if [ $exit_code -eq 0 ]; then
            duration=$(echo "$end - $start" | bc)
            sum=$(echo "$sum + $duration" | bc)
            echo "  Request $i: ${duration}s"
        else
            echo "  Request $i: TIMEOUT"
        fi
    done

    avg=$(echo "scale=3; $sum / $count" | bc)
    echo "Average latency: ${avg}s"
}

# Parse command-line arguments
INSTANCE=
COMPREHENSIVE=false

while [[ $# -gt 0 ]]; do
  case $1 in
    -i|--instance)
      INSTANCE="$2"
      shift 2
      ;;
    -c|--comprehensive)
      COMPREHENSIVE=true
      shift
      ;;
    *)
      echo "Unknown argument: $1"
      echo "Usage: test-tor [-i|--instance NUM] [-c|--comprehensive]"
      exit 1
      ;;
  esac
done

# Determine which proxy config to use
if [ -n "$INSTANCE" ]; then
    if [ "$INSTANCE" -eq 0 ]; then
        PROXY_CONFIG="/etc/proxychains4.conf"
        echo "Testing main Tor instance..."
    else
        PORT=$((9050 + $INSTANCE))
        PROXY_CONFIG="/etc/proxychains4.conf.$PORT"
        echo "Testing Tor instance $INSTANCE (port $PORT)..."
    fi
else
    PROXY_CONFIG="/etc/proxychains4.conf"
    echo "Testing main Tor instance..."
fi

# Check if the proxy config exists
if [ ! -f "$PROXY_CONFIG" ]; then
    echo "Error: Proxy configuration file $PROXY_CONFIG not found."
    exit 1
fi

echo "\n====== Tor Connection Test ======"
echo "Direct connection IP:"
curl -s https://ipinfo.io

echo "\n\n====== Tor Proxy Connection ======"
echo "Tor connection IP:"
proxychains4 -f $PROXY_CONFIG curl -s https://ipinfo.io

echo "\n\n====== Connection Test ======"
DIRECT_IP=$(curl -s https://api.ipify.org)
TOR_IP=$(proxychains4 -f $PROXY_CONFIG curl -s https://api.ipify.org)

if [ "$DIRECT_IP" != "$TOR_IP" ]; then
    echo "✓ SUCCESS: Your traffic is routing through Tor"
    echo "  Direct IP: $DIRECT_IP"
    echo "  Tor IP:    $TOR_IP"
else
    echo "✗ FAIL: Your traffic is NOT routing through Tor properly"
    echo "  Both IPs are: $DIRECT_IP"
fi

# Measure latency
echo "\n====== Latency Test ======"
echo "Direct connection:"
measure_latency "https://api.ipify.org"

echo "\nTor connection:"
measure_latency "https://api.ipify.org" "$PROXY_CONFIG"

# Check if Tor is working properly
echo "\n====== Tor Verification ======"
if proxychains4 -f $PROXY_CONFIG curl -s https://check.torproject.org | grep -q "Congratulations"; then
    echo "✓ SUCCESS: You are using Tor"
else
    echo "✗ FAIL: You are NOT using Tor"
fi

# Comprehensive tests
if [ "$COMPREHENSIVE" = true ]; then
    echo "\n====== DNS Leak Test ======"
    echo "Testing for DNS leaks..."
    proxychains4 -f $PROXY_CONFIG curl -s https://dnsleaktest.com/
    echo "Please visit https://dnsleaktest.com/ through your proxy to check for DNS leaks"

    echo "\n====== WebRTC Leak Test ======"
    echo "WebRTC can leak your real IP address even when using Tor."
    echo "Please visit these sites through your proxy to test for WebRTC leaks:"
    echo "  - https://browserleaks.com/webrtc"
    echo "  - https://ipleak.net"

    # Optionally, try to detect WebRTC leaks programmatically
    # This is a basic check and might not be as thorough as browser-based tests
    if command -v firefox >/dev/null 2>&1; then
        echo "\nAttempting to check for WebRTC leaks using headless Firefox..."
        WEBRTC_JS=$(cat <<EOF
        // Basic WebRTC leak detection
        function findIP(callback) {
          var myPeerConnection = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection;
          var pc = new myPeerConnection({iceServers: [{urls: "stun:stun.l.google.com:19302"}]});
          var noop = function(){};
          var localIPs = {};

          pc.createDataChannel("");
          pc.createOffer().then(function(offer) {
            return pc.setLocalDescription(offer);
          }).catch(noop);

          pc.onicecandidate = function(ice) {
            if (!ice || !ice.candidate || !ice.candidate.candidate) return;
            var lines = ice.candidate.candidate.split('\n');
            lines.forEach(function(line) {
              if (line.indexOf('a=candidate:') === 0) {
                var parts = line.split(' ');
                var addr = parts[4];
                var type = parts[7];
                if (addr !== '0.0.0.0' && addr !== '127.0.0.1') {
                  if (type === 'host') localIPs[addr] = true;
                }
              }
            });
            callback(Object.keys(localIPs));
          };
        }

        findIP(function(ips) {
          console.log(JSON.stringify({ips: ips}));
        });
        setTimeout(function() {
          window.close();
        }, 2000);
EOF
        )
        echo "$WEBRTC_JS" > /tmp/webrtc_check.js
        proxychains4 -f $PROXY_CONFIG firefox --headless --no-remote -url about:blank -jsconsole 2>/dev/null & 
        sleep 5
        # This is a simplified approach and may not work in all environments
        echo "Note: This basic test may not detect all WebRTC leaks. Browser tests are more reliable."
    fi
fi

echo "\n====== Test Complete ======"
echo "For more comprehensive testing, install and run proxy_tester.py:"
echo "sudo python3 proxy_tester.py --test-instance ${INSTANCE:-0} --verbose"
"""

    with open("/tmp/test-tor", "w") as f:
        f.write(test_script)

    run_command("sudo mv /tmp/test-tor " + test_script_path)
    run_command(f"sudo chmod +x {test_script_path}")

    print(f"[+] Test script created. Run '{test_script_path}' to verify your Tor connection.")

    def ip_rotation_daemon(interval=60, instance_num=None, instances=None):
    """Run IP rotation daemon that changes the Tor IP at specified intervals"""
    if instance_num is not None:
        # Single instance rotation
        print(f"[*] Starting IP rotation daemon for instance {instance_num} (interval: {interval} seconds)")
        try:
            while True:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"\n[{timestamp}] Running IP rotation for instance {instance_num}...")
                rotate_ip(instance_num)
                print(f"[*] Next rotation in {interval} seconds...")
                time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n[*] IP rotation daemon for instance {instance_num} stopped.")
    elif instances is not None:
        # Multiple instances rotation with different threads
        print(f"[*] Starting IP rotation daemon for {len(instances)} instances (interval: {interval} seconds)")

        # Create a thread for each instance
        threads = []
        for instance in instances:
            thread = threading.Thread(
                target=ip_rotation_daemon,
                args=(interval, instance["instance"])
            )
            thread.daemon = True
            threads.append(thread)
            thread.start()
            time.sleep(1)  # Small delay between thread starts

        # Keep the main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] All IP rotation daemons stopped.")
    else:
        # Original behavior for main Tor service
        print(f"[*] Starting IP rotation daemon for main Tor (interval: {interval} seconds)")
        try:
            while True:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"\n[{timestamp}] Running IP rotation...")

                if not check_tor_status():
                    print("[!] Tor service is not running. Restarting...")
                    restart_tor()

                rotate_ip()
                print(f"[*] Next rotation in {interval} seconds...")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[*] IP rotation daemon stopped.")

    def add_crontab_entry(interval=60):
    """Add crontab entry to auto-restart the script if it stops"""
    print("[*] Setting up auto-restart via crontab...")
    script_path = os.path.abspath(__file__)

    # Create a script that checks if the daemon is running and restarts it if not
    check_script = f"""#!/bin/bash
    if ! pgrep -f "python3 {script_path} --daemon" > /dev/null; then
    echo "[$(date)] Restarting Tor proxy daemon..." >> /tmp/tor_proxy_restart.log
    sudo python3 {script_path} --daemon --interval {interval} &
    fi
    """

    with open("/tmp/check_tor_proxy.sh", "w") as f:
        f.write(check_script)

    run_command("sudo chmod +x /tmp/check_tor_proxy.sh")
    run_command("sudo mv /tmp/check_tor_proxy.sh /usr/local/bin/check_tor_proxy.sh")

    # Add crontab entry to run every 5 minutes
    crontab_entry = f"*/5 * * * * /usr/local/bin/check_tor_proxy.sh\n"
    run_command(f"(crontab -l 2>/dev/null || echo '') | grep -v 'check_tor_proxy.sh' | {{ cat; echo '{crontab_entry}'; }} | crontab -")

    print("[+] Auto-restart crontab entry added. The script will automatically restart if it stops.")

    def main():
    parser = argparse.ArgumentParser(description="Tor Proxy Manager")
    parser.add_argument("--install", action="store_true", help="Install tor, proxychains4, sqlmap and curl")
    parser.add_argument("--setup-firefox", action="store_true", help="Configure Firefox to use Tor proxy")
    parser.add_argument("--rotate", action="store_true", help="Rotate Tor IP address once")
    parser.add_argument("--daemon", action="store_true", help="Run IP rotation daemon")
    parser.add_argument("--interval", type=int, default=60, help="IP rotation interval in seconds (default: 60)")
    parser.add_argument("--restart-tor", action="store_true", help="Restart Tor service")
    parser.add_argument("--status", action="store_true", help="Check Tor status and current IP")
    parser.add_argument("--auto-restart", action="store_true", help="Setup auto-restart via crontab if script stops")
    parser.add_argument("--verify", action="store_true", help="Verify Tor connection is working properly")
    parser.add_argument("--create-test", action="store_true", help="Create a test script to verify Tor connection")
    parser.add_argument("--all", action="store_true", help="Setup everything (install, setup Firefox, test script, auto-restart with daemon)")
    parser.add_argument("--multi-tor", type=int, help="Setup multiple Tor instances (specify number of instances)")
    parser.add_argument("--instance", type=int, help="Specify Tor instance number for operations")
    parser.add_argument("--run-sqlmap", action="store_true", help="Run sqlmap with Tor proxy")
    parser.add_argument("--url", help="URL for sqlmap scanning")
    parser.add_argument("--sqlmap-args", help="Additional sqlmap arguments")
    parser.add_argument("--list-instances", action="store_true", help="List all available Tor instances")
    parser.add_argument("--delete-instance", type=int, help="Delete a specific Tor instance")
    parser.add_argument("--delete-all-instances", action="store_true", help="Delete all Tor instances except the main one")
    parser.add_argument("--measure-latency", action="store_true", help="Measure latency of the Tor connection")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        return

    if args.all:
        install_packages()
        setup_firefox_proxy()
        create_test_script()
        add_crontab_entry(args.interval)
        verify_tor_connection()
        ip_rotation_daemon(args.interval)
        return

    if args.install:
        install_packages()

    if args.setup_firefox:
        setup_firefox_proxy()

    if args.create_test:
        create_test_script()

    if args.restart_tor:
        if args.instance:
            restart_tor(args.instance)
        else:
            restart_tor()

    if args.status:
        if args.instance:
            port = 9050 + args.instance
            print(f"[+] Tor instance {args.instance} status:")
            print(f"[+] Current IP: {get_current_ip(port)}")
        else:
            if check_tor_status():
                print("[+] Tor service is running")
                print(f"[+] Current IP: {get_current_ip()}")
            else:
                print("[!] Tor service is not running")

    if args.verify:
        verify_tor_connection()

    if args.auto_restart:
        add_crontab_entry(args.interval)

    if args.rotate:
        if args.instance:
            rotate_ip(args.instance)
        else:
            rotate_ip()

    if args.multi_tor:
        num_instances = args.multi_tor
        if num_instances < 1:
            print("[!] Number of instances must be at least 1")
            return
        instances = setup_multiple_tor_instances(num_instances)

        # If daemon is also specified, start rotation daemon for all instances
        if args.daemon:
            ip_rotation_daemon(args.interval, instances=instances)

    elif args.daemon:
        if args.instance:
            ip_rotation_daemon(args.interval, instance_num=args.instance)
        else:
            ip_rotation_daemon(args.interval)

    if args.run_sqlmap:
        if not args.url:
            print("[!] URL is required for sqlmap scanning")
            return

        sqlmap_args = args.sqlmap_args if args.sqlmap_args else ""
        port = 9050 + args.instance if args.instance else 9050
        proxychains_conf = f"/etc/proxychains4.conf.{port}" if args.instance else "/etc/proxychains4.conf"

        cmd = f"proxychains4 -f {proxychains_conf} sqlmap -u \"{args.url}\" --batch --random-agent {sqlmap_args}"
        print(f"[*] Running sqlmap with command: {cmd}")

        # Start in a separate process that will continue even if this script exits
        run_command(f"nohup {cmd} > /tmp/sqlmap_{port}.log 2>&1 &")
        print(f"[+] sqlmap started in background. Check /tmp/sqlmap_{port}.log for output")

            if args.list_instances:
        # Get all proxy instances
        print("\n[*] Listing all Tor proxy instances...")

        # Check main Tor service
        if check_tor_status():
            print("✓ Main Tor service is running (Port: 9050)")
        else:
            print("✗ Main Tor service is not running")

        # Check for additional instances
        found_instances = False
        for i in range(1, 20):  # Check up to 20 possible instances
            port = 9050 + i
            config_path = f"/etc/proxychains4.conf.{port}"
            data_dir = f"/tmp/tor-data-{i}"

            if os.path.exists(config_path):
                # Check if the process is running
                proc_running = run_command(f"pgrep -f 'tor --SocksPort {port}'")
                status = "✓ Running" if proc_running else "✗ Not running"

                print(f"Instance {i}: {status} (SOCKS Port: {port}, Control Port: {9051 + i})")
                found_instances = True

        if not found_instances:
            print("No additional Tor instances found.")

            if args.delete_instance is not None:
        instance_num = args.delete_instance
        if instance_num <= 0:
            print("[!] Cannot delete the main Tor service. Instance number must be > 0")
            return

        port = 9050 + instance_num
        config_path = f"/etc/proxychains4.conf.{port}"
        data_dir = f"/tmp/tor-data-{instance_num}"

        if not os.path.exists(config_path):
            print(f"[!] Instance {instance_num} not found.")
            return

        print(f"[*] Deleting Tor instance {instance_num}...")

        # Kill the Tor process
        run_command(f"pkill -f 'tor --SocksPort {port}'")

        # Remove the config file
        if os.path.exists(config_path):
            os.remove(config_path)

        # Remove the data directory
        if os.path.exists(data_dir):
            run_command(f"rm -rf {data_dir}")

        print(f"[+] Tor instance {instance_num} deleted.")

            if args.delete_all_instances:
        print("[*] Deleting all additional Tor instances...")

        # Kill all Tor processes except the main service
        run_command("pkill -f 'tor --SocksPort 905[1-9]'")

        # Remove all proxy configuration files
        for i in range(1, 20):
            config_file = f"/etc/proxychains4.conf.{9050 + i}"
            if os.path.exists(config_file):
                os.remove(config_file)

            # Remove data directories
            data_dir = f"/tmp/tor-data-{i}"
            if os.path.exists(data_dir):
                run_command(f"rm -rf {data_dir}")

        print("[+] All additional Tor instances deleted.")

            if args.measure_latency:
        # Measure latency to a common website
        test_url = "https://api.ipify.org"
        num_tests = 3

        print(f"\n[*] Measuring latency using {num_tests} requests to {test_url}")

        # First measure direct connection
        print("\nDirect connection:")
        direct_times = []
        for i in range(num_tests):
            start_time = time.time()
            result = run_command(f"curl -s -o /dev/null -w '%{{time_total}}' {test_url}")
            if result:
                try:
                    direct_times.append(float(result))
                    print(f"  Request {i+1}: {result}s")
                except ValueError:
                    print(f"  Request {i+1}: Error parsing result")
            time.sleep(0.5)

        if direct_times:
            avg_direct = sum(direct_times) / len(direct_times)
            print(f"  Average direct latency: {avg_direct:.3f}s")
        else:
            print("  Could not measure direct latency.")

        # Now measure through Tor
        if args.instance:
            port = 9050 + args.instance
            proxy_config = f"/etc/proxychains4.conf.{port}"
            print(f"\nTor instance {args.instance} (port {port}):")
        else:
            proxy_config = "/etc/proxychains4.conf"
            print("\nMain Tor instance:")

        # Check if the config file exists
        if not os.path.exists(proxy_config):
            print(f"  Error: Proxy configuration file {proxy_config} not found.")
            return

        tor_times = []
        for i in range(num_tests):
            start_time = time.time()
            cmd = f"proxychains4 -f {proxy_config} curl -s -o /dev/null -w '%{{time_total}}' {test_url}"
            result = run_command(cmd)
            if result:
                try:
                    tor_times.append(float(result))
                    print(f"  Request {i+1}: {result}s")
                except ValueError:
                    print(f"  Request {i+1}: Error parsing result")
            time.sleep(0.5)

        if tor_times:
            avg_tor = sum(tor_times) / len(tor_times)
            print(f"  Average Tor latency: {avg_tor:.3f}s")

            if direct_times:  # Calculate overhead if we have both measurements
                overhead = ((avg_tor / avg_direct) - 1) * 100
                print(f"  Tor overhead: {overhead:.1f}%")
        else:
            print("  Could not measure Tor latency.")

if __name__ == "__main__":
    # Check if script is run with root privileges
    if os.geteuid() != 0:
        print("[!] This script requires root privileges to install packages and configure services.")
        print("[!] Please run with sudo or as root.")
        sys.exit(1)

    main()
