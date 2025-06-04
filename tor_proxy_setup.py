#!/usr/bin/env python3
#!/usr/bin/env python3

import os
import sys
import time
import socket
import random
import signal
import subprocess
import argparse
import re
from pathlib import Path
from stem import Signal
from stem.control import Controller

# Global variables
DEFAULT_INTERVAL = 60  # Default IP rotation interval in seconds

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
    """Install required packages: tor, proxychains4, sqlmap, curl"""
    print("[*] Installing required packages...")

    # Check if packages are already installed
    tor_installed = run_command("which tor") is not None
    proxychains_installed = run_command("which proxychains4") is not None
    sqlmap_installed = run_command("which sqlmap") is not None
    curl_installed = run_command("which curl") is not None

    # Install missing packages
    if not tor_installed or not proxychains_installed or not sqlmap_installed or not curl_installed:
        # Update package lists
        print("[*] Updating package lists...")
        run_command("apt-get update")

    # Install Tor if not already installed
    if not tor_installed:
        print("[*] Installing Tor...")
        run_command("apt-get install -y tor")
        run_command("systemctl enable tor")
        run_command("systemctl start tor")
    else:
        print("[+] Tor is already installed.")

    # Install proxychains4 if not already installed
    if not proxychains_installed:
        print("[*] Installing proxychains4...")
        run_command("apt-get install -y proxychains4")
    else:
        print("[+] Proxychains4 is already installed.")

    # Install SQLMap if not already installed
    if not sqlmap_installed:
        print("[*] Installing SQLMap...")
        run_command("apt-get install -y sqlmap")
    else:
        print("[+] SQLMap is already installed.")

    # Install curl if not already installed
    if not curl_installed:
        print("[*] Installing curl...")
        run_command("apt-get install -y curl")
    else:
        print("[+] Curl is already installed.")

    # Configure Tor for control port access
    print("[*] Configuring Tor...")
    torrc_path = "/etc/tor/torrc"
    torrc_backup = "/etc/tor/torrc.backup"

    # Backup original torrc if it hasn't been backed up already
    if not os.path.exists(torrc_backup) and os.path.exists(torrc_path):
        run_command(f"cp {torrc_path} {torrc_backup}")

    # Update torrc configuration
    torrc_config = """
# Tor configuration for proxy rotation
ControlPort 9051
SocksPort 9050
DataDirectory /var/lib/tor
CookieAuthentication 1
HashedControlPassword """

    # Generate hashed control password
    password = "TorProxyManager" + str(random.randint(1000, 9999))
    hashed_password = run_command(f"tor --hash-password {password}")
    torrc_config += hashed_password + "\n"

    # Write the configuration to torrc
    with open("/tmp/torrc", "w") as f:
        f.write(torrc_config)

    run_command(f"sudo mv /tmp/torrc {torrc_path}")
    run_command("sudo chmod 644 /etc/tor/torrc")

    # Configure proxychains to use Tor
    proxychains_conf = "/etc/proxychains4.conf"
    proxychains_backup = "/etc/proxychains4.conf.backup"

    # Backup original proxychains.conf if it hasn't been backed up already
    if not os.path.exists(proxychains_backup) and os.path.exists(proxychains_conf):
        run_command(f"cp {proxychains_conf} {proxychains_backup}")

    proxychains_config = """
# proxychains.conf for Tor proxy rotation
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 9050
"""

    with open("/tmp/proxychains4.conf", "w") as f:
        f.write(proxychains_config)

    run_command(f"sudo mv /tmp/proxychains4.conf {proxychains_conf}")
    run_command("sudo chmod 644 /etc/proxychains4.conf")

    # Restart Tor service
    print("[*] Restarting Tor service...")
    run_command("systemctl restart tor")

    print("[+] Required packages installed and configured successfully.")
    return True

def check_tor_status():
    """Check if Tor service is running"""
    result = run_command("systemctl is-active tor")
    if result == "active":
        return True
    return False

def restart_tor(instance_num=None):
    """Restart the Tor service or a specific Tor instance"""
    if instance_num is not None:
        data_dir = f"/var/lib/tor/instance_{instance_num}"
        if os.path.exists(data_dir):
            pid_file = os.path.join(data_dir, "pid")
            if os.path.exists(pid_file):
                try:
                    with open(pid_file, "r") as f:
                        pid = f.read().strip()
                    if pid:
                        print(f"[*] Restarting Tor instance {instance_num} (PID: {pid})...")
                        run_command(f"kill -HUP {pid}")
                        time.sleep(5)  # Wait for Tor to restart
                        return True
                except Exception as e:
                    print(f"[!] Error restarting Tor instance {instance_num}: {str(e)}")

            # If PID file doesn't exist or there was an error, try to start the instance
            start_tor_instance(instance_num)
            return True
        else:
            print(f"[!] Tor instance {instance_num} doesn't exist. Create it first with --multi-tor.")
            return False
    else:
        print("[*] Restarting the main Tor service...")
        run_command("systemctl restart tor")
        time.sleep(5)  # Wait for Tor to restart
        if check_tor_status():
            print("[+] Tor service restarted successfully.")
            return True
        else:
            print("[!] Failed to restart Tor service.")
            return False

def get_current_ip(socks_port=9050):
    """Get the current Tor IP address"""
    cmd = f"proxychains4 -q -f /etc/proxychains4.conf{'.'+str(socks_port) if socks_port != 9050 else ''} curl -s https://api.ipify.org"
    ip = run_command(cmd)
    if not ip or not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
        print(f"[!] Could not get current IP address for port {socks_port}.")
        return None
    return ip

def start_tor_instance(instance_num):
    """Start a Tor instance with a specific port"""
    socks_port = 9050 + instance_num
    control_port = 9051 + instance_num
    data_dir = f"/var/lib/tor/instance_{instance_num}"

    # Create data directory if it doesn't exist
    if not os.path.exists(data_dir):
        run_command(f"mkdir -p {data_dir}")
        run_command(f"chown debian-tor:debian-tor {data_dir}")
        run_command(f"chmod 700 {data_dir}")

    # Create torrc configuration for this instance
    torrc_path = f"/etc/tor/torrc.{instance_num}"
    torrc_config = f"""
# Tor configuration for instance {instance_num}
SocksPort {socks_port}
ControlPort {control_port}
DataDirectory {data_dir}
CookieAuthentication 1
HashedControlPassword 16:B92771A5F21A091BA5CDD5C63965239FD2ED5D2C425EE638CA804F121B
"""

    with open("/tmp/torrc.instance", "w") as f:
        f.write(torrc_config)

    run_command(f"sudo mv /tmp/torrc.instance {torrc_path}")
    run_command(f"sudo chmod 644 {torrc_path}")

    # Create proxychains configuration for this instance
    proxychains_conf = f"/etc/proxychains4.conf.{socks_port}"
    proxychains_config = f"""
# proxychains.conf for Tor instance {instance_num}
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 {socks_port}
"""

    with open("/tmp/proxychains4.conf.instance", "w") as f:
        f.write(proxychains_config)

    run_command(f"sudo mv /tmp/proxychains4.conf.instance {proxychains_conf}")
    run_command(f"sudo chmod 644 {proxychains_conf}")

    # Start Tor instance
    print(f"[*] Starting Tor instance {instance_num} on port {socks_port}...")
    cmd = f"tor -f {torrc_path}"
    run_command(f"sudo -u debian-tor {cmd} &")

    # Wait for Tor to start
    time.sleep(5)

    # Check if the instance is running
    is_running = False
    for _ in range(5):  # Try 5 times
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("127.0.0.1", socks_port))
                is_running = True
                break
        except:
            time.sleep(2)

    if is_running:
        print(f"[+] Tor instance {instance_num} started successfully.")
        return True
    else:
        print(f"[!] Failed to start Tor instance {instance_num}.")
        return False

def setup_multiple_tor_instances(num_instances):
    """Setup multiple Tor instances with different IPs"""
    print(f"[*] Setting up {num_instances} Tor instances...")

    # Create instances
    successful_instances = 0
    for i in range(1, num_instances + 1):
        if start_tor_instance(i):
            successful_instances += 1

    # Rotate IPs to ensure they're different
    for i in range(1, num_instances + 1):
        rotate_ip(i)
        time.sleep(1)  # Add delay to avoid overwhelming the Tor network

    print(f"[+] Successfully set up {successful_instances} out of {num_instances} Tor instances.")

    # List all instances with their IPs
    print("\n[*] Tor instance information:")
    print("-" * 50)
    print(f"{'Instance':<10} {'SOCKS Port':<15} {'Control Port':<15} {'IP Address':<20}")
    print("-" * 50)

    # First show the main Tor instance
    main_ip = get_current_ip()
    print(f"{'Main':<10} {'9050':<15} {'9051':<15} {main_ip if main_ip else 'Not available':<20}")

    for i in range(1, num_instances + 1):
        socks_port = 9050 + i
        control_port = 9051 + i
        ip = get_current_ip(socks_port)
        print(f"{i:<10} {socks_port:<15} {control_port:<15} {ip if ip else 'Not available':<20}")

    print("-" * 50)
    return successful_instances

def verify_tor_connection(socks_port=9050):
    """Verify that Tor connection is working properly"""
    print("[*] Verifying Tor connection...")

    # Check if Tor is running
    if socks_port == 9050:
        if not check_tor_status():
            print("[!] Tor service is not running. Starting Tor...")
            run_command("systemctl start tor")
            time.sleep(5)  # Wait for Tor to start

    # Get current Tor IP
    ip = get_current_ip(socks_port)
    if not ip:
        print("[!] Could not get Tor IP address. Tor may not be working correctly.")
        return False

    print(f"[+] Current Tor IP: {ip}")

    # Check if we can access the Tor check service
    tor_check_cmd = f"proxychains4 -q -f /etc/proxychains4.conf{'.'+str(socks_port) if socks_port != 9050 else ''} curl -s https://check.torproject.org"
    tor_check_result = run_command(tor_check_cmd)

    if tor_check_result and "Congratulations" in tor_check_result:
        print("[+] Tor connection verified via check.torproject.org")
    else:
        print("[!] Could not verify Tor connection via check.torproject.org")

    # Compare with direct IP to ensure they're different
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

    try:
        # Try using stem library first
        try:
            from stem import Signal
            from stem.control import Controller

            with Controller.from_port(port=control_port) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                print("[+] Successfully rotated IP address using stem library.")
        except:
            # If stem fails, try the manual telnet method
            print("[!] Stem library not available or failed. Trying manual method...")

            # Create a temporary script to send commands to the Tor control port
            auth_script = f"""
#!/usr/bin/env python3
import socket, time

def send_tor_command(cmd):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', {control_port}))
    auth_response = s.recv(1024).decode()
    s.send(('AUTHENTICATE ""\r\n').encode())
    auth_response = s.recv(1024).decode()
    s.send((cmd + '\r\n').encode())
    response = s.recv(1024).decode()
    s.close()
    return response

# Send NEWNYM signal to rotate IP
print(send_tor_command('SIGNAL NEWNYM'))
time.sleep(2)  # Wait for rotation
"""

            with open("/tmp/rotate_tor_ip.py", "w") as f:
                f.write(auth_script)

            run_command("chmod +x /tmp/rotate_tor_ip.py")
            run_command("python3 /tmp/rotate_tor_ip.py")
            run_command("rm /tmp/rotate_tor_ip.py")

        # Wait for IP to change
        time.sleep(5)

        # Verify IP change
        new_ip = get_current_ip(socks_port)
        print(f"[*] New IP for port {socks_port}: {new_ip}")

        if old_ip and new_ip and old_ip == new_ip:
            print("[!] Warning: IP address did not change. Trying again...")
            # Try the rotation once more
            try:
                with Controller.from_port(port=control_port) as controller:
                    controller.authenticate()
                    controller.signal(Signal.NEWNYM)
            except:
                pass

            time.sleep(5)
            new_ip = get_current_ip(socks_port)
            print(f"[*] New IP after second attempt: {new_ip}")

            if old_ip and new_ip and old_ip == new_ip:
                print("[!] IP rotation failed. Try restarting Tor.")
                return False

        return True
    except Exception as e:
        print(f"[!] Error rotating IP: {str(e)}")
        return False

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
    """Create a test script to verify Tor connection"""
    print("[*] Creating test script...")

    test_script_path = "/usr/local/bin/test-tor"
    test_script = """#!/bin/bash
# Script to test Tor connection

# ASCII Art Banner
cat << "EOF"
  _______            _______         _   
 |__   __|          |__   __|       | |  
    | | ___  _ __      | | ___  ___| |_ 
    | |/ _ \| '__|     | |/ _ \/ __| __|
    | | (_) | |        | |  __/\__ \ |_ 
    |_|\___/|_|        |_|\___||___/\__|

EOF

# Parse command-line arguments
INSTANCE=""
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
            echo "Unknown option: $1"
            echo "Usage: test-tor [-i|--instance NUM] [-c|--comprehensive]"
            exit 1
            ;;
    esac
done

# Determine which Tor instance to test
if [ -z "$INSTANCE" ]; then
    PROXY_PORT=9050
    PROXY_CONFIG="/etc/proxychains4.conf"
    INSTANCE_NAME="Main Tor"
else
    PROXY_PORT=$((9050 + INSTANCE))
    PROXY_CONFIG="/etc/proxychains4.conf.$PROXY_PORT"
    INSTANCE_NAME="Tor Instance $INSTANCE"

    # Check if this instance exists
    if [ ! -f "$PROXY_CONFIG" ]; then
        echo "[!] Error: Tor instance $INSTANCE does not exist."
        echo "[!] Create it first with: sudo python3 tor_proxy_setup.py --multi-tor $INSTANCE"
        exit 1
    fi
fi

echo "\n===== Testing $INSTANCE_NAME (Port: $PROXY_PORT) ====="

# Get direct IP
echo -n "[*] Your direct IP address: "
DIRECT_IP=$(curl -s https://api.ipify.org)
echo "$DIRECT_IP"

# Get Tor IP
echo -n "[*] Your Tor IP address: "
TOR_IP=$(proxychains4 -q -f "$PROXY_CONFIG" curl -s https://api.ipify.org)
echo "$TOR_IP"

# Check if IPs are different
if [ "$DIRECT_IP" = "$TOR_IP" ]; then
    echo "[!] WARNING: Your Tor IP is the same as your direct IP!"
    echo "[!] Tor may not be working correctly."
    exit 1
fi

# Get IP location information
echo "\n[*] IP Location Information:"
TOR_LOCATION=$(proxychains4 -q -f "$PROXY_CONFIG" curl -s https://ipinfo.io)
COUNTRY=$(echo "$TOR_LOCATION" | grep -oP '"country":\s*"\K[^"]*')
CITY=$(echo "$TOR_LOCATION" | grep -oP '"city":\s*"\K[^"]*')
ISP=$(echo "$TOR_LOCATION" | grep -oP '"org":\s*"\K[^"]*')

echo "[+] Country: $COUNTRY"
echo "[+] City: $CITY"
echo "[+] ISP/Organization: $ISP"

# Check Tor verification
echo "\n[*] Verifying Tor connection..."
TOR_CHECK=$(proxychains4 -q -f "$PROXY_CONFIG" curl -s https://check.torproject.org/api/ip)
IS_TOR=$(echo "$TOR_CHECK" | grep -oP '"IsTor":\s*\K\w+')

if [ "$IS_TOR" = "true" ]; then
    echo "[+] Success! You are connected to the Tor network."
else
    echo "[!] Warning: You may not be using Tor properly."
fi

# Test latency
echo "\n[*] Testing connection latency..."
echo -n "[+] Direct connection: "
DIRECT_TIME=$(curl -s -w "%{time_total}" -o /dev/null https://www.google.com)
printf "%.2f seconds\n" "$DIRECT_TIME"

echo -n "[+] Tor connection: "
TOR_TIME=$(proxychains4 -q -f "$PROXY_CONFIG" curl -s -w "%{time_total}" -o /dev/null https://www.google.com)
printf "%.2f seconds\n" "$TOR_TIME"

# Comprehensive tests if requested
if [ "$COMPREHENSIVE" = true ]; then
    echo "\n===== Running Comprehensive Tests ====="

    # DNS leak test
    echo "\n[*] Testing for DNS leaks..."
    DNS_SERVERS=$(proxychains4 -q -f "$PROXY_CONFIG" curl -s https://dnsleaktest.com/json/api-dns-leak-test | grep -oP '"ip":\s*"\K[^"]*')
    DNS_COUNT=$(echo "$DNS_SERVERS" | wc -l)

    echo "[+] DNS servers detected: $DNS_COUNT"
    if [ "$DNS_COUNT" -gt 1 ]; then
        echo "[!] Warning: Multiple DNS servers detected, possible DNS leak."
    else
        echo "[+] Good: Only using one DNS server through Tor."
    fi

    # Browser warning
    echo "\n[*] Browser Security Recommendations:"
    echo "[!] Remember that using Tor with a regular browser may still leak your identity."
    echo "[!] For maximum anonymity, use the official Tor Browser instead."
    echo "[!] Browser plugins, JavaScript, WebRTC, and cookies can all reveal your true IP."

    # Check for common Tor exit nodes
    echo "\n[*] Checking if your exit node is a common one..."
    EXIT_NODE_IP="$TOR_IP"
    TOR_EXIT_DB="https://check.torproject.org/exit-addresses"
    KNOWN_EXIT=$(curl -s "$TOR_EXIT_DB" | grep "ExitAddress $EXIT_NODE_IP" | wc -l)

    if [ "$KNOWN_EXIT" -gt 0 ]; then
        echo "[+] Your Tor exit node is a known exit node in the public directory."
    else
        echo "[!] Your exit node is not in the public Tor directory. This could be normal for a bridge relay."
    fi
fi

echo "\n===== Test Completed Successfully ====="
echo "[+] Your Tor connection is working properly."
echo "[+] Your real IP is hidden: $DIRECT_IP -> $TOR_IP"
"""

    with open("/tmp/test-tor", "w") as f:
        f.write(test_script)

    run_command("sudo mv /tmp/test-tor " + test_script_path)
    run_command(f"sudo chmod +x {test_script_path}")

    print(f"[+] Test script created at {test_script_path}")
    print("[+] Run the script to test your Tor connection.")

def ip_rotation_daemon(interval=60, instance_num=None, instances=None):
    """Run IP rotation daemon"""
    if instance_num is not None:
        print(f"[*] Starting IP rotation daemon for instance {instance_num} with interval {interval} seconds...")
    elif instances is not None:
        print(f"[*] Starting IP rotation daemon for {len(instances)} instances with interval {interval} seconds...")
    else:
        print(f"[*] Starting IP rotation daemon with interval {interval} seconds...")

    try:
        while True:
            if instance_num is not None:
                rotate_ip(instance_num)
            elif instances is not None:
                for i in instances:
                    print(f"\n--- Rotating IP for instance {i} ---")
                    rotate_ip(i)
                    time.sleep(1)  # Small delay between rotations
            else:
                rotate_ip()

            # Sleep until next rotation
            print(f"[*] Next IP rotation in {interval} seconds...")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[!] IP rotation daemon stopped by user.")
    except Exception as e:
        print(f"\n[!] Error in IP rotation daemon: {str(e)}")

def add_crontab_entry(interval=60):
    """Add crontab entry to auto-restart the script if it stops"""
    print("[*] Setting up auto-restart via crontab...")

    # Create a check script that will run periodically
    script_path = "/usr/local/bin/check_tor_proxy.sh"
    script_content = f"""#!/bin/bash
# Script to check if tor_proxy_setup.py daemon is running and restart if not

CURRENT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROXY_SCRIPT="{os.path.abspath(__file__)}"
LOG_FILE="/var/log/tor_proxy.log"

# Check if daemon is running
if ! pgrep -f "python3 $PROXY_SCRIPT --daemon" > /dev/null; then
    echo "[$(date)] Tor proxy daemon not running. Restarting..." >> "$LOG_FILE"
    nohup python3 "$PROXY_SCRIPT" --daemon --interval {interval} >> "$LOG_FILE" 2>&1 &
fi
"""

    with open("/tmp/check_tor_proxy.sh", "w") as f:
        f.write(script_content)

    run_command(f"sudo mv /tmp/check_tor_proxy.sh {script_path}")
    run_command(f"sudo chmod +x {script_path}")

    # Add crontab entry to run the check script every 5 minutes
    crontab_entry = f"*/5 * * * * {script_path}\n"
    run_command(f"(crontab -l 2>/dev/null || echo '') | grep -v '{script_path}' | (cat; echo '{crontab_entry}') | crontab -")

    print("[+] Auto-restart setup completed. The script will be monitored and restarted if it stops.")
    return True

def measure_latency(test_url="https://api.ipify.org", proxy_config=None, num_tests=3):
    """Measure latency difference between direct and Tor connections"""
    results = {"direct": {"times": [], "timeouts": 0, "avg": 0},
              "tor": {"times": [], "timeouts": 0, "avg": 0}}

    print("[*] Measuring latency...")
    print(f"[*] Running {num_tests} tests for direct connection...")

    # Test direct connection
    direct_times = []
    for i in range(num_tests):
        try:
            start_time = time.time()
            result = run_command(f"curl -s -m 10 {test_url}")
            elapsed = time.time() - start_time

            if result:
                direct_times.append(elapsed)
                print(f"  Test {i+1}: {elapsed:.2f} seconds")
            else:
                results["direct"]["timeouts"] += 1
                print(f"  Test {i+1}: Timeout")
        except:
            results["direct"]["timeouts"] += 1
            print(f"  Test {i+1}: Error")

    # Calculate average direct latency
    if direct_times:
        avg_direct = sum(direct_times) / len(direct_times)
        results["direct"]["times"] = direct_times
        results["direct"]["avg"] = avg_direct
        print(f"[+] Average direct latency: {avg_direct:.2f} seconds")
    else:
        print("[!] Could not measure direct latency.")

    # Determine proxy configuration
    if not proxy_config:
        proxy_config = "/etc/proxychains4.conf"

    # Test Tor connection
    print(f"\n[*] Running {num_tests} tests for Tor connection...")
    tor_times = []
    for i in range(num_tests):
        try:
            start_time = time.time()
            cmd = f"proxychains4 -q -f {proxy_config} curl -s -m 30 {test_url}"
            result = run_command(cmd)
            elapsed = time.time() - start_time

            if result:
                tor_times.append(elapsed)
                print(f"  Test {i+1}: {elapsed:.2f} seconds")
            else:
                results["tor"]["timeouts"] += 1
                print(f"  Test {i+1}: Timeout")
        except:
            results["tor"]["timeouts"] += 1
            print(f"  Test {i+1}: Error")

    # Calculate average Tor latency
    if tor_times:
        avg_tor = sum(tor_times) / len(tor_times)
        results["tor"]["times"] = tor_times
        results["tor"]["avg"] = avg_tor
        print(f"[+] Average Tor latency: {avg_tor:.2f} seconds")
    else:
        print("[!] Could not measure Tor latency.")

    # Calculate overhead
    if direct_times and tor_times:
        overhead = (avg_tor / avg_direct) - 1
        print(f"[+] Tor overhead: {overhead:.2f}x (Tor is {overhead*100:.0f}% slower)")

    return results

def test_dns_leak(proxy_config=None):
    """Test for DNS leaks"""
    results = {}

    if not proxy_config:
        proxy_config = "/etc/proxychains4.conf"

    print("[*] Testing for DNS leaks...")
    try:
        # Try to get DNS servers from dnsleaktest.com
        cmd = f"proxychains4 -q -f {proxy_config} curl -s https://dnsleaktest.com/json/api-dns-leak-test"
        output = run_command(cmd)

        if output and output.strip():
            dns_servers = re.findall(r'"ip":\s*"([^"]+)"', output)

            if dns_servers:
                results["dns_servers"] = dns_servers
                results["count"] = len(dns_servers)

                print(f"[+] Detected {len(dns_servers)} DNS servers:")
                for server in dns_servers:
                    print(f"  - {server}")

                if len(dns_servers) > 1:
                    print("[!] Warning: Multiple DNS servers detected. Possible DNS leak.")
                    results["leaked"] = True
                else:
                    print("[+] Good: Only one DNS server detected.")
                    results["leaked"] = False
            else:
                print("[!] No DNS servers detected in the response.")
                results["error"] = "No DNS servers found in response"
        else:
            print("[!] Could not get DNS leak test results.")
            results["error"] = "No response from DNS leak test"
    except Exception as e:
        print(f"[!] Error testing for DNS leaks: {str(e)}")
        results["error"] = str(e)

    return results

def test_webrtc_leak(proxy_config=None):
    """Test for WebRTC leaks (conceptual, can't be fully tested from CLI)"""
    results = {"warning": "WebRTC leak testing requires a browser environment"}
    print("[*] WebRTC leak testing from CLI is limited.")
    print("[+] Important notes about WebRTC leaks:")
    print("  - WebRTC can bypass proxy settings in browsers and reveal your real IP")
    print("  - This cannot be fully tested from a command-line environment")
    print("  - For proper WebRTC leak testing, use a browser with appropriate extensions")
    print("  - Consider using the Tor Browser which has WebRTC disabled by default")

    return results

def ip_rotation_daemon(interval=60, instance_num=None, instances=None):
    """Run IP rotation daemon"""
    if instance_num is not None:
        print(f"[*] Starting IP rotation daemon for instance {instance_num} with interval {interval} seconds...")
    elif instances is not None:
        print(f"[*] Starting IP rotation daemon for {len(instances)} instances with interval {interval} seconds...")
    else:
        print(f"[*] Starting IP rotation daemon with interval {interval} seconds...")

    try:
        while True:
            if instance_num is not None:
                rotate_ip(instance_num)
            elif instances is not None:
                for i in instances:
                    print(f"\n--- Rotating IP for instance {i} ---")
                    rotate_ip(i)
                    time.sleep(1)  # Small delay between rotations
            else:
                rotate_ip()

            # Sleep until next rotation
            print(f"[*] Next IP rotation in {interval} seconds...")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[!] IP rotation daemon stopped by user.")
    except Exception as e:
        print(f"\n[!] Error in IP rotation daemon: {str(e)}")

def get_ip_info(proxy_config=None):
    """Get detailed information about the current IP address"""
    results = {}

    cmd_prefix = ""
    if proxy_config:
        cmd_prefix = f"proxychains4 -q -f {proxy_config} "

    print("[*] Getting IP information...")
    try:
        # Get basic IP
        ip_cmd = f"{cmd_prefix}curl -s https://api.ipify.org"
        ip = run_command(ip_cmd)

        if ip and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            results["ip"] = ip
            print(f"[+] IP Address: {ip}")

            # Get detailed info from ipinfo.io
            info_cmd = f"{cmd_prefix}curl -s https://ipinfo.io"
            info = run_command(info_cmd)

            if info:
                # Parse fields from the JSON response
                for field in ["country", "region", "city", "org", "hostname", "loc"]:
                    match = re.search(r'"' + field + '":\s*"([^"]+)"', info)
                    if match:
                        results[field] = match.group(1)

                # Display the information
                if "city" in results and "country" in results:
                    print(f"[+] Location: {results.get('city', 'Unknown')}, {results.get('country', 'Unknown')}")
                if "org" in results:
                    print(f"[+] ISP/Organization: {results.get('org', 'Unknown')}")
        else:
            print("[!] Could not get IP address information.")
    except Exception as e:
        print(f"[!] Error getting IP information: {str(e)}")

    return results

def add_crontab_entry(interval=60):
    """Add crontab entry to auto-restart the script if it stops"""
    print("[*] Setting up auto-restart via crontab...")

    # Create a check script that will run periodically
    script_path = "/usr/local/bin/check_tor_proxy.sh"
    script_content = f"""#!/bin/bash
    # Script to check if tor_proxy_setup.py daemon is running and restart if not

    CURRENT_DIR="$(cd "$(dirname "$0")" && pwd)"
    PROXY_SCRIPT="{os.path.abspath(__file__)}"
    LOG_FILE="/var/log/tor_proxy.log"

    # Check if daemon is running
    if ! pgrep -f "python3 $PROXY_SCRIPT --daemon" > /dev/null; then
    echo "[$(date)] Tor proxy daemon not running. Restarting..." >> "$LOG_FILE"
    nohup python3 "$PROXY_SCRIPT" --daemon --interval {interval} >> "$LOG_FILE" 2>&1 &
    fi
    """

    with open("/tmp/check_tor_proxy.sh", "w") as f:
        f.write(script_content)

    run_command(f"sudo mv /tmp/check_tor_proxy.sh {script_path}")
    run_command(f"sudo chmod +x {script_path}")

    # Add crontab entry to run the check script every 5 minutes
    crontab_entry = f"*/5 * * * * {script_path}\n"
    run_command(f"(crontab -l 2>/dev/null || echo '') | grep -v '{script_path}' | {{ {{ cat; echo '{crontab_entry}'; }} | crontab -}}")

    print("[+] Auto-restart setup completed. The script will be monitored and restarted if it stops.")
    return True

def check_tor_connection(proxy_config=None):
    """Check if the connection is using Tor"""
    results = {"is_tor": False}

    if not proxy_config:
        proxy_config = "/etc/proxychains4.conf"

    print("[*] Checking if connection is using Tor...")
    try:
        # Try to access the Tor Project's checker API
        cmd = f"proxychains4 -q -f {proxy_config} curl -s https://check.torproject.org/api/ip"
        output = run_command(cmd)

        if output and "IsTor" in output:
            is_tor = "true" in output.lower()
            results["is_tor"] = is_tor

            if is_tor:
                print("[+] Connection confirmed to be using Tor.")
            else:
                print("[!] Connection is NOT using Tor.")

            # Extract IP from the response
            ip_match = re.search(r'"IP":\s*"([^"]+)"', output)
            if ip_match:
                results["ip"] = ip_match.group(1)
        else:
            print("[!] Could not determine if connection is using Tor.")
    except Exception as e:
        print(f"[!] Error checking Tor connection: {str(e)}")

    return results

def main():
    parser = argparse.ArgumentParser(description="Tor Proxy Manager with IP Rotation")

    # Basic options
    parser.add_argument("--install", action="store_true", help="Install tor, proxychains4, sqlmap and curl")
    parser.add_argument("--setup-firefox", action="store_true", help="Configure Firefox to use Tor proxy")
    parser.add_argument("--rotate", action="store_true", help="Rotate Tor IP address once")
    parser.add_argument("--daemon", action="store_true", help="Run IP rotation daemon")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help=f"IP rotation interval in seconds (default: {DEFAULT_INTERVAL})")
    parser.add_argument("--restart-tor", action="store_true", help="Restart Tor service")
    parser.add_argument("--status", action="store_true", help="Check Tor status and current IP")
    parser.add_argument("--auto-restart", action="store_true", help="Setup auto-restart via crontab if script stops")
    parser.add_argument("--verify", action="store_true", help="Verify Tor connection is working properly")
    parser.add_argument("--create-test", action="store_true", help="Create a test script to verify Tor connection")
    parser.add_argument("--all", action="store_true", help="Setup everything (install, Firefox setup, test script, daemon)")

    # Multi-tor options
    parser.add_argument("--multi-tor", type=int, help="Setup multiple Tor instances")
    parser.add_argument("--instance", type=int, help="Specify Tor instance number for operations")
    parser.add_argument("--list-instances", action="store_true", help="List all available Tor instances")
    parser.add_argument("--delete-instance", type=int, help="Delete a specific Tor instance")
    parser.add_argument("--delete-all-instances", action="store_true", help="Delete all Tor instances except the main one")

    # Testing options
    parser.add_argument("--measure-latency", action="store_true", help="Measure latency difference between direct and Tor connections")

    # SQLMap integration
    parser.add_argument("--run-sqlmap", action="store_true", help="Run SQLMap through Tor proxy")
    parser.add_argument("--url", help="Target URL for SQLMap")
    parser.add_argument("--sqlmap-args", help="Additional SQLMap arguments")
    parser.add_argument("--create-recover-script", action="store_true", help="Create a script to recover SQLMap if it dies")

    args = parser.parse_args()

    # Check if script is run with root privileges
    if os.geteuid() != 0:
        print("[!] This script must be run with root privileges.")
        print("[!] Please run with sudo or as root.")
        sys.exit(1)

    # Print banner
    print("\n" + "=" * 60)
    print("" + " " * 15 + "Tor Proxy Manager with IP Rotation")
    print("" + " " * 20 + "CLI-only VPS Edition")
    print("=" * 60 + "\n")

    # Check if no arguments were provided, show help in that case
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    # Process arguments
    if args.install:
        install_packages()

    if args.list_instances:
        print("[*] Listing all Tor instances...")
        found_instances = []

        # First, check the main Tor service
        if check_tor_status():
            print("[+] Main Tor instance is running on port 9050")
            found_instances.append({"instance": 0, "port": 9050})

        # Then look for additional instances
        for i in range(1, 20):  # Check up to 20 possible instances
            port = 9050 + i
            config_path = f"/etc/proxychains4.conf.{port}"
            data_dir = f"/var/lib/tor/instance_{i}"

            if os.path.exists(config_path) or os.path.exists(data_dir):
                # Check if the instance is running
                proc_running = False
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.connect(("127.0.0.1", port))
                        proc_running = True
                except:
                    pass

                status = "Running" if proc_running else "Not running"
                print(f"[+] Tor instance {i} is configured on port {port} ({status})")
                found_instances.append({"instance": i, "port": port, "running": proc_running})

        if not found_instances:
            print("[!] No Tor instances found.")
            print("[!] Create instances with: --multi-tor <number>")

    if args.delete_instance is not None:
        instance_num = args.delete_instance
        print(f"[*] Deleting Tor instance {instance_num}...")

        # Stop the instance if it's running
        port = 9050 + instance_num
        config_path = f"/etc/proxychains4.conf.{port}"
        data_dir = f"/var/lib/tor/instance_{instance_num}"

        # Kill the process if it's running
        run_command(f"pkill -f 'tor -f /etc/tor/torrc.{instance_num}'")

        # Remove the files
        if os.path.exists(f"/etc/tor/torrc.{instance_num}"):
            run_command(f"rm /etc/tor/torrc.{instance_num}")

        if os.path.exists(config_path):
            run_command(f"rm {config_path}")

        if os.path.exists(data_dir):
            run_command(f"rm -rf {data_dir}")

        print(f"[+] Tor instance {instance_num} deleted.")

    if args.delete_all_instances:
        print("[*] Deleting all Tor instances except the main one...")

        # Stop all running instances
        run_command("pkill -f 'tor -f /etc/tor/torrc.[0-9]'")

        # Remove all instance files
        for i in range(1, 20):  # Handle up to 20 instances
            # Remove configuration files
            if os.path.exists(f"/etc/tor/torrc.{i}"):
                run_command(f"rm /etc/tor/torrc.{i}")

            # Remove proxychains configuration
            port = 9050 + i
            if os.path.exists(f"/etc/proxychains4.conf.{port}"):
                run_command(f"rm /etc/proxychains4.conf.{port}")

            # Remove data directories
            if os.path.exists(f"/var/lib/tor/instance_{i}"):
                run_command(f"rm -rf /var/lib/tor/instance_{i}")

        print("[+] All Tor instances deleted.")

    if args.multi_tor:
        setup_multiple_tor_instances(args.multi_tor)

    if args.measure_latency:
        proxy_config = None
        if args.instance is not None:
            proxy_config = f"/etc/proxychains4.conf.{9050 + args.instance}"
        measure_latency(proxy_config=proxy_config)

    if args.verify:
        socks_port = 9050
        if args.instance is not None:
            socks_port = 9050 + args.instance
        verify_tor_connection(socks_port)

    if args.create_test:
        create_test_script()

    if args.auto_restart:
        add_crontab_entry(args.interval)

    if args.setup_firefox:
        setup_firefox_proxy()

    if args.all:
        install_packages()
        setup_firefox_proxy()
        create_test_script()
        add_crontab_entry(args.interval)
        # Start daemon at the end
        args.daemon = True

    if args.status:
        # Check if we're checking status for a specific instance
        socks_port = 9050
        if args.instance is not None:
            socks_port = 9050 + args.instance
            print(f"[*] Checking status for Tor instance {args.instance} (port {socks_port})...")

            # Check if instance exists
            config_path = f"/etc/proxychains4.conf.{socks_port}"
            if not os.path.exists(config_path):
                print(f"[!] Tor instance {args.instance} is not configured.")
                print(f"[!] Create it first with: --multi-tor {args.instance}")
                return
        else:
            print("[*] Checking status for main Tor instance...")
            if not check_tor_status():
                print("[!] Tor service is not running.")
                return

        # Get the current IP
        ip = get_current_ip(socks_port)
        if ip:
            print(f"[+] Current Tor IP: {ip}")

            # Get additional information about the IP
            proxy_config = "/etc/proxychains4.conf"
            if args.instance is not None:
                proxy_config = f"/etc/proxychains4.conf.{socks_port}"

            get_ip_info(proxy_config)
        else:
            print("[!] Could not get current Tor IP. Tor may not be working correctly.")

    if args.rotate:
        instance_num = None
        if args.instance is not None:
            instance_num = args.instance
        rotate_ip(instance_num)

    if args.restart_tor:
        instance_num = None
        if args.instance is not None:
            instance_num = args.instance
        restart_tor(instance_num)

    if args.daemon:
        # Check if we should run daemon for a specific instance, all instances, or just the main Tor
        if args.instance is not None:
            # Run for a specific instance
            ip_rotation_daemon(args.interval, args.instance)
        elif args.multi_tor is not None:
            # Run for all created instances
            instances = list(range(1, args.multi_tor + 1))
            ip_rotation_daemon(args.interval, instances=instances)
        else:
            # Run for main Tor
            ip_rotation_daemon(args.interval)

    if args.run_sqlmap:
        if not args.url:
            print("[!] Error: URL is required for SQLMap.")
            print("[!] Example: --run-sqlmap --url \"http://example.com/page.php?id=1\"")
            return

        # Build the SQLMap command
        sqlmap_cmd = f"sqlmap -u \"{args.url}\" --batch --random-agent"
        if args.sqlmap_args:
            sqlmap_cmd += f" {args.sqlmap_args}"

        # Determine which Tor instance to use
        port = 9050
        if args.instance is not None:
            port = 9050 + args.instance

        proxychains_conf = "/etc/proxychains4.conf"
        if args.instance is not None:
            proxychains_conf = f"/etc/proxychains4.conf.{port}"

        # Run SQLMap through proxychains
        cmd = f"proxychains4 -f {proxychains_conf} {sqlmap_cmd}"
        print(f"[*] Running SQLMap through Tor proxy (port {port})...")
        print(f"[*] Command: {cmd}")

        # Execute the command
        try:
            subprocess.call(cmd, shell=True)
        except KeyboardInterrupt:
            print("\n[!] SQLMap execution interrupted by user.")
        except Exception as e:
            print(f"\n[!] Error running SQLMap: {str(e)}")

    if args.create_recover_script:
        print("[*] Creating SQLMap recovery script...")

        recovery_script = """#!/bin/bash

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
    """

        with open("recover_sqlmap.sh", "w") as f:
            f.write(recovery_script)

        run_command("chmod +x recover_sqlmap.sh")

        print("[+] SQLMap recovery script created as recover_sqlmap.sh")
        print("[+] Usage: ./recover_sqlmap.sh <target_url> [sqlmap_args] [tor_instance]")
        print("[+] Example: ./recover_sqlmap.sh \"http://example.com/page.php?id=1\" \"--dbs --level=5\" 2")

        if __name__ == "__main__":
            main()

def main():
    parser = argparse.ArgumentParser(description="Tor Proxy Manager with IP Rotation")

    # Basic options
    parser.add_argument("--install", action="store_true", help="Install tor, proxychains4, sqlmap and curl")
    parser.add_argument("--setup-firefox", action="store_true", help="Configure Firefox to use Tor proxy")
    parser.add_argument("--rotate", action="store_true", help="Rotate Tor IP address once")
    parser.add_argument("--daemon", action="store_true", help="Run IP rotation daemon")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help=f"IP rotation interval in seconds (default: {DEFAULT_INTERVAL})")
    parser.add_argument("--restart-tor", action="store_true", help="Restart Tor service")
    parser.add_argument("--status", action="store_true", help="Check Tor status and current IP")
    parser.add_argument("--auto-restart", action="store_true", help="Setup auto-restart via crontab if script stops")
    parser.add_argument("--verify", action="store_true", help="Verify Tor connection is working properly")
    parser.add_argument("--create-test", action="store_true", help="Create a test script to verify Tor connection")
    parser.add_argument("--all", action="store_true", help="Setup everything (install, Firefox setup, test script, daemon)")

    # Multi-tor options
    parser.add_argument("--multi-tor", type=int, help="Setup multiple Tor instances")
    parser.add_argument("--instance", type=int, help="Specify Tor instance number for operations")
    parser.add_argument("--list-instances", action="store_true", help="List all available Tor instances")
    parser.add_argument("--delete-instance", type=int, help="Delete a specific Tor instance")
    parser.add_argument("--delete-all-instances", action="store_true", help="Delete all Tor instances except the main one")

    # Testing options
    parser.add_argument("--measure-latency", action="store_true", help="Measure latency difference between direct and Tor connections")

    # SQLMap integration
    parser.add_argument("--run-sqlmap", action="store_true", help="Run SQLMap through Tor proxy")
    parser.add_argument("--url", help="Target URL for SQLMap")
    parser.add_argument("--sqlmap-args", help="Additional SQLMap arguments")
    parser.add_argument("--create-recover-script", action="store_true", help="Create a script to recover SQLMap if it dies")

    args = parser.parse_args()

    # Check if script is run with root privileges
    if os.geteuid() != 0:
        print("[!] This script must be run with root privileges.")
        print("[!] Please run with sudo or as root.")
        sys.exit(1)

    # Print banner
    print("\n" + "=" * 60)
    print("" + " " * 15 + "Tor Proxy Manager with IP Rotation")
    print("" + " " * 20 + "CLI-only VPS Edition")
    print("=" * 60 + "\n")

    # Check if no arguments were provided, show help in that case
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    # Process arguments
    if args.install:
        install_packages()

    if args.list_instances:
        print("[*] Listing all Tor instances...")
        found_instances = []

        # First, check the main Tor service
        if check_tor_status():
            print("[+] Main Tor instance is running on port 9050")
            found_instances.append({"instance": 0, "port": 9050})

        # Then look for additional instances
        for i in range(1, 20):  # Check up to 20 possible instances
            port = 9050 + i
            config_path = f"/etc/proxychains4.conf.{port}"
            data_dir = f"/var/lib/tor/instance_{i}"

            if os.path.exists(config_path) or os.path.exists(data_dir):
                # Check if the instance is running
                proc_running = False
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.connect(("127.0.0.1", port))
                        proc_running = True
                except:
                    pass

                status = "Running" if proc_running else "Not running"
                print(f"[+] Tor instance {i} is configured on port {port} ({status})")
                found_instances.append({"instance": i, "port": port, "running": proc_running})

        if not found_instances:
            print("[!] No Tor instances found.")
            print("[!] Create instances with: --multi-tor <number>")

    if args.delete_instance is not None:
        instance_num = args.delete_instance
        print(f"[*] Deleting Tor instance {instance_num}...")

        # Stop the instance if it's running
        port = 9050 + instance_num
        config_path = f"/etc/proxychains4.conf.{port}"
        data_dir = f"/var/lib/tor/instance_{instance_num}"

        # Kill the process if it's running
        run_command(f"pkill -f 'tor -f /etc/tor/torrc.{instance_num}'")

        # Remove the files
        if os.path.exists(f"/etc/tor/torrc.{instance_num}"):
            run_command(f"rm /etc/tor/torrc.{instance_num}")

        if os.path.exists(config_path):
            run_command(f"rm {config_path}")

        if os.path.exists(data_dir):
            run_command(f"rm -rf {data_dir}")

        print(f"[+] Tor instance {instance_num} deleted.")

    if args.delete_all_instances:
        print("[*] Deleting all Tor instances except the main one...")

        # Stop all running instances
        run_command("pkill -f 'tor -f /etc/tor/torrc.[0-9]'")

        # Remove all instance files
        for i in range(1, 20):  # Handle up to 20 instances
            # Remove configuration files
            if os.path.exists(f"/etc/tor/torrc.{i}"):
                run_command(f"rm /etc/tor/torrc.{i}")

            # Remove proxychains configuration
            port = 9050 + i
            if os.path.exists(f"/etc/proxychains4.conf.{port}"):
                run_command(f"rm /etc/proxychains4.conf.{port}")

            # Remove data directories
            if os.path.exists(f"/var/lib/tor/instance_{i}"):
                run_command(f"rm -rf /var/lib/tor/instance_{i}")

        print("[+] All Tor instances deleted.")

    if args.multi_tor:
        setup_multiple_tor_instances(args.multi_tor)

    if args.measure_latency:
        proxy_config = None
        if args.instance is not None:
            proxy_config = f"/etc/proxychains4.conf.{9050 + args.instance}"
        measure_latency(proxy_config=proxy_config)

    if args.verify:
        socks_port = 9050
        if args.instance is not None:
            socks_port = 9050 + args.instance
        verify_tor_connection(socks_port)

    if args.create_test:
        create_test_script()

    if args.auto_restart:
        add_crontab_entry(args.interval)

    if args.setup_firefox:
        setup_firefox_proxy()

    if args.all:
        install_packages()
        setup_firefox_proxy()
        create_test_script()
        add_crontab_entry(args.interval)
        # Start daemon at the end
        args.daemon = True

    if args.status:
        # Check if we're checking status for a specific instance
        socks_port = 9050
        if args.instance is not None:
            socks_port = 9050 + args.instance
            print(f"[*] Checking status for Tor instance {args.instance} (port {socks_port})...")

            # Check if instance exists
            config_path = f"/etc/proxychains4.conf.{socks_port}"
            if not os.path.exists(config_path):
                print(f"[!] Tor instance {args.instance} is not configured.")
                print(f"[!] Create it first with: --multi-tor {args.instance}")
                return
        else:
            print("[*] Checking status for main Tor instance...")
            if not check_tor_status():
                print("[!] Tor service is not running.")
                return

        # Get the current IP
        ip = get_current_ip(socks_port)
        if ip:
            print(f"[+] Current Tor IP: {ip}")

            # Get additional information about the IP
            proxy_config = "/etc/proxychains4.conf"
            if args.instance is not None:
                proxy_config = f"/etc/proxychains4.conf.{socks_port}"

            get_ip_info(proxy_config)
        else:
            print("[!] Could not get current Tor IP. Tor may not be working correctly.")

    if args.rotate:
        instance_num = None
        if args.instance is not None:
            instance_num = args.instance
        rotate_ip(instance_num)

    if args.restart_tor:
        instance_num = None
        if args.instance is not None:
            instance_num = args.instance
        restart_tor(instance_num)

    if args.daemon:
        # Check if we should run daemon for a specific instance, all instances, or just the main Tor
        if args.instance is not None:
            # Run for a specific instance
            ip_rotation_daemon(args.interval, args.instance)
        elif args.multi_tor is not None:
            # Run for all created instances
            instances = list(range(1, args.multi_tor + 1))
            ip_rotation_daemon(args.interval, instances=instances)
        else:
            # Run for main Tor
            ip_rotation_daemon(args.interval)

    if args.run_sqlmap:
        if not args.url:
            print("[!] Error: URL is required for SQLMap.")
            print("[!] Example: --run-sqlmap --url \"http://example.com/page.php?id=1\"")
            return

        # Build the SQLMap command
        sqlmap_cmd = f"sqlmap -u \"{args.url}\" --batch --random-agent"
        if args.sqlmap_args:
            sqlmap_cmd += f" {args.sqlmap_args}"

        # Determine which Tor instance to use
        port = 9050
        if args.instance is not None:
            port = 9050 + args.instance

        proxychains_conf = "/etc/proxychains4.conf"
        if args.instance is not None:
            proxychains_conf = f"/etc/proxychains4.conf.{port}"

        # Run SQLMap through proxychains
        cmd = f"proxychains4 -f {proxychains_conf} {sqlmap_cmd}"
        print(f"[*] Running SQLMap through Tor proxy (port {port})...")
        print(f"[*] Command: {cmd}")

        # Execute the command
        try:
            subprocess.call(cmd, shell=True)
        except KeyboardInterrupt:
            print("\n[!] SQLMap execution interrupted by user.")
        except Exception as e:
            print(f"\n[!] Error running SQLMap: {str(e)}")

    if args.create_recover_script:
        print("[*] Creating SQLMap recovery script...")

        recovery_script = """#!/bin/bash

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
"""

        with open("recover_sqlmap.sh", "w") as f:
            f.write(recovery_script)

        run_command("chmod +x recover_sqlmap.sh")

        print("[+] SQLMap recovery script created as recover_sqlmap.sh")
        print("[+] Usage: ./recover_sqlmap.sh <target_url> [sqlmap_args] [tor_instance]")
        print("[+] Example: ./recover_sqlmap.sh \"http://example.com/page.php?id=1\" \"--dbs --level=5\" 2")

if __name__ == "__main__":
    main()
import os
import sys
import time
import subprocess
import argparse
import re
import threading
import json
import re
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

def create_test_script(interval=None, instances=None, instance_num=None):
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
    global avg_direct
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

        # If daemon is also specified, start a rotation daemon for all instances
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
    # Check if a script is run with root privileges
    if os.geteuid() != 0:
        print("[!] This script requires root privileges to install packages and configure services.")
        print("[!] Please run with sudo or as root.")
        sys.exit(1)

    main()
