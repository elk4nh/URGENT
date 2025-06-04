#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import argparse
import re
import json
import threading
import random
from datetime import datetime
from urllib.parse import urlparse

# Constants for testing
TEST_URLS = [
    "https://api.ipify.org",                 # Basic IP test
    "https://ipinfo.io/json",                # Detailed IP info
    "https://browserleaks.com/ip",           # IP leaks test
    "https://browserleaks.com/webrtc",       # WebRTC leaks test
    "https://www.perfect-privacy.com/webrtc-leaktest/",  # Another WebRTC test
    "https://ipleak.net",                    # Comprehensive leak test
    "https://dnsleaktest.com",               # DNS leak test
    "https://check.torproject.org"           # Tor check
]

# Global variables to track instances
tor_instances = []

def run_command(command, timeout=30):
    """Run a shell command and return the output with timeout"""
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, 
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=timeout)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {command}")
        print(f"Error message: {e.stderr}")
        return None

def get_proxy_instances():
    """Get information about all running Tor instances"""
    global tor_instances
    tor_instances = []

    # First, check the main Tor service
    if os.path.exists("/etc/proxychains4.conf"):
        tor_instances.append({"instance": 0, "socks_port": 9050, "control_port": 9051, "config": "/etc/proxychains4.conf"})

    # Then look for additional instances
    for i in range(1, 20):  # Check up to 20 possible instances
        port = 9050 + i
        config_path = f"/etc/proxychains4.conf.{port}"
        if os.path.exists(config_path):
            tor_instances.append({
                "instance": i,
                "socks_port": port,
                "control_port": 9051 + i,
                "config": config_path
            })

    return tor_instances

def measure_latency(url, proxy_config=None, num_requests=3):
    """Measure latency to a URL using the specified proxy"""
    times = []
    for i in range(num_requests):
        start_time = time.time()
        if proxy_config:
            cmd = f"proxychains4 -f {proxy_config} curl -s -o /dev/null -w '%{http_code}' {url}"
        else:
            cmd = f"curl -s -o /dev/null -w '%{http_code}' {url}"

        result = run_command(cmd)
        end_time = time.time()

        if result == "200":
            times.append(end_time - start_time)
        elif result == "TIMEOUT":
            times.append(30.0)  # Default timeout value

        time.sleep(0.5)  # Brief pause between requests

    # Calculate average, excluding timeouts
    valid_times = [t for t in times if t < 30.0]
    if valid_times:
        avg_time = sum(valid_times) / len(valid_times)
    else:
        avg_time = 30.0  # All were timeouts

    return {
        "times": times,
        "avg": avg_time,
        "min": min(times) if times else 30.0,
        "max": max(times) if times else 30.0,
        "timeouts": times.count(30.0)
    }

def get_ip_info(proxy_config=None):
    """Get detailed IP information using ipinfo.io"""
    if proxy_config:
        cmd = f"proxychains4 -f {proxy_config} curl -s https://ipinfo.io/json"
    else:
        cmd = "curl -s https://ipinfo.io/json"

    result = run_command(cmd)
    if result and result != "TIMEOUT":
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"error": "Invalid JSON response"}

    return {"error": "Failed to get IP info"}

def test_webrtc_leak(proxy_config=None):
    """Test for WebRTC leaks (basic test using headless browser)"""
    if not os.path.exists("/usr/bin/firefox") and not os.path.exists("/usr/bin/chromium-browser"):
        return {"error": "Firefox or Chromium not found. Install one of them for WebRTC testing."}

    # Create a temporary script to check WebRTC
    script_content = """
        const page = new Promise(resolve => {
            const iframe = document.createElement('iframe');
            document.body.appendChild(iframe);
            iframe.style.display = 'none';
            iframe.contentWindow.RTCPeerConnection = iframe.contentWindow.RTCPeerConnection || iframe.contentWindow.mozRTCPeerConnection || iframe.contentWindow.webkitRTCPeerConnection;
            const pc = new iframe.contentWindow.RTCPeerConnection({iceServers: [{urls: 'stun:stun.l.google.com:19302'}]});

            pc.createDataChannel('');
            pc.createOffer().then(offer => pc.setLocalDescription(offer));

            pc.onicecandidate = ice => {
                if (!ice || !ice.candidate || !ice.candidate.candidate) return;

                const candidate = ice.candidate.candidate;
                const regex = /([0-9]{1,3}(\.[0-9]{1,3}){3})/;
                const match = regex.exec(candidate);
                if (match) {
                    const ip = match[1];
                    console.log(JSON.stringify({rtcIp: ip}));
                    resolve();
                }
            };

            setTimeout(() => {
                console.log(JSON.stringify({rtcIp: 'Not detected'}));
                resolve();
            }, 2000);
        });
    """

    with open("/tmp/webrtc_check.js", "w") as f:
        f.write(script_content)

    # Run the browser with proxy settings
    if os.path.exists("/usr/bin/firefox"):
        browser_cmd = "firefox"
    else:
        browser_cmd = "chromium-browser"

    if proxy_config:
        cmd = f"proxychains4 -f {proxy_config} {browser_cmd} --headless --no-sandbox --disable-gpu --js-flags=\"--file=/tmp/webrtc_check.js\" about:blank 2>/dev/null | grep rtcIp"
    else:
        cmd = f"{browser_cmd} --headless --no-sandbox --disable-gpu --js-flags=\"--file=/tmp/webrtc_check.js\" about:blank 2>/dev/null | grep rtcIp"

    result = run_command(cmd, timeout=10)

    # Clean up temporary file
    if os.path.exists("/tmp/webrtc_check.js"):
        os.remove("/tmp/webrtc_check.js")

    if result and result != "TIMEOUT" and "{" in result:
        try:
            # Extract JSON from potential noise in the output
            json_match = re.search(r'\{.*\}', result)
            if json_match:
                return json.loads(json_match.group(0))
            return {"error": "No valid JSON found in output"}
        except json.JSONDecodeError:
            return {"error": "Invalid JSON response"}

    return {"rtcIp": "Test failed or timed out"}

def test_dns_leak(proxy_config=None):
    """Test for DNS leaks"""
    # Use a custom DNS leak test site that returns JSON
    if proxy_config:
        cmd = f"proxychains4 -f {proxy_config} curl -s https://dnsleaktest.com/json/api-dns-leak-test"
    else:
        cmd = "curl -s https://dnsleaktest.com/json/api-dns-leak-test"

    result = run_command(cmd)
    if result and result != "TIMEOUT":
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            # If the site doesn't return JSON, try a simpler test
            dns_servers = []
            for dns in ["1.1.1.1", "8.8.8.8", "9.9.9.9"]:
                if proxy_config:
                    cmd = f"proxychains4 -f {proxy_config} nslookup example.com {dns} | grep Server"
                else:
                    cmd = f"nslookup example.com {dns} | grep Server"

                dns_result = run_command(cmd)
                if dns_result and dns_result != "TIMEOUT":
                    dns_servers.append({"server": dns, "result": dns_result})

            return {"dns_servers": dns_servers}

    return {"error": "Failed to test DNS leaks"}

def check_tor_connection(proxy_config=None):
    """Check if the connection is going through Tor"""
    if proxy_config:
        cmd = f"proxychains4 -f {proxy_config} curl -s https://check.torproject.org | grep 'Congratulations'"
    else:
        cmd = "curl -s https://check.torproject.org | grep 'Congratulations'"

    result = run_command(cmd)

    is_tor = result is not None and "Congratulations" in result

    return {"is_tor": is_tor}

def test_proxy(instance=None, verbose=False):
    """Run a comprehensive test on a specific Tor proxy instance"""
    results = {}

    # Get proxy configuration
    if instance is None:
        proxy_config = "/etc/proxychains4.conf"
        instance_num = "main"
    else:
        proxy_config = instance["config"]
        instance_num = instance["instance"]

    print(f"\n[*] Testing Tor proxy instance {instance_num}...")

    # 1. Check if proxy is reachable
    print(f"[*] Checking if proxy is reachable...")
    latency = measure_latency("https://api.ipify.org", proxy_config)
    if latency["timeouts"] == 3:  # All requests timed out
        results["status"] = "unreachable"
        print(f"[!] Proxy is unreachable. All requests timed out.")
        return results

    results["latency"] = latency
    print(f"[+] Proxy is reachable. Avg latency: {latency['avg']:.2f}s")

    # 2. Get IP information
    print(f"[*] Getting IP information...")
    ip_info = get_ip_info(proxy_config)
    results["ip_info"] = ip_info

    if "ip" in ip_info:
        print(f"[+] IP: {ip_info['ip']}")
        if "city" in ip_info and "country" in ip_info:
            print(f"[+] Location: {ip_info.get('city', 'Unknown')}, {ip_info.get('country', 'Unknown')}")
        if "org" in ip_info:
            print(f"[+] ISP/Org: {ip_info.get('org', 'Unknown')}")
    else:
        print(f"[!] Could not get IP information.")

    # 3. Check Tor connection
    print(f"[*] Verifying Tor connection...")
    tor_check = check_tor_connection(proxy_config)
    results["is_tor"] = tor_check["is_tor"]

    if tor_check["is_tor"]:
        print(f"[+] Successfully connected through Tor.")
    else:
        print(f"[!] Not connected through Tor. This proxy may not be using Tor.")

    # 4. DNS leak test
    if verbose:
        print(f"[*] Testing for DNS leaks...")
        dns_leak = test_dns_leak(proxy_config)
        results["dns_leak"] = dns_leak

        if "error" in dns_leak:
            print(f"[!] DNS leak test failed: {dns_leak['error']}")
        else:
            print(f"[+] DNS leak test completed. Check results for details.")

    # 5. WebRTC leak test (if verbose)
    if verbose:
        print(f"[*] Testing for WebRTC leaks...")
        webrtc_leak = test_webrtc_leak(proxy_config)
        results["webrtc_leak"] = webrtc_leak

        if "error" in webrtc_leak:
            print(f"[!] WebRTC leak test failed: {webrtc_leak['error']}")
        elif "rtcIp" in webrtc_leak:
            if webrtc_leak["rtcIp"] == "Not detected":
                print(f"[+] No WebRTC leaks detected.")
            else:
                print(f"[!] WebRTC leak detected! IP: {webrtc_leak['rtcIp']}")

    # Compare direct IP with proxy IP
    if "ip_info" in results and "ip" in results["ip_info"]:
        direct_ip = get_ip_info()
        if "ip" in direct_ip and direct_ip["ip"] == results["ip_info"]["ip"]:
            print(f"[!] WARNING: Your proxy IP matches your direct IP. Anonymity compromised!")
            results["anonymity"] = "compromised"
        else:
            results["anonymity"] = "good"

    return results

def test_all_proxies(verbose=False, output_file=None):
    """Test all detected Tor proxy instances"""
    # Get direct connection info first for comparison
    print("\n[*] Getting direct connection information for comparison...")
    direct_ip = get_ip_info()

    if "ip" in direct_ip:
        print(f"[+] Your direct IP: {direct_ip['ip']}")
        if "city" in direct_ip and "country" in direct_ip:
            print(f"[+] Location: {direct_ip.get('city', 'Unknown')}, {direct_ip.get('country', 'Unknown')}")
    else:
        print(f"[!] Could not get direct IP information.")

    # Get all proxy instances
    instances = get_proxy_instances()

    if not instances:
        print("[!] No Tor proxy instances found. Please set up at least one instance.")
        return

    print(f"\n[*] Found {len(instances)} Tor proxy instances.")

    all_results = {}
    all_results["direct_connection"] = direct_ip
    all_results["proxies"] = {}

    # Test each instance
    for instance in instances:
        instance_num = instance["instance"]
        instance_name = "main" if instance_num == 0 else f"instance_{instance_num}"

        results = test_proxy(instance, verbose)
        all_results["proxies"][instance_name] = results

    # Save results to file if requested
    if output_file:
        with open(output_file, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\n[+] Results saved to {output_file}")

    # Print summary
    print("\n===== Proxy Test Summary =====")
    print(f"Direct IP: {direct_ip.get('ip', 'Unknown')}")

    for instance in instances:
        instance_num = instance["instance"]
        instance_name = "main" if instance_num == 0 else f"instance_{instance_num}"
        proxy_results = all_results["proxies"][instance_name]

        ip = proxy_results.get("ip_info", {}).get("ip", "Unknown")
        latency = proxy_results.get("latency", {}).get("avg", 0)
        is_tor = proxy_results.get("is_tor", False)

        status = "✓" if is_tor else "✗"
        print(f"{status} {instance_name}: IP {ip}, Latency {latency:.2f}s")

    return all_results

def create_or_delete_instances(num_instances=None, delete_all=False):
    """Create or delete Tor proxy instances"""
    if delete_all:
        print("[*] Deleting all Tor proxy instances...")

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

        print("[+] All Tor proxy instances deleted.")
        return

    if num_instances is None or num_instances < 1:
        print("[!] Please specify a valid number of instances to create.")
        return

    # Check if tor_proxy_setup.py exists
    if not os.path.exists('./tor_proxy_setup.py'):
        print("[!] tor_proxy_setup.py not found in the current directory.")
        return

    print(f"[*] Setting up {num_instances} Tor instances...")
    run_command(f"sudo python3 ./tor_proxy_setup.py --multi-tor {num_instances}")

    # Verify instances were created
    instances = get_proxy_instances()
    actual_instances = len([i for i in instances if i["instance"] != 0])

    if actual_instances == num_instances:
        print(f"[+] Successfully created {num_instances} Tor instances.")
    else:
        print(f"[!] Created {actual_instances} out of {num_instances} requested instances.")

def main():
    parser = argparse.ArgumentParser(description="Tor Proxy Testing Tool")

    # Main operation groups
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--test", action="store_true", help="Test all proxy instances")
    group.add_argument("--test-instance", type=int, help="Test a specific proxy instance (0 for main Tor)")
    group.add_argument("--create", type=int, help="Create specified number of Tor proxy instances")
    group.add_argument("--delete-all", action="store_true", help="Delete all Tor proxy instances")
    group.add_argument("--list", action="store_true", help="List all available proxy instances")

    # Additional options
    parser.add_argument("-v", "--verbose", action="store_true", help="Run verbose tests including WebRTC and DNS leaks")
    parser.add_argument("-o", "--output", help="Save test results to specified JSON file")

    args = parser.parse_args()

    # Handle commands
    if args.test:
        test_all_proxies(args.verbose, args.output)

    elif args.test_instance is not None:
        instances = get_proxy_instances()
        instance = next((i for i in instances if i["instance"] == args.test_instance), None)

        if instance:
            results = test_proxy(instance, args.verbose)
            if args.output:
                with open(args.output, "w") as f:
                    json.dump(results, f, indent=2)
                print(f"\n[+] Results saved to {args.output}")
        else:
            print(f"[!] Proxy instance {args.test_instance} not found.")

    elif args.create:
        create_or_delete_instances(args.create)

    elif args.delete_all:
        create_or_delete_instances(delete_all=True)

    elif args.list:
        instances = get_proxy_instances()

        if not instances:
            print("[!] No Tor proxy instances found.")
            return

        print("\n===== Available Tor Proxy Instances =====")
        for instance in instances:
            instance_num = instance["instance"]
            instance_name = "main" if instance_num == 0 else f"instance_{instance_num}"
            print(f"- {instance_name}: SOCKS Port {instance['socks_port']}, Control Port {instance['control_port']}")
            print(f"  Config: {instance['config']}")

if __name__ == "__main__":
    # Check if script is run with root privileges
    if os.geteuid() != 0:
        print("[!] This script requires root privileges.")
        print("[!] Please run with sudo or as root.")
        sys.exit(1)

    main()
