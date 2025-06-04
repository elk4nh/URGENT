#!/usr/bin/env python3

import os
import sys
import time
import socket
import socket
import json
import argparse
import subprocess
import tempfile
import threading
import http.server
import socketserver
import webbrowser
from pathlib import Path

# HTML content for WebRTC leak test
WEBRTC_TEST_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>WebRTC Leak Tester</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
        }
        h1, h2 {
            color: #2c3e50;
        }
        .card {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .ip-box {
            background: #e9ecef;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            margin: 10px 0;
        }
        .warning {
            color: #dc3545;
            font-weight: bold;
        }
        .success {
            color: #28a745;
            font-weight: bold;
        }
        .button {
            background: #007bff;
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 4px;
            cursor: pointer;
        }
        .button:hover {
            background: #0069d9;
        }
        #loading {
            display: none;
            margin-left: 10px;
        }
    </style>
</head>
<body>
    <h1>WebRTC and DNS Leak Test</h1>

    <div class="card">
        <h2>Current Public IP</h2>
        <div id="public-ip" class="ip-box">Checking...</div>
    </div>

    <div class="card">
        <h2>WebRTC Local IP Addresses</h2>
        <p>These are your local network IPs that WebRTC might expose:</p>
        <div id="local-ips" class="ip-box">Checking...</div>
    </div>

    <div class="card">
        <h2>WebRTC Public IP Address</h2>
        <p>This is the public IP that WebRTC might expose:</p>
        <div id="webrtc-public-ip" class="ip-box">Checking...</div>
    </div>

    <div class="card">
        <h2>Leak Detection Results</h2>
        <div id="results">Running tests...</div>
    </div>

    <div class="card">
        <h2>DNS Leak Test</h2>
        <p>Testing if your DNS requests are leaking outside the Tor network:</p>
        <div id="dns-test" class="ip-box">Checking...</div>
        <button id="test-dns" class="button">Run DNS Leak Test</button>
        <span id="loading">Testing...</span>
    </div>

    <div class="card">
        <h2>Tools for Further Testing</h2>
        <p>For more comprehensive testing, visit these external sites:</p>
        <ul>
            <li><a href="https://browserleaks.com/webrtc" target="_blank">BrowserLeaks WebRTC Test</a></li>
            <li><a href="https://ipleak.net" target="_blank">IPLeak.net</a></li>
            <li><a href="https://dnsleaktest.com" target="_blank">DNS Leak Test</a></li>
        </ul>
    </div>

    <script>
    // Get public IP
    fetch('https://api.ipify.org?format=json')
        .then(response => response.json())
        .then(data => {
            document.getElementById('public-ip').textContent = data.ip;
        })
        .catch(error => {
            document.getElementById('public-ip').textContent = 'Error: Could not retrieve public IP';
        });

    // WebRTC local IP detection
    function findLocalIPs() {
        const rtcPeerConnection = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection;
        if (!rtcPeerConnection) {
            document.getElementById('local-ips').innerHTML = 'WebRTC not supported in this browser';
            return;
        }

        const pc = new rtcPeerConnection({
            iceServers: []
        });
        const localIPs = {};

        pc.createDataChannel('');
        pc.createOffer().then(offer => pc.setLocalDescription(offer));

        pc.onicecandidate = function(ice) {
            if (!ice || !ice.candidate || !ice.candidate.candidate) return;

            const candidate = ice.candidate.candidate;
            const match = /([0-9]{1,3}(\.[0-9]{1,3}){3})/.exec(candidate);
            if (match) {
                const ip = match[1];
                if (ip !== '0.0.0.0' && !localIPs[ip]) {
                    localIPs[ip] = true;
                    updateLocalIPs(Object.keys(localIPs));
                }
            }
        };

        // Set a timeout to ensure we show results even if no candidates are found
        setTimeout(function() {
            const ips = Object.keys(localIPs);
            if (ips.length === 0) {
                document.getElementById('local-ips').textContent = 'No local IPs detected or WebRTC is blocked';
            }
        }, 2000);
    }

    function updateLocalIPs(ips) {
        if (ips.length > 0) {
            document.getElementById('local-ips').innerHTML = ips.join('<br>');
        } else {
            document.getElementById('local-ips').textContent = 'No local IPs detected';
        }
    }

    // WebRTC public IP detection
    function findPublicIP() {
        const rtcPeerConnection = window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection;
        if (!rtcPeerConnection) {
            document.getElementById('webrtc-public-ip').innerHTML = 'WebRTC not supported in this browser';
            return;
        }

        const pc = new rtcPeerConnection({
            iceServers: [{
                urls: 'stun:stun.l.google.com:19302'
            }]
        });

        pc.createDataChannel('');
        pc.createOffer().then(offer => pc.setLocalDescription(offer));

        let publicIP = null;
        pc.onicecandidate = function(ice) {
            if (!ice || !ice.candidate || !ice.candidate.candidate) return;

            const candidate = ice.candidate.candidate;
            const match = /([0-9]{1,3}(\.[0-9]{1,3}){3})/.exec(candidate);
            if (match) {
                const ip = match[1];
                // Check if this is likely a public IP (not local)
                if (!ip.startsWith('10.') && !ip.startsWith('192.168.') && !ip.startsWith('172.')) {
                    publicIP = ip;
                    document.getElementById('webrtc-public-ip').textContent = publicIP;
                    checkForLeaks();
                }
            }
        };

        // Set a timeout to ensure we show results even if no candidates are found
        setTimeout(function() {
            if (!publicIP) {
                document.getElementById('webrtc-public-ip').textContent = 'No public IP detected or WebRTC is blocked';
                checkForLeaks();
            }
        }, 2000);
    }

    // DNS leak test
    document.getElementById('test-dns').addEventListener('click', function() {
        const button = this;
        const loading = document.getElementById('loading');
        const dnsTest = document.getElementById('dns-test');

        button.disabled = true;
        loading.style.display = 'inline';
        dnsTest.textContent = 'Testing...';

        // Make requests to multiple DNS leak test services
        Promise.all([
            fetch('https://dnsleaktest.com/json/api-dns-leak-test'),
            fetch('https://www.dnsleaktest.com/api-dns-leak-test.php')
        ])
        .then(responses => {
            return Promise.all(responses.map(response => response.json()));
        })
        .then(data => {
            const combinedResults = [];
            data.forEach(result => {
                if (result && Array.isArray(result)) {
                    combinedResults.push(...result);
                }
            });

            if (combinedResults.length > 0) {
                const dnsServers = combinedResults.map(server => 
                    `${server.ip} (${server.country})`
                ).join('<br>');
                dnsTest.innerHTML = dnsServers;

                // Check for DNS leaks
                if (combinedResults.length > 1) {
                    document.getElementById('results').innerHTML += '<p class="warning">Potential DNS leak detected! Multiple DNS servers found.</p>';
                } else {
                    document.getElementById('results').innerHTML += '<p class="success">DNS test: Only one DNS server detected, which is good.</p>';
                }
            } else {
                dnsTest.textContent = 'Could not perform DNS leak test';
            }
        })
        .catch(error => {
            dnsTest.textContent = 'Error running DNS leak test';
            console.error('DNS leak test error:', error);
        })
        .finally(() => {
            button.disabled = false;
            loading.style.display = 'none';
        });
    });

    // Check for potential leaks
    function checkForLeaks() {
        const publicIP = document.getElementById('public-ip').textContent;
        const webrtcIP = document.getElementById('webrtc-public-ip').textContent;

        const resultsDiv = document.getElementById('results');

        if (publicIP === 'Checking...' || webrtcIP === 'Checking...') {
            setTimeout(checkForLeaks, 500);
            return;
        }

        if (publicIP !== 'Error: Could not retrieve public IP' && 
            webrtcIP !== 'No public IP detected or WebRTC is blocked' && 
            webrtcIP !== 'WebRTC not supported in this browser') {

            if (publicIP === webrtcIP) {
                resultsDiv.innerHTML = '<p class="warning">WebRTC LEAK DETECTED! Your WebRTC public IP matches your actual public IP.</p>';
            } else {
                resultsDiv.innerHTML = '<p class="success">No WebRTC IP leak detected. Your WebRTC public IP is different from your actual public IP.</p>';
            }
        } else if (webrtcIP === 'No public IP detected or WebRTC is blocked') {
            resultsDiv.innerHTML = '<p class="success">WebRTC appears to be properly blocked. No IP was exposed.</p>';
        } else {
            resultsDiv.innerHTML = '<p>Could not complete leak test. Some information is missing.</p>';
        }
    }

    // Run tests
    findLocalIPs();
    findPublicIP();
    </script>
</body>
</html>
"""

# DNS leak test HTML
DNS_TEST_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>DNS Leak Test</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
        }
        h1, h2 {
            color: #2c3e50;
        }
        .card {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .dns-server {
            background: #e9ecef;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
            font-family: monospace;
        }
        .warning {
            color: #dc3545;
            font-weight: bold;
        }
        .success {
            color: #28a745;
            font-weight: bold;
        }
        .button {
            background: #007bff;
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 4px;
            cursor: pointer;
            margin-top: 10px;
        }
        .button:hover {
            background: #0069d9;
        }
        #loading {
            display: none;
        }
    </style>
</head>
<body>
    <h1>DNS Leak Test</h1>

    <div class="card">
        <h2>What is a DNS leak?</h2>
        <p>When using Tor, your DNS requests should go through the Tor network. If they leak, they could reveal your real location and ISP.</p>
    </div>

    <div class="card">
        <h2>DNS Servers Being Used</h2>
        <p>These are the DNS servers that were detected for your connection:</p>
        <div id="dns-servers">Click the button below to start the test...</div>
        <button id="run-test" class="button">Run DNS Leak Test</button>
        <div id="loading">Testing... this may take a few seconds.</div>
    </div>

    <div class="card">
        <h2>Test Results</h2>
        <div id="results">Results will appear after the test is run.</div>
    </div>

    <script>
    document.getElementById('run-test').addEventListener('click', function() {
        const button = this;
        const loading = document.getElementById('loading');
        const dnsServersDiv = document.getElementById('dns-servers');
        const resultsDiv = document.getElementById('results');

        button.disabled = true;
        loading.style.display = 'block';
        dnsServersDiv.textContent = 'Testing...';
        resultsDiv.textContent = 'Analyzing...';

        // Make multiple requests to different DNS servers
        const requests = [
            fetch('https://dnsleaktest.com/json/api-dns-leak-test'),
            fetch('https://www.dnsleaktest.com/api-dns-leak-test.php')
        ];

        // Add additional hostnames that force DNS lookups
        ['google.com', 'facebook.com', 'amazon.com', 'netflix.com', 'microsoft.com'].forEach(domain => {
            requests.push(fetch(`https://${domain}/favicon.ico`, { mode: 'no-cors' }));
        });

        // Wait a moment to allow DNS queries to be made, then check results
        setTimeout(() => {
            Promise.all([
                fetch('https://dnsleaktest.com/json/api-dns-leak-test'),
                fetch('https://www.dnsleaktest.com/api-dns-leak-test.php')
            ])
            .then(responses => {
                return Promise.all(responses.map(response => {
                    if (!response.ok) {
                        throw new Error('Network response was not ok');
                    }
                    return response.json();
                }));
            })
            .then(data => {
                const servers = new Set();
                let serverHTML = '';

                data.forEach(result => {
                    if (Array.isArray(result)) {
                        result.forEach(server => {
                            if (server && server.ip) {
                                servers.add(`${server.ip} (${server.country || 'Unknown'})`);
                            }
                        });
                    }
                });

                if (servers.size === 0) {
                    dnsServersDiv.innerHTML = 'No DNS servers detected. This could mean the test failed or DNS requests are properly routed through Tor.';
                } else {
                    servers.forEach(server => {
                        serverHTML += `<div class="dns-server">${server}</div>`;
                    });
                    dnsServersDiv.innerHTML = serverHTML;
                }

                // Analyze results
                if (servers.size === 0) {
                    resultsDiv.innerHTML = '<p>Could not detect any DNS servers. This may be good (Tor is working properly) or the test failed.</p>';
                } else if (servers.size === 1) {
                    resultsDiv.innerHTML = '<p class="success">Only one DNS server detected, which suggests DNS requests are properly routed.</p>';
                } else {
                    resultsDiv.innerHTML = `<p class="warning">Potential DNS leak detected! ${servers.size} different DNS servers were found.</p>` +
                                          '<p>When using Tor, all DNS requests should go through the Tor network.</p>';
                }
            })
            .catch(error => {
                console.error('Error:', error);
                dnsServersDiv.textContent = 'Error running the DNS leak test.';
                resultsDiv.textContent = 'Test failed due to an error. Please try again later.';
            })
            .finally(() => {
                button.disabled = false;
                loading.style.display = 'none';
            });
        }, 3000); // Wait 3 seconds for DNS queries to complete
    });
    </script>
</body>
</html>
"""

# Custom HTTP server that can run with a specific proxy
class ProxyHttpServer:
    def __init__(self, port=8888, proxy_config=None):
        self.port = port
        self.proxy_config = proxy_config
        self.server = None
        self.server_thread = None
        self.temp_dir = None

    def create_test_files(self):
        """Create temporary HTML test files"""
        self.temp_dir = tempfile.mkdtemp(prefix="tor_leak_test_")

        # Create WebRTC test page
        webrtc_path = os.path.join(self.temp_dir, "webrtc_test.html")
        with open(webrtc_path, "w") as f:
            f.write(WEBRTC_TEST_HTML)

        # Create DNS test page
        dns_path = os.path.join(self.temp_dir, "dns_test.html")
        with open(dns_path, "w") as f:
            f.write(DNS_TEST_HTML)

        # Create index page
        index_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Tor Leak Tests</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    line-height: 1.6;
                    color: #333;
                    max-width: 800px;
                    margin: 0 auto;
                }}
                h1, h2 {{
                    color: #2c3e50;
                }}
                .card {{
                    background: #f8f9fa;
                    border-radius: 8px;
                    padding: 20px;
                    margin-bottom: 20px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .button {{
                    display: inline-block;
                    background: #007bff;
                    color: white;
                    border: none;
                    padding: 10px 15px;
                    border-radius: 4px;
                    cursor: pointer;
                    text-decoration: none;
                    margin-right: 10px;
                }}
                .button:hover {{
                    background: #0069d9;
                }}
                .proxy-info {{
                    background: #e9ecef;
                    padding: 10px;
                    border-radius: 4px;
                    margin-top: 20px;
                    font-family: monospace;
                }}
            </style>
        </head>
        <body>
            <h1>Tor Leak Test Suite</h1>

            <div class="card">
                <h2>Available Tests</h2>
                <p>Select one of the following tests:</p>
                <a href="/webrtc_test.html" class="button">WebRTC Leak Test</a>
                <a href="/dns_test.html" class="button">DNS Leak Test</a>
            </div>

            <div class="card">
                <h2>How to Use These Tests</h2>
                <p>These tests will help you verify if your Tor proxy is properly protecting your identity:</p>
                <ul>
                    <li><strong>WebRTC Leak Test</strong>: Checks if WebRTC is exposing your real IP address</li>
                    <li><strong>DNS Leak Test</strong>: Verifies if DNS requests are going through Tor</li>
                </ul>
            </div>

            <div class="proxy-info">
                Running with proxy: {self.proxy_config if self.proxy_config else 'Direct connection (no proxy)'}
            </div>
        </body>
        </html>
        """

        index_path = os.path.join(self.temp_dir, "index.html")
        with open(index_path, "w") as f:
            f.write(index_html)

        return self.temp_dir

    def start_server(self):
        """Start HTTP server in a separate thread"""
        dir_path = self.create_test_files()
        os.chdir(dir_path)

        # Create custom handler
        handler = http.server.SimpleHTTPRequestHandler

        class CustomHTTPServer(socketserver.TCPServer):
            allow_reuse_address = True

        self.server = CustomHTTPServer(("", self.port), handler)

        # Start server in a separate thread
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

        print(f"[+] Server started at http://localhost:{self.port}")
        print(f"[+] Test files available in: {dir_path}")

        return f"http://localhost:{self.port}"

    def stop_server(self):
        """Stop the server and clean up"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            print("[+] Server stopped")

        # Clean up temporary files
        if self.temp_dir and os.path.exists(self.temp_dir):
            # Keep files for a while in case they're still being used
            print(f"[*] Temporary files will remain in {self.temp_dir} until program exits")

def open_browser_with_proxy(url, proxy_config=None):
    """Open the default browser with the specified proxy configuration"""
    if proxy_config and os.path.exists(proxy_config):
        # Get SOCKS port from proxychains config
        socks_port = None
        try:
            with open(proxy_config, 'r') as f:
                for line in f:
                    if 'socks5 127.0.0.1' in line:
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            socks_port = parts[2]
                            break
        except Exception as e:
            print(f"[!] Error reading proxy config: {e}")

        if socks_port:
            firefox_cmd = f"proxychains4 -f {proxy_config} firefox --new-instance -P 'TorTest' \
                          -no-remote -url {url}"
            try:
                subprocess.Popen(firefox_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"[+] Opened Firefox with proxy (SOCKS port: {socks_port})")
                return True
            except Exception as e:
                print(f"[!] Error opening Firefox with proxy: {e}")
        else:
            print(f"[!] Could not determine SOCKS port from {proxy_config}")

    # Fallback to default browser without proxy
    try:
        webbrowser.open(url)
        print(f"[+] Opened default browser (no proxy)")
        return True
    except Exception as e:
        print(f"[!] Error opening browser: {e}")
        return False

def get_available_proxy_configs():
    """Get a list of available proxychains configurations"""
    configs = []

    # Check for main config
    if os.path.exists("/etc/proxychains4.conf"):
        configs.append({"instance": 0, "name": "Main Tor", "config": "/etc/proxychains4.conf"})

    # Check for additional instances
    for i in range(1, 20):
        port = 9050 + i
        config_path = f"/etc/proxychains4.conf.{port}"
        if os.path.exists(config_path):
            configs.append({"instance": i, "name": f"Instance {i}", "config": config_path})

    return configs

def main():
    parser = argparse.ArgumentParser(description="Browser-based WebRTC and DNS Leak Test for Tor")
    parser.add_argument("-i", "--instance", type=int, help="Tor instance number to test (0 for main)")
    parser.add_argument("-p", "--port", type=int, default=8888, help="Port for the test server (default: 8888)")
    parser.add_argument("-a", "--all", action="store_true", help="Test all available Tor instances")
    parser.add_argument("-l", "--list", action="store_true", help="List available Tor instances")

    args = parser.parse_args()

    if args.list:
        configs = get_available_proxy_configs()
        if not configs:
            print("[!] No Tor proxy configurations found.")
            return

        print("\nAvailable Tor proxy configurations:")
        for config in configs:
            print(f"  {config['instance']}: {config['name']} ({config['config']})")
        return

    # Determine which proxy config to use
    if args.instance is not None:
        if args.instance == 0:
            proxy_config = "/etc/proxychains4.conf"
            if not os.path.exists(proxy_config):
                print(f"[!] Main Tor proxy configuration not found at {proxy_config}")
                return
            print(f"[*] Testing main Tor instance with config: {proxy_config}")
        else:
            port = 9050 + args.instance
            proxy_config = f"/etc/proxychains4.conf.{port}"
            if not os.path.exists(proxy_config):
                print(f"[!] Proxy configuration for instance {args.instance} not found at {proxy_config}")
                return
            print(f"[*] Testing Tor instance {args.instance} with config: {proxy_config}")

        # Start server and open browser
        server = ProxyHttpServer(args.port, proxy_config)
        url = server.start_server()

        if open_browser_with_proxy(url, proxy_config):
            print("\n[*] Browser leak test started. Please check the browser window.")
            print("[*] Press Ctrl+C to stop the server when done.")

            # Keep the script running
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[*] Stopping server...")
                server.stop_server()

    elif args.all:
        configs = get_available_proxy_configs()
        if not configs:
            print("[!] No Tor proxy configurations found.")
            return

        print(f"[*] Found {len(configs)} Tor proxy configurations.")
        print("[*] Testing each configuration in sequence...")

        for config in configs:
            proxy_config = config["config"]
            print(f"\n[*] Testing {config['name']} with config: {proxy_config}")

            # Start server and open browser
            server = ProxyHttpServer(args.port, proxy_config)
            url = server.start_server()

            if open_browser_with_proxy(url, proxy_config):
                print("\n[*] Browser leak test started. Please check the browser window.")
                print("[*] Press Enter to continue to the next instance or Ctrl+C to stop.")

                try:
                    input()
                except KeyboardInterrupt:
                    print("\n[*] Stopping server...")
                    server.stop_server()
                    break

                server.stop_server()

    else:
        # No instance specified, use direct connection for comparison
        print("[*] No Tor instance specified. Running tests with direct connection for baseline comparison.")

        server = ProxyHttpServer(args.port)
        url = server.start_server()

        if open_browser_with_proxy(url):
            print("\n[*] Browser leak test started. Please check the browser window.")
            print("[*] Press Ctrl+C to stop the server when done.")

            # Keep the script running
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[*] Stopping server...")
                server.stop_server()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] This script requires root privileges for proxychains.")
        print("[!] Please run with sudo or as root.")
        sys.exit(1)

    main()
