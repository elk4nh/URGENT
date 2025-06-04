# Tor Proxy Manager
# Tor Proxy Manager

A tool for managing Tor proxies with automatic IP rotation for CLI-only VPS systems.

## Features

- Easy setup of Tor proxy with automatic IP rotation
- Multiple Tor instances for parallel operations
- SQLMap integration with automatic Tor proxy rotation
- Firefox configuration for Tor proxy use
- Comprehensive testing tools
- Auto-restart capability

## Installation

1. Clone or download this repository
2. Run the setup script as root:

```bash
sudo ./setup.sh
```

The setup script will:
- Install required packages (tor, proxychains4, sqlmap, curl)
- Configure Tor for IP rotation
- Set up Firefox to use Tor (optional - Firefox-ESR will be installed if not present)
- Create test scripts
- Configure auto-restart
- Start the IP rotation daemon

### Main Scripts

After installation, these scripts will be available on your system:

- `tor_proxy_setup.py` - The main script for managing Tor proxies
- `/usr/local/bin/test-tor` - Script to test your Tor connection
- `/usr/local/bin/firefox-tor` - Script to launch Firefox with Tor proxy
- `/usr/local/bin/check_tor_proxy.sh` - Script that ensures the Tor proxy is running

## Basic Usage

Run any command through Tor proxy:

```bash
proxychains4 <command>
```

For example:

```bash
proxychains4 curl https://api.ipify.org
```

## Command Line Options

### Main Options

```bash
sudo python3 tor_proxy_setup.py [OPTIONS]
```

| Option | Description | Example |
|--------|-------------|--------|
| `--install` | Install tor, proxychains4, sqlmap and curl | `--install` |
| `--setup-firefox` | Configure Firefox to use Tor proxy | `--setup-firefox` |
| `--rotate` | Rotate Tor IP address once | `--rotate` |
| `--daemon` | Run IP rotation daemon | `--daemon` |
| `--interval SECONDS` | IP rotation interval in seconds (default: 60) | `--interval 120` |
| `--restart-tor` | Restart Tor service | `--restart-tor` |
| `--status` | Check Tor status and current IP | `--status` |
| `--auto-restart` | Setup auto-restart via crontab if script stops | `--auto-restart` |
| `--verify` | Verify Tor connection is working properly | `--verify` |
| `--create-test` | Create a test script to verify Tor connection | `--create-test` |
| `--all` | Setup everything (install, Firefox setup, test script, daemon) | `--all` |

### Multiple Tor Instances

```bash
sudo python3 tor_proxy_setup.py --multi-tor 5
```

This creates 5 Tor instances with different IPs that can be used in parallel.

| Option | Description | Example |
|--------|-------------|--------|
| `--multi-tor NUMBER` | Setup multiple Tor instances | `--multi-tor 5` |
| `--instance NUMBER` | Specify Tor instance number for operations | `--rotate --instance 2` |
| `--list-instances` | List all available Tor instances | `--list-instances` |
| `--delete-instance NUMBER` | Delete a specific Tor instance | `--delete-instance 3` |
| `--delete-all-instances` | Delete all Tor instances except the main one | `--delete-all-instances` |

For example, to set up 3 Tor instances and rotate the IP of instance 2:

```bash
sudo python3 tor_proxy_setup.py --multi-tor 3
sudo python3 tor_proxy_setup.py --rotate --instance 2
```

### SQLMap Integration

```bash
sudo python3 tor_proxy_setup.py --run-sqlmap --url "http://example.com/page.php?id=1" --sqlmap-args "--dbs --level=5"
```

For multi-instance SQLMap runs:

```bash
sudo python3 multi_sqlmap_runner.py -i 5 -u "http://example.com/page.php?id=1" -p "--dbs --level=5"
```

## Testing Your Connection

Test your Tor connection:

```bash
test-tor
```

Comprehensive test with instance selection:

```bash
test-tor -i 2 -c
```

Options:
- `-i, --instance NUMBER` - Test a specific Tor instance (e.g., `test-tor -i 3`)
- `-c, --comprehensive` - Run additional tests for DNS and WebRTC leaks

## Examples

Basic usage examples with the main script:

```bash
# Check your current Tor IP
sudo python3 tor_proxy_setup.py --status

# Manually rotate your Tor IP
sudo python3 tor_proxy_setup.py --rotate

# Start IP rotation daemon with 2-minute interval
sudo python3 tor_proxy_setup.py --daemon --interval 120

# Set up 3 Tor instances and run SQLMap through all of them
sudo python3 tor_proxy_setup.py --multi-tor 3
sudo python3 multi_sqlmap_runner.py -i 3 -u "http://example.com/page.php?id=1"

# Run normal commands through Tor
proxychains4 curl https://api.ipify.org
proxychains4 wget https://example.com/file.zip
```

## Troubleshooting

- If you encounter connection issues, try restarting Tor:
  ```bash
  sudo python3 tor_proxy_setup.py --restart-tor
  ```

- Check if your Tor connection is working properly:
  ```bash
  sudo python3 tor_proxy_setup.py --verify
  ```

- If a specific Tor instance is not working, you can restart it:
  ```bash
  sudo python3 tor_proxy_setup.py --restart-tor --instance 2
  ```

## Security Notes

- While Tor provides anonymity, it's not foolproof. Don't rely on it for high-stakes anonymity needs.
- The tool is designed for CLI-only VPS systems and ethical use cases like security testing.
- Always ensure you have permission to scan or test any target systems.
A lightweight, portable Tor proxy manager with automatic IP rotation for anonymous browsing and security testing. This tool is designed to be simple yet powerful, especially for CLI-only VPS environments.

## Features

- One-click installation of Tor, proxychains4, sqlmap, and curl
- Multiple Tor instances with different IPs running simultaneously
- Auto-recovery for sqlmap processes if they crash
- Multi-threaded scanning with different IPs
- Firefox proxy configuration for anonymous browsing
- Automatic IP rotation at configurable intervals
- Connection verification to ensure Tor is working properly
- Built-in test script to verify anonymity
- Auto-restart functionality if the script stops running
- Minimal dependencies, works on most Debian-based systems

## Quick Setup

1. Download the scripts to your system
2. Make the setup script executable and run it:
   ```bash
   chmod +x setup.sh
   sudo ./setup.sh
   ```

This simple setup will:
- Install all required packages
- Configure Tor and proxychains4
- Set up Firefox proxy configuration
- Start IP rotation daemon
- Configure auto-restart via crontab

## Manual Usage

For more control, you can use the Python script directly:

```bash
# Install everything and run with defaults
sudo python3 tor_proxy_setup.py --all

# Or configure individual components:

# Just install required packages
sudo python3 tor_proxy_setup.py --install

# Setup Firefox to use Tor proxy
sudo python3 tor_proxy_setup.py --setup-firefox

# Create a test script to verify your connection
sudo python3 tor_proxy_setup.py --create-test

# Verify Tor connection is working properly
sudo python3 tor_proxy_setup.py --verify

# Check current status and IP
sudo python3 tor_proxy_setup.py --status

# Rotate IP address once
sudo python3 tor_proxy_setup.py --rotate

# Run IP rotation daemon with custom interval (e.g., 30 seconds)
sudo python3 tor_proxy_setup.py --daemon --interval 30

# Set up auto-restart via crontab
sudo python3 tor_proxy_setup.py --auto-restart
```

## Multi-Tor Usage

Run multiple Tor instances simultaneously, each with a different IP:

```bash
# Setup 5 Tor instances
sudo python3 tor_proxy_setup.py --multi-tor 5

# Rotate IP for a specific instance
sudo python3 tor_proxy_setup.py --rotate --instance 3

# Check status/IP of a specific instance
sudo python3 tor_proxy_setup.py --status --instance 2

# Run IP rotation daemon for a specific instance
sudo python3 tor_proxy_setup.py --daemon --interval 45 --instance 1

# Run IP rotation for all instances
sudo python3 tor_proxy_setup.py --multi-tor 5 --daemon --interval 60
```

## SQLMap with Auto-Recovery

Use the multi-sqlmap runner to run several sqlmap instances through different Tor proxies:

```bash
# Run 5 sqlmap instances on the target with different Tor IPs
sudo python3 multi_sqlmap_runner.py -i 5 -u "http://example.com/page.php?id=1" -p "--dbs --level=5" -r 60

# Single sqlmap with auto-recovery if it dies
sudo ./recover_sqlmap.sh "http://example.com/page.php?id=1" "--dbs --level=5" 2
```

## Proxy Testing and Management

Use the proxy testing tool to verify that your Tor proxies are working correctly and provide anonymity:

```bash
# Test all proxy instances (basic test)
sudo python3 proxy_tester.py --test

# Run comprehensive tests including WebRTC and DNS leak detection
sudo python3 proxy_tester.py --test --verbose

# Test a specific proxy instance
sudo python3 proxy_tester.py --test-instance 3 --verbose

# Create new proxy instances
sudo python3 proxy_tester.py --create 5

# List all available proxy instances
sudo python3 proxy_tester.py --list

# Delete all proxy instances
sudo python3 proxy_tester.py --delete-all

# Save test results to a file
sudo python3 proxy_tester.py --test --output proxy_report.json
```

You can also use the enhanced test-tor script for quick checks:

```bash
# Test the main Tor instance
/usr/local/bin/test-tor

# Test a specific Tor instance
/usr/local/bin/test-tor --instance 2

# Run comprehensive tests including WebRTC and DNS leak checks
/usr/local/bin/test-tor --comprehensive
```

## Practical Examples

### Verify Your Tor Connection

```bash
# Run the basic test script
/usr/local/bin/test-tor

# Test a specific instance
/usr/local/bin/test-tor --instance 2

# Comprehensive test including WebRTC and DNS leak checks
/usr/local/bin/test-tor --comprehensive

# Quick IP check
echo "Regular IP: $(curl -s https://api.ipify.org)"
echo "Tor IP: $(proxychains4 curl -s https://api.ipify.org)"

# Interactive browser-based leak testing
sudo python3 browser_leak_test.py --instance 3
```

### Run Commands Through Tor Proxy

```bash
# Get detailed IP information
proxychains4 curl ipinfo.io

# Run sqlmap through Tor
proxychains4 sqlmap -u "http://example.com/page.php?id=1" --dbs

# Run any command with Tor
proxychains4 wget https://example.com/file.zip

# Browse with Firefox through Tor
/usr/local/bin/firefox-tor
```

### Troubleshooting

If you encounter issues:

1. Check Tor status: `sudo systemctl status tor`
2. Manually restart Tor: `sudo python3 tor_proxy_setup.py --restart-tor`
3. Check current IP: `sudo python3 tor_proxy_setup.py --status`
4. Verify crontab is set: `crontab -l | grep check_tor_proxy.sh`

## Notes

- This tool is designed for educational and legitimate security testing purposes
- For higher security, consider using the official Tor Browser
- Works best on Debian-based systems (Ubuntu, Kali Linux, etc.)
