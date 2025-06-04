# Common Tor and Proxy Issues - Troubleshooting Guide

## System Requirements

Ensure your system meets these requirements:

- Debian-based Linux system (Ubuntu, Kali, etc.)
- Python 3.6 or higher
- Root privileges for installation
- At least 512MB RAM for basic functionality
- At least 1GB RAM for multiple Tor instances

## Common Errors and Fixes

### 1. Connection Refused Errors

**Problem**: `Connection refused` when trying to connect to Tor

**Fix**:
```bash
# Restart Tor service
sudo systemctl restart tor

# Check if Tor is running
sudo systemctl status tor

# If port conflicts occur, modify /etc/tor/torrc
sudo nano /etc/tor/torrc
# Change SocksPort to a different port (e.g., 9051)
```

### 2. DNS Resolution Issues

**Problem**: DNS leaks or inability to resolve domains

**Fix**:
```bash
# Run the DNS fix script
sudo ./dns_fix.sh

# Or manually configure DNS
echo "nameserver 8.8.8.8
nameserver 1.1.1.1" | sudo tee /etc/resolv.conf
```

### 3. Python Module Import Errors

**Problem**: Missing Python modules

**Fix**:
```bash
# Install all required Python dependencies
sudo pip3 install -r requirements.txt

# If specific module issues persist, install individually
sudo pip3 install <module_name>
```

### 4. Permission Denied Errors

**Problem**: Permission issues when running scripts

**Fix**:
```bash
# Make scripts executable
chmod +x *.py *.sh

# Run scripts with sudo
sudo ./tor_proxy_setup.py --install
```

### 5. Tor Service Fails to Start

**Problem**: Tor service won't start or keeps crashing

**Fix**:
```bash
# Check Tor service logs
sudo journalctl -u tor

# Reinstall Tor
sudo apt purge tor
sudo apt autoremove
sudo apt install tor

# Check torrc configuration
sudo cat /etc/tor/torrc
```

### 6. IP Rotation Not Working

**Problem**: IP doesn't change when using rotation

**Fix**:
```bash
# Manually rotate IP
sudo python3 tor_proxy_setup.py --rotate

# Check if Tor control port is accessible
sudo netstat -tlnp | grep 9051

# Ensure control port is enabled in torrc
sudo grep "ControlPort" /etc/tor/torrc
```

### 7. Multiple Tor Instances Fail

**Problem**: Can't create multiple Tor instances

**Fix**:
```bash
# Verify system resources
free -m

# Kill existing instances and retry
sudo pkill -f "tor"
sudo python3 tor_proxy_setup.py --multi-tor 3
```

### 8. Firefox Proxy Configuration Issues

**Problem**: Firefox doesn't use Tor proxy

**Fix**:
```bash
# Manually configure Firefox proxy
# Settings → Network Settings → Manual proxy configuration
# SOCKS Host: 127.0.0.1, Port: 9050, SOCKS v5

# Or re-run the Firefox setup
sudo python3 tor_proxy_setup.py --setup-firefox
```

## Advanced Troubleshooting

### Check if Tor is properly connecting to the network

```bash
sudo -u debian-tor tor --verify-config
sudo cat /var/log/tor/log
```

### Test SOCKS proxy connection manually

```bash
curl --socks5 127.0.0.1:9050 https://check.torproject.org/
```

### Verify if proxychains is configured correctly

```bash
cat /etc/proxychains4.conf
# Should include: socks5 127.0.0.1 9050
```

### Memory issues with multiple instances

If running out of memory with multiple instances, try:

```bash
# Lower number of instances
sudo python3 tor_proxy_setup.py --multi-tor 2

# Or increase system swap
sudo fallocate -l 1G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

## Contact and Support

If you continue experiencing issues after trying these fixes, please file a detailed issue report including:

- Exact error messages
- Output of `sudo python3 tor_proxy_setup.py --verify`
- System information (`lsb_release -a`)
- Tor status (`systemctl status tor`)
