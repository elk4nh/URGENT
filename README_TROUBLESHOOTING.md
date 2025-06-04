# Tor Proxy Manager - Troubleshooting Guide

## Common Issues and Solutions

### SyntaxError: f-string: invalid syntax

If you see an error like this:
```
File "/path/to/tor_proxy_setup.py", line 666
  ( { cat; echo '{crontab_entry}'; } | crontab -)
         ^
SyntaxError: f-string: invalid syntax
```

This is fixed in the current version. Make sure you're using the fixed version of the script.

### Missing 'socket' module error

If you see an error about the socket module:
```
NameError: name 'socket' is not defined
```

Run the fix_multi_sqlmap_runner.py script to add the missing import:
```bash
sudo python3 fix_multi_sqlmap_runner.py
```

### Tor not connecting or rotating IP

1. Try restarting the Tor service:
```bash
sudo systemctl restart tor
```

2. Fix DNS issues with the dns_fix.sh script:
```bash
sudo ./dns_fix.sh
```

3. Check Tor configuration:
```bash
sudo cat /etc/tor/torrc
```

Make sure ControlPort is enabled:
```
ControlPort 9051
```

### Permission denied errors

Run the fix_permissions.sh script:
```bash
sudo ./fix_permissions.sh
```

### Python module import errors

Install dependencies using the install_dependencies.sh script:
```bash
sudo ./install_dependencies.sh
```

### Multiple Tor instances fail to start

1. Check if your system has enough resources
2. Kill any existing Tor processes and try again:
```bash
sudo pkill -f "tor"
sudo python3 tor_proxy_setup.py --multi-tor 3
```

## Complete Setup Instructions

For a fresh installation, follow these steps in order:

1. Install dependencies:
```bash
sudo ./install_dependencies.sh
```

2. Fix permissions:
```bash
sudo ./fix_permissions.sh
```

3. Fix DNS if needed:
```bash
sudo ./dns_fix.sh
```

4. Run the setup script:
```bash
sudo ./setup.sh
```

## Checking Logs

Check Tor logs for errors:
```bash
sudo cat /var/log/tor/log
```

Check daemon rotation logs:
```bash
sudo cat /tmp/tor_rotation.log
```

## Need More Help?

If you're still experiencing issues, please provide detailed information about:

1. Your operating system and version
2. Full error messages
3. Output of `systemctl status tor`
4. Output of `python3 tor_proxy_setup.py --verify`
