#!/bin/bash
#!/bin/bash

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

echo "[*] Installing system dependencies..."

# Update package lists
apt update

# Install core system packages
apt install -y \
    tor \
    proxychains4 \
    sqlmap \
    curl \
    python3 \
    python3-pip \
    python3-venv \
    firefox-esr \
    torsocks \
    netcat-openbsd

# Install Python dependencies if requirements.txt exists
if [ -f "requirements.txt" ]; then
    echo "[*] Installing Python dependencies from requirements.txt..."
    pip3 install -r requirements.txt
else
    echo "[*] Installing Python dependencies individually..."
    pip3 install requests psutil bs4 lxml pyfiglet colorama argparse python-dotenv dnspython
    pip3 install termcolor progress selenium webdriver-manager
fi

# Fix multi_sqlmap_runner.py if it exists
if [ -f "fix_multi_sqlmap_runner.py" ]; then
    echo "[*] Fixing multi_sqlmap_runner.py..."
    python3 fix_multi_sqlmap_runner.py
fi

# Make scripts executable
chmod +x *.py *.sh

# Check Tor installation
if ! command -v tor &> /dev/null; then
    echo "[!] Error: Tor installation failed"
    exit 1
fi

# Check proxychains4 installation
if ! command -v proxychains4 &> /dev/null; then
    echo "[!] Error: proxychains4 installation failed"
    exit 1
fi

# Check sqlmap installation
if ! command -v sqlmap &> /dev/null; then
    echo "[!] Error: sqlmap installation failed"
    exit 1
fi

echo "[+] All dependencies installed successfully!"
echo "[*] You can now run the setup script: sudo ./setup.sh"
# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

echo "[*] Installing system dependencies..."

# Update package lists
apt update

# Install core system packages
apt install -y \
    tor \
    proxychains4 \
    sqlmap \
    curl \
    python3 \
    python3-pip \
    python3-venv \
    firefox-esr \
    torsocks \
    netcat-openbsd

# Install Python dependencies
pip3 install -r requirements.txt

# Check Tor installation
if ! command -v tor &> /dev/null; then
    echo "[!] Error: Tor installation failed"
    exit 1
fi

# Check proxychains4 installation
if ! command -v proxychains4 &> /dev/null; then
    echo "[!] Error: proxychains4 installation failed"
    exit 1
fi

# Check sqlmap installation
if ! command -v sqlmap &> /dev/null; then
    echo "[!] Error: sqlmap installation failed"
    exit 1
fi

echo "[+] All system dependencies installed successfully!"
echo "[*] You can now run the setup script: sudo ./setup.sh"
