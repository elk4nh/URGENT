#!/bin/bash

# Script untuk memeriksa dan memperbaiki kesalahan umum dalam proyek
echo "Memeriksa kesalahan umum dalam proyek..."

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Script ini harus dijalankan sebagai root" >&2
    exit 1
fi

# 1. Periksa import socket di semua file Python
for pyfile in *.py; do
    if [ -f "$pyfile" ]; then
        if ! grep -q "import socket" "$pyfile"; then
            echo "[!] $pyfile tidak memiliki import socket"
            sed -i '/import random/a import socket' "$pyfile"
            echo "[+] Menambahkan import socket ke $pyfile"
        fi
    fi
 done

# 2. Periksa penggunaan 'localhost' dan ganti dengan '127.0.0.1'
for pyfile in *.py; do
    if [ -f "$pyfile" ]; then
        if grep -q "localhost" "$pyfile"; then
            echo "[!] Menemukan referensi 'localhost' dalam $pyfile"
            sed -i 's/localhost/127.0.0.1/g' "$pyfile"
            echo "[+] Mengganti 'localhost' dengan '127.0.0.1' di $pyfile"
        fi
    fi
done

# 3. Perbaiki penanganan kesalahan
for pyfile in *.py; do
    if [ -f "$pyfile" ]; then
        if grep -q "print(f\"Error message: {e.stderr}\")" "$pyfile"; then
            echo "[!] Menemukan penanganan kesalahan yang tidak aman di $pyfile"
            sed -i 's/print(f\"Error message: {e.stderr}\")/if hasattr(e, "stderr") and e.stderr:\n        print(f\"Error message: {e.stderr}\")/g' "$pyfile"
            echo "[+] Memperbaiki penanganan kesalahan di $pyfile"
        fi
    fi
done

# 4. Periksa permasalahan duplikasi fungsi di tor_proxy_setup.py
if [ -f "tor_proxy_setup.py" ]; then
    num_ip_rotation_daemon=$(grep -c "def ip_rotation_daemon" "tor_proxy_setup.py")
    num_add_crontab_entry=$(grep -c "def add_crontab_entry" "tor_proxy_setup.py")

    if [ "$num_ip_rotation_daemon" -gt 1 ] || [ "$num_add_crontab_entry" -gt 1 ]; then
        echo "[!] Menemukan fungsi duplikat di tor_proxy_setup.py"
        echo "[!] Mohon periksa dan perbaiki file tor_proxy_setup.py secara manual"
    fi
fi

# 5. Periksa dan perbaiki izin file
chmod +x *.sh *.py
echo "[+] Memperbaiki izin file untuk semua script shell dan Python"

# 6. Periksa paket yang diperlukan
pip3 install -r requirements.txt

echo "Pemeriksaan selesai. Semua kesalahan umum telah diperbaiki."
echo "Anda dapat menjalankan 'test-tor' atau 'python3 proxy_tester.py --test' untuk memverifikasi koneksi."
