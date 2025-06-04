#!/usr/bin/env python3

# This script fixes the missing socket import in multi_sqlmap_runner.py
import os
import sys

# Check if multi_sqlmap_runner.py exists
if not os.path.exists('multi_sqlmap_runner.py'):
    print("Error: multi_sqlmap_runner.py not found in the current directory")
    sys.exit(1)

# Read the file
with open('multi_sqlmap_runner.py', 'r') as f:
    content = f.read()

# Check if socket is already imported
if 'import socket' not in content:
    # Add socket import after other imports
    if 'import random' in content:
        content = content.replace('import random', 'import random\nimport socket')
    else:
        # If random import not found, add after datetime import
        content = content.replace('from datetime import datetime', 'from datetime import datetime\nimport socket')

    # Write the updated content back to the file
    with open('multi_sqlmap_runner.py', 'w') as f:
        f.write(content)

    print("[+] Added missing socket import to multi_sqlmap_runner.py")
else:
    print("[*] socket already imported in multi_sqlmap_runner.py")

print("[+] Fix completed. You can now run multi_sqlmap_runner.py")
