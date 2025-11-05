#!/bin/bash

# We must be root/sudo to write to /usr/local/bin
if [ "$EUID" -ne 0 ]; then
  echo "[!] This script must be run with sudo or as root."
  exit 1
fi

# 1. Get the full, absolute path to the project directory
CURRENT_DIR=$(pwd)

# 2. Get the full path to your main script
SCRIPT_PATH="$CURRENT_DIR/scanner.py"

# 3. Check if the script exists
if [ ! -f "$SCRIPT_PATH" ]; then
    echo "[!] ERROR: scanner.py not found in $CURRENT_DIR"
    echo "Please run this script from the root of the 'FIAS' project directory."
    exit 1
fi

# 4. Create the symbolic link in /usr/local/bin
# This is the "shortcut" that makes 'FIAS' a global command
echo "[*] Creating system-wide symlink..."
ln -sf "$SCRIPT_PATH" /usr/local/bin/FIAS

# 5. Verify the link
if [ -L /usr/local/bin/FIAS ]; then
    echo "[+] Success! The 'FIAS' command is now installed."
    echo "Please open a NEW terminal, or type 'hash -r', to start using it."
else
    echo "[!] ERROR: Failed to create symlink."
    exit 1
fi

exit 0
