#!/bin/bash

# Installation script for hash algorithm dependencies
# Installs SCrypt and Argon2 tools

echo "================================================"
echo "Security Utils - Hash Algorithm Dependencies"
echo "Installation Script"
echo "================================================"
echo

# Check if running as root or with sudo
if [[ $EUID -ne 0 ]]; then
    echo "This script requires sudo privileges to install packages."
    echo "Please run with: sudo $0"
    echo
    echo "Alternatively, you can install manually:"
    echo "  sudo apt-get update"
    echo "  sudo apt-get install scrypt argon2"
    echo "  pip3 install scrypt argon2-cffi"
    exit 1
fi

# Update package lists
echo "Updating package lists..."
apt-get update

echo
echo "Installing command-line tools..."

# Install SCrypt
echo "Installing scrypt..."
if apt-get install -y scrypt; then
    echo "✓ scrypt installed successfully"
else
    echo "✗ Failed to install scrypt"
fi

# Install Argon2
echo "Installing argon2..."
if apt-get install -y argon2; then
    echo "✓ argon2 installed successfully"
else
    echo "✗ Failed to install argon2"
fi

echo
echo "Installing Python packages (optional)..."

# Check if pip3 is available
if command -v pip3 >/dev/null 2>&1; then
    echo "Installing Python scrypt module..."
    if pip3 install scrypt; then
        echo "✓ Python scrypt module installed"
    else
        echo "✗ Failed to install Python scrypt module"
    fi
    
    echo "Installing Python argon2-cffi module..."
    if pip3 install argon2-cffi; then
        echo "✓ Python argon2-cffi module installed"
    else
        echo "✗ Failed to install Python argon2-cffi module"
    fi
else
    echo "pip3 not found. Install Python packages manually:"
    echo "  pip3 install scrypt argon2-cffi"
fi

echo
echo "================================================"
echo "Installation Complete"
echo "================================================"
echo

# Test installations
echo "Testing installations..."
echo

if command -v scrypt >/dev/null 2>&1; then
    echo "✓ scrypt command available"
else
    echo "✗ scrypt command not available"
fi

if command -v argon2 >/dev/null 2>&1; then
    echo "✓ argon2 command available"
else
    echo "✗ argon2 command not available"
fi

if python3 -c "import scrypt" 2>/dev/null; then
    echo "✓ Python scrypt module available"
else
    echo "✗ Python scrypt module not available"
fi

if python3 -c "import argon2" 2>/dev/null; then
    echo "✓ Python argon2 module available"
else
    echo "✗ Python argon2 module not available"
fi

echo
echo "You can now run the full test suite:"
echo "  ./test_all_algorithms.sh"
echo
echo "Or test individual algorithms:"
echo "  ./test_scrypt.sh"
echo "  ./test_argon2.sh"