#!/bin/bash

# Master Test Script for All Hashing Algorithms
# Runs tests for SHA256, SHA512, BCrypt, SCrypt, and Argon2

echo "=========================================="
echo "Security Utils - Hash Algorithm Test Suite"
echo "=========================================="
echo

# Make all scripts executable
chmod +x "$(dirname "$0")/test_sha256.sh"
chmod +x "$(dirname "$0")/test_sha512.sh"
chmod +x "$(dirname "$0")/test_bcrypt.sh"
chmod +x "$(dirname "$0")/test_scrypt.sh"
chmod +x "$(dirname "$0")/test_argon2.sh"

# Test input parameters
echo "Standard Test Inputs:"
echo "Password: abc123"
echo "Q1: a"
echo "Q2: b"
echo "Q3: c"
echo "Iterations: 1"
echo
echo "=========================================="
echo

# Function to run a test with error handling
run_test() {
    local test_name="$1"
    local script_path="$2"
    
    echo ">>> Running $test_name Tests..."
    echo
    
    if [[ -f "$script_path" ]]; then
        if bash "$script_path"; then
            echo "✓ $test_name tests completed successfully"
        else
            echo "✗ $test_name tests failed or dependencies missing"
        fi
    else
        echo "✗ $test_name test script not found: $script_path"
    fi
    
    echo
    echo "------------------------------------------"
    echo
}

# Get the directory where this script is located
SCRIPT_DIR="$(dirname "$0")"

# Run all algorithm tests
run_test "SHA256" "$SCRIPT_DIR/test_sha256.sh"
run_test "SHA512" "$SCRIPT_DIR/test_sha512.sh"
run_test "BCrypt" "$SCRIPT_DIR/test_bcrypt.sh"
run_test "SCrypt" "$SCRIPT_DIR/test_scrypt.sh"
run_test "Argon2" "$SCRIPT_DIR/test_argon2.sh"

echo "=========================================="
echo "All Algorithm Tests Complete"
echo "=========================================="
echo
echo "Summary of Available Algorithms:"
echo
echo "1. SHA256 - Fast cryptographic hash function"
echo "   Use case: General-purpose hashing, not for passwords"
echo
echo "2. SHA512 - Stronger variant of SHA with longer output"
echo "   Use case: More secure general-purpose hashing"
echo
echo "3. BCrypt - Password hashing with adaptive cost"
echo "   Use case: Password storage, adjustable security"
echo
echo "4. SCrypt - Memory-hard key derivation function"
echo "   Use case: Password storage, ASIC-resistant"
echo
echo "5. Argon2 - Modern password hashing (PHC winner)"
echo "   Use case: State-of-the-art password storage"
echo
echo "Recommendations:"
echo "- For password storage: Use Argon2id > BCrypt > SCrypt"
echo "- For general hashing: Use SHA256/SHA512"
echo "- For legacy compatibility: Use BCrypt or SCrypt"
echo
echo "Note: Password hashing functions (BCrypt, SCrypt, Argon2)"
echo "      are designed to be slow and memory-intensive for security"