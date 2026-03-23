#!/bin/bash

# SCrypt Hash Generation Test Script
# SCrypt is a key derivation function designed to be memory-hard

# Check if scrypt is available
check_scrypt_availability() {
    if command -v scrypt >/dev/null 2>&1; then
        echo "SCrypt available via scrypt command"
        return 0
    elif command -v python3 >/dev/null 2>&1 && python3 -c "import scrypt" 2>/dev/null; then
        echo "SCrypt available via Python scrypt module"
        return 0
    elif command -v node >/dev/null 2>&1 && node -e "require('scrypt')" 2>/dev/null; then
        echo "SCrypt available via Node.js scrypt module"
        return 0
    elif command -v openssl >/dev/null 2>&1 && openssl version | grep -q "1\.[1-9]\|[2-9]\."; then
        # Check if OpenSSL supports scrypt (version 1.1.0+)
        if openssl list -kdf 2>/dev/null | grep -qi scrypt; then
            echo "SCrypt available via OpenSSL KDF"
            return 0
        fi
    fi
    
    echo "SCrypt not available. Install via:"
    echo "  - Command line: sudo apt-get install scrypt"
    echo "  - Python: pip3 install scrypt"
    echo "  - Node.js: npm install scrypt"
    echo "  - Or use OpenSSL 1.1.0+"
    return 1
}

# Generate SCrypt hash using available method
generate_scrypt_hash() {
    local input="$1"
    local salt="${2:-$(openssl rand -hex 16)}"
    local N="${3:-16384}"    # CPU/memory cost parameter
    local r="${4:-8}"        # Block size parameter  
    local p="${5:-1}"        # Parallelization parameter
    local dklen="${6:-32}"   # Derived key length
    
    if command -v python3 >/dev/null 2>&1 && python3 -c "import scrypt" 2>/dev/null; then
        # Use Python scrypt
        python3 -c "
import scrypt
import binascii
import sys
password = sys.argv[1].encode('utf-8')
salt = bytes.fromhex(sys.argv[2])
N, r, p, dklen = int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])
hash_result = scrypt.hash(password, salt, N, r, p, dklen)
# Return salt + hash in hex format
print(sys.argv[2] + binascii.hexlify(hash_result).decode())
" "$input" "$salt" "$N" "$r" "$p" "$dklen"
    elif command -v openssl >/dev/null 2>&1 && openssl list -kdf 2>/dev/null | grep -qi scrypt; then
        # Use OpenSSL scrypt KDF
        local salt_bytes=$(echo -n "$salt" | xxd -r -p | base64 -w 0)
        local result=$(echo -n "$input" | openssl kdf -keylen $dklen -kdfopt digest:SHA256 -kdfopt pass:stdin -kdfopt salt:"$salt_bytes" -kdfopt N:$N -kdfopt r:$r -kdfopt p:$p SCRYPT | xxd -p -c 256)
        echo "${salt}${result}"
    elif command -v scrypt >/dev/null 2>&1; then
        # Use scrypt command (format may vary)
        local temp_input=$(mktemp)
        local temp_output=$(mktemp)
        echo -n "$input" > "$temp_input"
        scrypt enc -P "$temp_input" "$temp_output" 2>/dev/null
        if [[ -f "$temp_output" ]]; then
            xxd -p -c 256 "$temp_output" | tr -d '\n'
            rm -f "$temp_input" "$temp_output"
        else
            rm -f "$temp_input" "$temp_output"
            echo "Error: scrypt command failed"
            return 1
        fi
    else
        echo "Error: No SCrypt implementation available"
        return 1
    fi
}

# Combine questions like the original function
process_questions() {
    local q1="$1"
    local q2="$2"
    local q3="$3"
    local iterations="$4"
    
    local questions=()
    [[ -n "$q1" ]] && questions+=("$q1")
    [[ -n "$q2" ]] && questions+=("$q2")
    [[ -n "$q3" ]] && questions+=("$q3")
    
    if [[ ${#questions[@]} -eq 0 ]]; then
        echo ""
        return
    fi
    
    # Hash each question individually first with MD5 (to match original logic)
    local question_hashes=()
    for question in "${questions[@]}"; do
        local question_hash="$question"
        for ((i=0; i<iterations; i++)); do
            question_hash=$(echo -n "$question_hash" | openssl dgst -md5 -binary | xxd -p -c 256)
        done
        question_hashes+=("$question_hash")
    done
    
    # Combine question hashes
    if [[ ${#question_hashes[@]} -eq 1 ]]; then
        echo "${question_hashes[0]}"
    else
        local joined_hashes=""
        for hash in "${question_hashes[@]}"; do
            joined_hashes="$joined_hashes$hash"
        done
        echo -n "$joined_hashes" | openssl dgst -md5 -binary | xxd -p -c 256
    fi
}

# Main SCrypt test function
test_scrypt() {
    local password="$1"
    local q1="$2"
    local q2="$3"
    local q3="$4"
    local iterations="${5:-1}"
    local N="${6:-16384}"
    local r="${7:-8}"
    local p="${8:-1}"
    
    echo "Testing SCrypt with parameters: N=$N, r=$r, p=$p"
    echo "Password: $password"
    echo "Questions: Q1='$q1', Q2='$q2', Q3='$q3'"
    echo "Iterations: $iterations"
    echo
    
    # Generate a consistent salt for testing (normally this should be random)
    local test_salt="0123456789abcdef0123456789abcdef"
    
    # Process questions to get combined hash
    local question_hash=$(process_questions "$q1" "$q2" "$q3" "$iterations")
    
    # Determine what to hash with SCrypt
    local input_to_hash=""
    
    if [[ -n "$question_hash" ]] && [[ -n "$password" ]]; then
        # Combine password and question hash
        input_to_hash="${password}${question_hash}"
        echo "Input type: Password + Question Hash"
    elif [[ -n "$password" ]]; then
        input_to_hash="$password"
        echo "Input type: Password only"
    elif [[ -n "$question_hash" ]]; then
        input_to_hash="$question_hash"
        echo "Input type: Question hash only"
    else
        echo "Error: No input provided"
        return 1
    fi
    
    echo "SCrypt input length: ${#input_to_hash} characters"
    echo "Using salt: $test_salt"
    
    # Generate SCrypt hash
    local scrypt_hash=$(generate_scrypt_hash "$input_to_hash" "$test_salt" "$N" "$r" "$p" "32")
    
    if [[ $? -eq 0 ]]; then
        echo "SCrypt Hash: $scrypt_hash"
        echo "Hash length: ${#scrypt_hash} characters"
        echo "Format: [salt][hash] where salt=${test_salt}"
    else
        echo "Error generating SCrypt hash"
        return 1
    fi
}

echo "=== SCrypt Hash Generation Tests ==="
echo

# Check availability
check_scrypt_availability
if [[ $? -ne 0 ]]; then
    exit 1
fi
echo

# Test 1: Your specific example with default parameters
echo "Test 1: Your example inputs (default params: N=16384, r=8, p=1)"
test_scrypt "abc123" "a" "b" "c" "1"
echo

# Test 2: Lower memory usage for faster testing
echo "Test 2: Your example inputs (lower memory: N=1024, r=8, p=1)"
test_scrypt "abc123" "a" "b" "c" "1" "1024"
echo

# Test 3: Just password
echo "Test 3: Password only (N=1024)"
test_scrypt "abc123" "" "" "" "1" "1024"
echo

# Test 4: Just questions
echo "Test 4: Questions only (N=1024)"
test_scrypt "" "a" "b" "c" "1" "1024"
echo

# Test 5: Single question
echo "Test 5: Single question with password (N=1024)"
test_scrypt "abc123" "a" "" "" "1" "1024"
echo

# Test 6: Multiple iterations
echo "Test 6: Multiple iterations (N=1024)"
test_scrypt "abc123" "a" "b" "c" "3" "1024"
echo

# Test 7: Higher security parameters
echo "Test 7: Higher security (N=65536, r=8, p=1) - may take longer"
test_scrypt "abc123" "a" "b" "c" "1" "65536"
echo

echo "=== SCrypt Tests Complete ==="
echo
echo "Note: SCrypt is designed to be memory-hard and CPU-intensive"
echo "Higher N values provide better security but require more time and memory"