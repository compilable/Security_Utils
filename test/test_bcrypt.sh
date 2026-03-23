#!/bin/bash

# BCrypt Hash Generation Test Script
# BCrypt is a password hashing function with built-in salt and cost factor

# Check if bcrypt is available (via htpasswd, python, or dedicated bcrypt tool)
check_bcrypt_availability() {
    if command -v htpasswd >/dev/null 2>&1; then
        echo "BCrypt available via htpasswd"
        return 0
    elif command -v python3 >/dev/null 2>&1 && python3 -c "import bcrypt" 2>/dev/null; then
        echo "BCrypt available via Python bcrypt module"
        return 0
    elif command -v bcrypt >/dev/null 2>&1; then
        echo "BCrypt available via bcrypt command"
        return 0
    else
        echo "BCrypt not available. Install via:"
        echo "  - Apache utils: sudo apt-get install apache2-utils"
        echo "  - Python bcrypt: pip3 install bcrypt"
        echo "  - BCrypt command: sudo apt-get install bcrypt"
        return 1
    fi
}

# Generate BCrypt hash using available method
generate_bcrypt_hash() {
    local input="$1"
    local cost="${2:-12}"  # Default cost of 12
    
    if command -v python3 >/dev/null 2>&1 && python3 -c "import bcrypt" 2>/dev/null; then
        # Use Python bcrypt
        python3 -c "
import bcrypt
import sys
password = sys.argv[1].encode('utf-8')
cost = int(sys.argv[2])
hashed = bcrypt.hashpw(password, bcrypt.gensalt(rounds=cost))
print(hashed.decode('utf-8'))
" "$input" "$cost"
    elif command -v htpasswd >/dev/null 2>&1; then
        # Use htpasswd (Apache utils)
        htpasswd -nbB "" "$input" | cut -d: -f2
    elif command -v bcrypt >/dev/null 2>&1; then
        # Use bcrypt command
        echo -n "$input" | bcrypt -c "$cost"
    else
        echo "Error: No BCrypt implementation available"
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

# Main BCrypt test function
test_bcrypt() {
    local password="$1"
    local q1="$2"
    local q2="$3"
    local q3="$4"
    local iterations="${5:-1}"
    local cost="${6:-12}"
    
    echo "Testing BCrypt with cost factor: $cost"
    echo "Password: $password"
    echo "Questions: Q1='$q1', Q2='$q2', Q3='$q3'"
    echo "Iterations: $iterations"
    echo
    
    # Process questions to get combined hash
    local question_hash=$(process_questions "$q1" "$q2" "$q3" "$iterations")
    
    # Determine what to hash with BCrypt
    local input_to_hash=""
    
    if [[ -n "$question_hash" ]] && [[ -n "$password" ]]; then
        # Combine password and question hash (mimicking HMAC approach)
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
    
    echo "BCrypt input length: ${#input_to_hash} characters"
    
    # Generate BCrypt hash
    local bcrypt_hash=$(generate_bcrypt_hash "$input_to_hash" "$cost")
    
    if [[ $? -eq 0 ]]; then
        echo "BCrypt Hash: $bcrypt_hash"
        echo "Hash length: ${#bcrypt_hash} characters"
    else
        echo "Error generating BCrypt hash"
        return 1
    fi
}

echo "=== BCrypt Hash Generation Tests ==="
echo

# Check availability
check_bcrypt_availability
if [[ $? -ne 0 ]]; then
    exit 1
fi
echo

# Test 1: Your specific example
echo "Test 1: Your example inputs (cost=12)"
test_bcrypt "abc123" "a" "b" "c" "1" "12"
echo

# Test 2: Lower cost for faster testing
echo "Test 2: Your example inputs (cost=8 - faster)"
test_bcrypt "abc123" "a" "b" "c" "1" "8"
echo

# Test 3: Just password
echo "Test 3: Password only (cost=10)"
test_bcrypt "abc123" "" "" "" "1" "10"
echo

# Test 4: Just questions
echo "Test 4: Questions only (cost=10)"
test_bcrypt "" "a" "b" "c" "1" "10"
echo

# Test 5: Single question
echo "Test 5: Single question with password (cost=10)"
test_bcrypt "abc123" "a" "" "" "1" "10"
echo

# Test 6: Multiple iterations
echo "Test 6: Multiple iterations (cost=8)"
test_bcrypt "abc123" "a" "b" "c" "3" "8"
echo

echo "=== BCrypt Tests Complete ==="
echo
echo "Note: BCrypt hashes will be different each time due to random salt generation"
echo "This is the intended security behavior of BCrypt"