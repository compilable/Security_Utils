#!/bin/bash

# Argon2 Hash Generation Test Script  
# Argon2 is the winner of the Password Hashing Competition (PHC)

# Check if Argon2 is available
check_argon2_availability() {
    if command -v argon2 >/dev/null 2>&1; then
        echo "Argon2 available via argon2 command"
        return 0
    elif command -v python3 >/dev/null 2>&1 && python3 -c "import argon2" 2>/dev/null; then
        echo "Argon2 available via Python argon2-cffi module"
        return 0
    elif command -v node >/dev/null 2>&1 && node -e "require('argon2')" 2>/dev/null; then
        echo "Argon2 available via Node.js argon2 module"
        return 0
    elif command -v php >/dev/null 2>&1 && php -m 2>/dev/null | grep -q sodium; then
        echo "Argon2 available via PHP sodium extension"
        return 0
    fi
    
    echo "Argon2 not available. Install via:"
    echo "  - Command line: sudo apt-get install argon2"
    echo "  - Python: pip3 install argon2-cffi"
    echo "  - Node.js: npm install argon2"
    echo "  - PHP: Install sodium extension"
    return 1
}

# Generate Argon2 hash using available method
generate_argon2_hash() {
    local input="$1"
    local salt="${2:-$(openssl rand -hex 16)}"
    local variant="${3:-argon2id}"  # argon2i, argon2d, or argon2id
    local memory="${4:-65536}"      # Memory usage in KB
    local time="${5:-3}"            # Time cost (iterations)
    local parallelism="${6:-1}"     # Parallelism factor
    local hash_length="${7:-32}"    # Output hash length
    
    if command -v python3 >/dev/null 2>&1 && python3 -c "import argon2" 2>/dev/null; then
        # Use Python argon2-cffi
        python3 -c "
import argon2
import binascii
import sys

password = sys.argv[1].encode('utf-8')
salt = bytes.fromhex(sys.argv[2])
variant = sys.argv[3]
memory_cost = int(sys.argv[4])
time_cost = int(sys.argv[5])
parallelism = int(sys.argv[6])
hash_length = int(sys.argv[7])

if variant == 'argon2i':
    hasher = argon2.PasswordHasher(memory_cost=memory_cost, time_cost=time_cost, parallelism=parallelism, hash_len=hash_length, type=argon2.Type.I)
elif variant == 'argon2d':
    hasher = argon2.PasswordHasher(memory_cost=memory_cost, time_cost=time_cost, parallelism=parallelism, hash_len=hash_length, type=argon2.Type.D)  
else:  # argon2id
    hasher = argon2.PasswordHasher(memory_cost=memory_cost, time_cost=time_cost, parallelism=parallelism, hash_len=hash_length, type=argon2.Type.ID)

# Generate hash
hash_result = hasher.hash(password, salt=salt)
print(hash_result)
" "$input" "$salt" "$variant" "$memory" "$time" "$parallelism" "$hash_length"
    elif command -v argon2 >/dev/null 2>&1; then
        # Use argon2 command line tool
        local variant_flag=""
        case "$variant" in
            "argon2i") variant_flag="-i" ;;
            "argon2d") variant_flag="-d" ;;
            "argon2id") variant_flag="-id" ;;
            *) variant_flag="-id" ;;
        esac
        
        # Create temporary salt file
        local salt_file=$(mktemp)
        echo -n "$salt" | xxd -r -p > "$salt_file"
        
        local result=$(echo -n "$input" | argon2 "$salt_file" -t "$time" -m "$memory" -p "$parallelism" -l "$hash_length" $variant_flag -r)
        rm -f "$salt_file"
        echo "$result"
    elif command -v php >/dev/null 2>&1 && php -m 2>/dev/null | grep -q sodium; then
        # Use PHP sodium extension
        php -r "
\$password = \$argv[1];
\$salt = hex2bin(\$argv[2]);
\$memory = (int)\$argv[4] * 1024; // Convert KB to bytes
\$time = (int)\$argv[5];
\$threads = (int)\$argv[6];
\$length = (int)\$argv[7];

// PHP sodium only supports Argon2ID
if (function_exists('sodium_crypto_pwhash')) {
    \$hash = sodium_crypto_pwhash(\$length, \$password, \$salt, \$time, \$memory, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID);
    echo bin2hex(\$hash);
} else {
    echo 'Error: sodium_crypto_pwhash not available';
}
" "$input" "$salt" "$variant" "$memory" "$time" "$parallelism" "$hash_length"
    else
        echo "Error: No Argon2 implementation available"
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

# Main Argon2 test function
test_argon2() {
    local password="$1"
    local q1="$2"
    local q2="$3"
    local q3="$4"
    local iterations="${5:-1}"
    local variant="${6:-argon2id}"
    local memory="${7:-65536}"
    local time="${8:-3}"
    local parallelism="${9:-1}"
    
    echo "Testing Argon2 with parameters:"
    echo "  Variant: $variant"
    echo "  Memory: ${memory} KB"
    echo "  Time cost: $time"
    echo "  Parallelism: $parallelism"
    echo "Password: $password"
    echo "Questions: Q1='$q1', Q2='$q2', Q3='$q3'"
    echo "Iterations: $iterations"
    echo
    
    # Generate a consistent salt for testing (normally this should be random)
    local test_salt="0123456789abcdef0123456789abcdef"
    
    # Process questions to get combined hash
    local question_hash=$(process_questions "$q1" "$q2" "$q3" "$iterations")
    
    # Determine what to hash with Argon2
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
    
    echo "Argon2 input length: ${#input_to_hash} characters"
    echo "Using salt: $test_salt"
    
    # Generate Argon2 hash
    local argon2_hash=$(generate_argon2_hash "$input_to_hash" "$test_salt" "$variant" "$memory" "$time" "$parallelism" "32")
    
    if [[ $? -eq 0 ]]; then
        echo "Argon2 Hash: $argon2_hash"
        echo "Hash length: ${#argon2_hash} characters"
    else
        echo "Error generating Argon2 hash"
        return 1
    fi
}

echo "=== Argon2 Hash Generation Tests ==="
echo

# Check availability
check_argon2_availability
if [[ $? -ne 0 ]]; then
    exit 1
fi
echo

# Test 1: Your specific example with Argon2id (recommended)
echo "Test 1: Your example inputs (Argon2id, default params)"
test_argon2 "abc123" "a" "b" "c" "1" "argon2id"
echo

# Test 2: Lower memory usage for faster testing
echo "Test 2: Your example inputs (Argon2id, lower memory: 4MB)"
test_argon2 "abc123" "a" "b" "c" "1" "argon2id" "4096"
echo

# Test 3: Just password
echo "Test 3: Password only (Argon2id, 4MB)"
test_argon2 "abc123" "" "" "" "1" "argon2id" "4096"
echo

# Test 4: Just questions
echo "Test 4: Questions only (Argon2id, 4MB)"
test_argon2 "" "a" "b" "c" "1" "argon2id" "4096"
echo

# Test 5: Single question
echo "Test 5: Single question with password (Argon2id, 4MB)"
test_argon2 "abc123" "a" "" "" "1" "argon2id" "4096"
echo

# Test 6: Multiple iterations
echo "Test 6: Multiple iterations (Argon2id, 4MB)"
test_argon2 "abc123" "a" "b" "c" "3" "argon2id" "4096"
echo

# Test 7: Argon2i variant (data-independent)
echo "Test 7: Argon2i variant (data-independent, 4MB)"
test_argon2 "abc123" "a" "b" "c" "1" "argon2i" "4096"
echo

# Test 8: Higher security parameters
echo "Test 8: Higher security (Argon2id, 32MB, time=5) - may take longer"
test_argon2 "abc123" "a" "b" "c" "1" "argon2id" "32768" "5"
echo

echo "=== Argon2 Tests Complete ==="
echo
echo "Argon2 Variants:"  
echo "  - Argon2i: Data-independent, resistant to side-channel attacks"
echo "  - Argon2d: Data-dependent, resistant to time-memory trade-offs"
echo "  - Argon2id: Hybrid, recommended for general use"
echo
echo "Note: Higher memory and time costs provide better security"
echo "      but require more computational resources"