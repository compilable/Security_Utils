#!/bin/bash

# Bash function to generate password hash following the same logic as the PHP/JS implementation
# Requires openssl for MD5 and HMAC operations

generate_hash() {
    local password="$1"
    local q1="$2"
    local q2="$3"
    local q3="$4"
    local iterations="$5"
    local algorithm="$6"
    
    # Validate inputs
    if [[ -z "$iterations" ]] || [[ "$iterations" -lt 1 ]] || [[ "$iterations" -gt 10 ]]; then
        echo "Error: Invalid iteration count (must be 1-10)" >&2
        return 1
    fi
    
    # Normalize algorithm to lowercase
    algorithm=$(echo "$algorithm" | tr '[:upper:]' '[:lower:]')
    
    # Check if algorithm is supported
    case "$algorithm" in
        "md5"|"sha1"|"sha256"|"sha512")
            ;;
        *)
            echo "Error: Unsupported algorithm: $algorithm" >&2
            echo "Supported: md5, sha1, sha256, sha512" >&2
            return 1
            ;;
    esac
    
    local question_hashes=()
    local questions=()
    
    # Collect non-empty questions
    [[ -n "$q1" ]] && questions+=("$q1")
    [[ -n "$q2" ]] && questions+=("$q2")
    [[ -n "$q3" ]] && questions+=("$q3")
    
    # Generate hash for each question with iterations
    for question in "${questions[@]}"; do
        local question_hash="$question"
        
        # Apply iterations
        for ((i=0; i<iterations; i++)); do
            question_hash=$(echo -n "$question_hash" | openssl dgst -$algorithm -binary | xxd -p -c 256)
        done
        
        question_hashes+=("$question_hash")
    done
    
    local final_password_list=()
    
    # If we have questions, process them
    if [[ ${#question_hashes[@]} -gt 0 ]]; then
        local combined_question_hash=""
        
        if [[ ${#question_hashes[@]} -eq 1 ]]; then
            # Single question - use its hash directly
            combined_question_hash="${question_hashes[0]}"
        else
            # Multiple questions - join hashes and hash the result
            local joined_hashes=""
            for hash in "${question_hashes[@]}"; do
                joined_hashes="$joined_hashes$hash"
            done
            combined_question_hash=$(echo -n "$joined_hashes" | openssl dgst -$algorithm -binary | xxd -p -c 256)
        fi
        
        final_password_list+=("$combined_question_hash")
    fi
    
    # Check if we have any input to work with
    if [[ ${#final_password_list[@]} -eq 0 ]] && [[ -z "$password" ]]; then
        echo "Error: At least one input is required: password, or security questions" >&2
        return 1
    fi
    
    # If no questions provided but password exists, use the password itself as input
    if [[ ${#final_password_list[@]} -eq 0 ]] && [[ -n "$password" ]]; then
        final_password_list+=("$password")
    fi
    
    local final_hash
    
    # Use password as HMAC key if provided, otherwise just combine the hashes
    if [[ -n "$password" ]]; then
        # Join all password list elements
        local combined_input=""
        for item in "${final_password_list[@]}"; do
            combined_input="$combined_input$item"
        done
        
        # Generate HMAC
        final_hash=$(echo -n "$combined_input" | openssl dgst -$algorithm -hmac "$password" -binary | xxd -p -c 256)
    else
        # If no password provided, just hash the combined inputs
        local combined_input=""
        for item in "${final_password_list[@]}"; do
            combined_input="$combined_input$item"
        done
        final_hash=$(echo -n "$combined_input" | openssl dgst -$algorithm -binary | xxd -p -c 256)
    fi
    
    echo "$final_hash"
}

# Example usage function for your specific inputs
generate_example_hash() {
    echo "Generating hash for the specified inputs:"
    echo "Password: abc123"
    echo "Q1: a"
    echo "Q2: b"
    echo "Q3: c"
    echo "Iterations: 1"
    echo "Algorithm: MD5"
    echo
    
    local result=$(generate_hash "abc123" "a" "b" "c" "1" "md5")
    if [[ $? -eq 0 ]]; then
        echo "Generated hash: $result"
    else
        echo "Error generating hash"
        return 1
    fi
}

# Function to test with different combinations
test_hash_generation() {
    echo "=== Testing Hash Generation ==="
    echo
    
    # Test 1: Your specific example
    echo "Test 1: Full example with password and 3 questions"
    generate_hash "abc123" "a" "b" "c" "1" "md5"
    echo
    
    # Test 2: Just password
    echo "Test 2: Just password, no questions"
    generate_hash "abc123" "" "" "" "1" "md5"
    echo
    
    # Test 3: Just questions, no password
    echo "Test 3: Just questions, no password"
    generate_hash "" "a" "b" "c" "1" "md5"
    echo
    
    # Test 4: Single question with password
    echo "Test 4: Single question with password"
    generate_hash "abc123" "a" "" "" "1" "md5"
    echo
    
    # Test 5: Different algorithm
    echo "Test 5: Same inputs with SHA256"
    generate_hash "abc123" "a" "b" "c" "1" "sha256"
    echo
    
    # Test 6: Multiple iterations
    echo "Test 6: Same inputs with 3 iterations"
    generate_hash "abc123" "a" "b" "c" "3" "md5"
    echo
}

# If script is run directly (not sourced), run the example
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    generate_example_hash
    echo
    echo "To run additional tests, call: test_hash_generation"
    echo "To use the function with custom inputs, call: generate_hash <password> <q1> <q2> <q3> <iterations> <algorithm>"
fi