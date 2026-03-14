#!/bin/bash

# SHA512 Hash Generation Test Script
# Tests the generate_hash function specifically with SHA512 algorithm

source "$(dirname "$0")/generate_hash.sh"

echo "=== SHA512 Hash Generation Tests ==="
echo

# Test your specific example with SHA512
echo "Test: Your example with SHA512"
echo "Password: abc123, Q1: a, Q2: b, Q3: c, Iterations: 1"
result=$(generate_hash "abc123" "a" "b" "c" "1" "sha512")
echo "SHA512 Hash: $result"
echo

# Test with multiple iterations
echo "Test: Same inputs with 5 iterations"
result=$(generate_hash "abc123" "a" "b" "c" "5" "sha512")
echo "SHA512 Hash (5 iterations): $result"
echo

# Test with just password
echo "Test: Password only"
result=$(generate_hash "abc123" "" "" "" "1" "sha512")
echo "SHA512 Hash (password only): $result"
echo

# Test with just questions
echo "Test: Questions only"
result=$(generate_hash "" "a" "b" "c" "1" "sha512")
echo "SHA512 Hash (questions only): $result"
echo

# Test with single question
echo "Test: Single question with password"
result=$(generate_hash "abc123" "a" "" "" "1" "sha512")
echo "SHA512 Hash (single question): $result"
echo

# Test with complex inputs
echo "Test: Complex password and questions"
result=$(generate_hash "MyS3cur3P@ssw0rd!" "What is your favorite color?" "Where were you born?" "What is your pet's name?" "3" "sha512")
echo "SHA512 Hash (complex inputs, 3 iterations): $result"
echo

echo "=== SHA512 Tests Complete ==="