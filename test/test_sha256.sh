#!/bin/bash

# SHA256 Hash Generation Test Script
# Tests the generate_hash function specifically with SHA256 algorithm

source "$(dirname "$0")/generate_hash.sh"

echo "=== SHA256 Hash Generation Tests ==="
echo

# Test your specific example with SHA256
echo "Test: Your example with SHA256"
echo "Password: abc123, Q1: a, Q2: b, Q3: c, Iterations: 1"
result=$(generate_hash "abc123" "a" "b" "c" "1" "sha256")
echo "SHA256 Hash: $result"
echo

# Test with multiple iterations
echo "Test: Same inputs with 3 iterations"
result=$(generate_hash "abc123" "a" "b" "c" "3" "sha256")
echo "SHA256 Hash (3 iterations): $result"
echo

# Test with just password
echo "Test: Password only"
result=$(generate_hash "abc123" "" "" "" "1" "sha256")
echo "SHA256 Hash (password only): $result"
echo

# Test with just questions
echo "Test: Questions only"
result=$(generate_hash "" "a" "b" "c" "1" "sha256")
echo "SHA256 Hash (questions only): $result"
echo

# Test with single question
echo "Test: Single question with password"
result=$(generate_hash "abc123" "a" "" "" "1" "sha256")
echo "SHA256 Hash (single question): $result"
echo

# Test with different inputs
echo "Test: Different password and questions"
result=$(generate_hash "test123" "hello" "world" "security" "2" "sha256")
echo "SHA256 Hash (different inputs, 2 iterations): $result"
echo

echo "=== SHA256 Tests Complete ==="