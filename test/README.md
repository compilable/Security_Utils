# Hash Algorithm Test Scripts

This directory contains bash scripts to test various hash algorithms with the same inputs as your Security Utils password hash generator.

## Available Test Scripts

### Core Algorithms (Available)
- ✅ **`test_sha256.sh`** - SHA256 hash testing
- ✅ **`test_sha512.sh`** - SHA512 hash testing  
- ✅ **`test_bcrypt.sh`** - BCrypt password hashing testing

### Advanced Algorithms (Require Installation)
- 📦 **`test_scrypt.sh`** - SCrypt key derivation testing
- 📦 **`test_argon2.sh`** - Argon2 password hashing testing

### Utility Scripts
- 🚀 **`test_all_algorithms.sh`** - Run all algorithm tests
- 🔧 **`install_dependencies.sh`** - Install missing dependencies
- 📖 **`generate_hash.sh`** - Core hash generation function

## Quick Start

### Test Available Algorithms
```bash
# Test all available algorithms
./test_all_algorithms.sh

# Test specific algorithms
./test_sha256.sh
./test_sha512.sh
./test_bcrypt.sh
```

### Install Missing Dependencies
```bash
# Install SCrypt and Argon2 (requires sudo)
sudo ./install_dependencies.sh
```

### Test Your Specific Example
All scripts test these default inputs:
- **Password:** `abc123`
- **Q1:** `a`
- **Q2:** `b`
- **Q3:** `c`
- **Iterations:** `1`

## Expected Results for Your Example

| Algorithm | Expected Hash |
|-----------|---------------|
| **MD5** | `90ba9bccf3e05cf30efd404244e0226a` |
| **SHA256** | `16b95890b2e175928c4e348c0aaea3d6d43b8c2957142a26f89a8695a09a2211` |
| **SHA512** | `8a49c69584dd910ec45842751bed6f7f1688898598fe554c72383866cb04c0bd2bf8a9a1042ec56e20e34d2f4fc4b267e4cd910e956e845187d2f683dc5fcd49` |
| **BCrypt** | *Different each time (includes random salt)* |
| **SCrypt** | *Consistent with same salt parameters* |
| **Argon2** | *Consistent with same salt parameters* |

## Algorithm Details

### SHA256/SHA512
- **Type:** Cryptographic hash functions
- **Use Case:** General-purpose hashing, integrity verification
- **Speed:** Very fast
- **Security:** Not suitable for password storage (too fast)

### BCrypt
- **Type:** Password hashing function
- **Use Case:** Password storage
- **Features:** Built-in salt, adjustable cost factor
- **Speed:** Intentionally slow (configurable)

### SCrypt
- **Type:** Key derivation function
- **Use Case:** Password storage, cryptocurrency mining
- **Features:** Memory-hard (ASIC-resistant)
- **Speed:** Slow and memory-intensive

### Argon2
- **Type:** Password hashing function (PHC winner)
- **Use Case:** Modern password storage
- **Variants:** Argon2i (data-independent), Argon2d (data-dependent), Argon2id (hybrid)
- **Features:** Configurable time, memory, and parallelism costs

## Usage Examples

### Using the Core Function
```bash
# Source the core function
source generate_hash.sh

# Generate hashes with custom inputs
generate_hash "mypassword" "answer1" "answer2" "answer3" "2" "sha256"
```

### Test Parameters
Each test script includes variations:
- Password + questions
- Password only
- Questions only
- Single question
- Multiple iterations
- Different security parameters

## File Structure
```
test/
├── generate_hash.sh          # Core hash generation function
├── test_sha256.sh           # SHA256 tests
├── test_sha512.sh           # SHA512 tests
├── test_bcrypt.sh           # BCrypt tests
├── test_scrypt.sh           # SCrypt tests
├── test_argon2.sh           # Argon2 tests
├── test_all_algorithms.sh   # Master test runner
├── install_dependencies.sh  # Dependency installer
└── README.md               # This file
```

## Dependencies

### System Requirements
- **OpenSSL** (for SHA functions and HMAC)
- **xxd** (for hex conversion)
- **Apache Utils** (htpasswd for BCrypt)

### Optional Dependencies
- **scrypt** command or Python scrypt module
- **argon2** command or Python argon2-cffi module

### Installation Commands
```bash
# Ubuntu/Debian
sudo apt-get install openssl xxd apache2-utils scrypt argon2

# Python modules
pip3 install scrypt argon2-cffi
```

## Security Notes

1. **For Password Storage:** Use Argon2id > BCrypt > SCrypt
2. **For General Hashing:** Use SHA256/SHA512
3. **Never use MD5 or SHA1** for security-critical applications
4. **Always use random salts** in production (these tests use fixed salts for consistency)
5. **Adjust cost parameters** based on your security requirements and performance constraints

## Troubleshooting

### Common Issues
1. **"Command not found"** - Install missing dependencies
2. **"Permission denied"** - Make scripts executable: `chmod +x *.sh`
3. **Slow performance** - Reduce cost parameters for testing
4. **Different results** - BCrypt uses random salts; others should be consistent

### Getting Help
```bash
# Check what's available on your system
./test_all_algorithms.sh

# Install missing tools
sudo ./install_dependencies.sh

# Test individual algorithms
./test_sha256.sh
```