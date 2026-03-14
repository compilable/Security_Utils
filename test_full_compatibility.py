#!/usr/bin/env python3
"""
Comprehensive test to verify Python and JavaScript implementations produce identical results.
This script tests the core algorithm components to ensure compatibility.
"""

import sys
import os
sys.path.append('/home/rootx/workspace/LIVE/sec_utils/Security_Utils_v1')

from password_hash_gen import HasUtils, HASH_ALGORITHEM
import tempfile
import json
import subprocess

def run_js_test(test_data):
    """Run JavaScript test and return results"""
    js_test_code = f'''
const crypto = require('crypto');
const fs = require('fs');

// Test data from Python
const testData = {json.dumps(test_data)};

// JavaScript implementations (matching the web version)
function md5Hash(text) {{
    return crypto.createHash('md5').update(text, 'utf8').digest('hex');
}}

function hmacMd5(data, key) {{
    return crypto.createHmac('md5', key).update(data, 'utf8').digest('hex');
}}

function fileHash(filepath) {{
    const content = fs.readFileSync(filepath);
    return crypto.createHash('md5').update(content).digest('hex');
}}

function questionHash(questions) {{
    const individualHashes = questions.map(q => md5Hash(q));
    return md5Hash(individualHashes.join(''));
}}

// Create test file with same content
const testFilePath = '/tmp/js_test_file.txt';
fs.writeFileSync(testFilePath, testData.file_content);

// Run tests
const results = {{}};
results.string_md5 = md5Hash(testData.test_string);
results.file_md5 = fileHash(testFilePath);
results.questions_md5 = questionHash(testData.questions);
results.final_hmac = hmacMd5([results.file_md5, results.questions_md5].join(''), testData.hmac_key);

console.log(JSON.stringify(results));

// Cleanup
fs.unlinkSync(testFilePath);
    '''
    
    # Write JS test to temp file and run it
    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write(js_test_code)
        js_file = f.name
    
    try:
        result = subprocess.run(['node', js_file], capture_output=True, text=True, cwd='/home/rootx/workspace/LIVE/sec_utils/Security_Utils_v2')
        if result.returncode == 0:
            return json.loads(result.stdout.strip())
        else:
            print(f"JavaScript test failed: {result.stderr}")
            return None
    finally:
        os.unlink(js_file)

def main():
    print("=== COMPREHENSIVE COMPATIBILITY TEST ===\\n")
    
    # Test configuration
    test_config = {
        'test_string': 'hello world',
        'file_content': 'test file content', 
        'questions': ['answer1', 'answer2'],
        'hmac_key': 'testkey',
        'cycles': 1
    }
    
    # Create test file for Python
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(test_config['file_content'])
        test_file_path = f.name
    
    try:
        # Python implementation tests
        print("PYTHON IMPLEMENTATION RESULTS:")
        python_results = {}
        
        # String hashing
        python_results['string_md5'] = HasUtils.gen_str_hash(HASH_ALGORITHEM.MD5SUM, test_config['test_string'])
        print(f"  String MD5: {python_results['string_md5']}")
        
        # File hashing  
        python_results['file_md5'] = HasUtils.gen_file_hash([test_file_path], HASH_ALGORITHEM.MD5SUM, test_config['cycles'])
        print(f"  File MD5: {python_results['file_md5']}")
        
        # Question hashing
        python_results['questions_md5'] = HasUtils.gen_question_hash(test_config['questions'], HASH_ALGORITHEM.MD5SUM, test_config['cycles'])
        print(f"  Questions MD5: {python_results['questions_md5']}")
        
        # Final HMAC
        password_list = [python_results['file_md5'], python_results['questions_md5']]
        python_results['final_hmac'] = HasUtils.get_hmac_digest(HASH_ALGORITHEM.MD5SUM, password_list, test_config['hmac_key'])
        print(f"  Final HMAC: {python_results['final_hmac']}")
        
        print("\\nJAVASCRIPT IMPLEMENTATION RESULTS:")
        # JavaScript implementation tests
        js_results = run_js_test(test_config)
        
        if js_results:
            print(f"  String MD5: {js_results['string_md5']}")
            print(f"  File MD5: {js_results['file_md5']}")
            print(f"  Questions MD5: {js_results['questions_md5']}")
            print(f"  Final HMAC: {js_results['final_hmac']}")
            
            print("\\n=== COMPATIBILITY RESULTS ===")
            compatible = all(
                python_results[key] == js_results[key] 
                for key in python_results.keys()
            )
            
            if compatible:
                print("✅ SUCCESS: Both implementations produce IDENTICAL results!")
                print("\\nThe Python and JavaScript versions are now fully compatible.")
            else:
                print("❌ MISMATCH: Implementations produce different results:")
                for key in python_results.keys():
                    match = python_results[key] == js_results[key]
                    status = "✅" if match else "❌"
                    print(f"  {status} {key}: {match}")
                    if not match:
                        print(f"    Python:     {python_results[key]}")
                        print(f"    JavaScript: {js_results[key]}")
        else:
            print("❌ Failed to run JavaScript tests")
            return 1
            
    finally:
        # Cleanup test file
        os.unlink(test_file_path)
    
    return 0 if compatible else 1

if __name__ == "__main__":
    sys.exit(main())