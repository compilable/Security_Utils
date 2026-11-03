// Test script to verify JavaScript implementation matches Python results
const crypto = require('crypto');
const fs = require('fs');

// Simple MD5 implementation to test string hashing
function md5Hash(text) {
    return crypto.createHash('md5').update(text, 'utf8').digest('hex');
}

// Simple HMAC implementation
function hmacMd5(data, key) {
    return crypto.createHmac('md5', key).update(data, 'utf8').digest('hex');
}

// Test file hash (same as Python - read file and hash)
function fileHash(filepath) {
    const content = fs.readFileSync(filepath);
    return crypto.createHash('md5').update(content).digest('hex');
}

// Test question hash - join then hash (Python behavior)
function questionHash(questions) {
    const individualHashes = questions.map(q => md5Hash(q));
    return md5Hash(individualHashes.join(''));
}

console.log('=== NODE.JS COMPATIBILITY TESTS ===');

// Create test file
const testContent = 'test file content'; 
const testFilePath = '/tmp/test_nodejs.txt';
fs.writeFileSync(testFilePath, testContent);

// Test individual components
const testText = 'hello world';
const md5Result = md5Hash(testText);
console.log(`MD5('${testText}'): ${md5Result}`);

const fileMd5 = fileHash(testFilePath);
console.log(`File MD5: ${fileMd5}`);

const questions = ['answer1', 'answer2'];
const questionMd5 = questionHash(questions);
console.log(`Questions MD5: ${questionMd5}`);

const passwordList = [fileMd5, questionMd5];
const finalHmac = hmacMd5(passwordList.join(''), 'testkey');
console.log(`Final HMAC: ${finalHmac}`);

console.log('\n=== EXPECTED RESULTS (from Python) ===');
console.log(`MD5('hello world'): 5eb63bbbe01eeed093cb22bb8f5acdc3`);
console.log(`File MD5: c785060c866796cc2a1708c997154c8e`);
console.log(`Questions MD5: ad08e37313e10d3f962b7bd1dda7ce17`);
console.log(`Final HMAC: 1ed6e8f7e54a5f36120925e9f2ceb499`);

console.log('\n=== COMPATIBILITY CHECK ===');
const compatible = (
    md5Result === '5eb63bbbe01eeed093cb22bb8f5acdc3' &&
    fileMd5 === 'c785060c866796cc2a1708c997154c8e' &&
    questionMd5 === 'ad08e37313e10d3f962b7bd1dda7ce17' &&
    finalHmac === '1ed6e8f7e54a5f36120925e9f2ceb499'
);

console.log(`Node.js implementation ${compatible ? 'MATCHES' : 'DOES NOT MATCH'} Python implementation!`);

// Cleanup
fs.unlinkSync(testFilePath);