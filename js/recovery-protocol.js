(function (root, factory) {
    const protocol = factory();
    if (typeof module === 'object' && module.exports) module.exports = protocol;
    root.RecoveryProtocol = protocol;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    const VERSION = 1;
    const PROTOCOL_ID = 'security-utils-recovery-v1';
    const INFO = new TextEncoder().encode('Security Utils Recovery Key v1');
    const MAGIC = new TextEncoder().encode('SecurityUtilsRecovery');
    const MAX_FILES = 10;
    const MAX_FILE_SIZE = 5 * 1024 * 1024;
    const MAX_ANSWER_SIZE = 1024;

    function webCrypto() {
        const implementation = globalThis.crypto;
        if (!implementation || !implementation.subtle || !implementation.getRandomValues) {
            throw new Error('Recovery Protocol v1 requires Web Crypto in a secure context');
        }
        return implementation;
    }

    function text(value) {
        return new TextEncoder().encode(String(value).normalize('NFC'));
    }

    function uint32(value) {
        const bytes = new Uint8Array(4);
        new DataView(bytes.buffer).setUint32(0, value, false);
        return bytes;
    }

    function concat(parts) {
        const length = parts.reduce((total, part) => total + part.length, 0);
        const result = new Uint8Array(length);
        let offset = 0;
        for (const part of parts) {
            result.set(part, offset);
            offset += part.length;
        }
        return result;
    }

    function field(tag, bytes) {
        return concat([new Uint8Array([tag]), uint32(bytes.length), bytes]);
    }

    function compareBytes(left, right) {
        const length = Math.min(left.length, right.length);
        for (let i = 0; i < length; i++) {
            if (left[i] !== right[i]) return left[i] - right[i];
        }
        return left.length - right.length;
    }

    function hex(bytes) {
        return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    function fromHex(value) {
        if (!/^[0-9a-fA-F]{64}$/.test(value)) {
            throw new Error('Private seed must be exactly 64 hexadecimal characters (256 bits)');
        }
        return new Uint8Array(value.match(/../g).map(byte => parseInt(byte, 16)));
    }

    function base64Url(bytes) {
        let binary = '';
        for (const byte of bytes) binary += String.fromCharCode(byte);
        const encoded = typeof btoa === 'function'
            ? btoa(binary)
            : Buffer.from(bytes).toString('base64');
        return encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    async function prepareFiles(files) {
        if (files.length > MAX_FILES) throw new Error(`Maximum ${MAX_FILES} files allowed`);
        const subtle = webCrypto().subtle;
        const prepared = [];

        for (const file of files) {
            const bytes = file.bytes instanceof Uint8Array ? file.bytes : new Uint8Array(file.bytes);
            if (bytes.length > MAX_FILE_SIZE) throw new Error(`${file.name} exceeds the 5 MiB limit`);
            const name = text(file.name);
            const digest = new Uint8Array(await subtle.digest('SHA-512', bytes));
            prepared.push({ name, digest, size: bytes.length });
        }

        prepared.sort((left, right) => compareBytes(left.name, right.name) || compareBytes(left.digest, right.digest));
        return prepared;
    }

    async function derive(options) {
        const cryptoApi = webCrypto();
        const snapshot = text(options.snapshotId);
        if (snapshot.length === 0 || snapshot.length > 256) {
            throw new Error('Snapshot ID must contain 1–256 UTF-8 bytes');
        }

        const answers = Array.from({ length: 3 }, (_, index) => text((options.answers || [])[index] || ''));
        if (answers.some(answer => answer.length > MAX_ANSWER_SIZE)) {
            throw new Error('Each answer must be at most 1024 UTF-8 bytes');
        }
        const files = await prepareFiles(options.files || []);
        const canonical = [MAGIC, uint32(VERSION), field(1, snapshot)];
        answers.forEach((answer, index) => canonical.push(field(index + 2, answer)));
        for (const file of files) {
            canonical.push(field(5, concat([field(1, file.name), field(2, uint32(file.size)), field(3, file.digest)])));
        }

        const contextDigest = new Uint8Array(await cryptoApi.subtle.digest('SHA-512', concat(canonical)));
        const seed = fromHex(options.seedHex);
        try {
            const key = await cryptoApi.subtle.importKey('raw', seed, 'HKDF', false, ['deriveBits']);
            const bits = await cryptoApi.subtle.deriveBits({
                name: 'HKDF',
                hash: 'SHA-512',
                salt: contextDigest,
                info: INFO
            }, key, 256);
            return {
                credential: base64Url(new Uint8Array(bits)),
                contextSha512: hex(contextDigest),
                files: files.map(file => ({
                    name: new TextDecoder().decode(file.name),
                    size: file.size,
                    sha512: hex(file.digest)
                }))
            };
        } finally {
            seed.fill(0);
        }
    }

    function generateSeed() {
        const seed = webCrypto().getRandomValues(new Uint8Array(32));
        const value = hex(seed);
        seed.fill(0);
        return value;
    }

    function manifest(snapshotId, result, verifiedOn, toolBuildSha256) {
        if (!/^[0-9a-fA-F]{64}$/.test(toolBuildSha256 || '')) {
            throw new Error('Tool build SHA-256 must be exactly 64 hexadecimal characters');
        }
        return {
            protocol: PROTOCOL_ID,
            version: VERSION,
            kdf: 'HKDF-SHA-512',
            output: '256-bit Base64URL without padding',
            tool_build_sha256: toolBuildSha256.toLowerCase(),
            snapshot_id: String(snapshotId).normalize('NFC'),
            canonical_encoding: 'NFC UTF-8, tagged 32-bit big-endian length-prefixed fields',
            file_order: 'NFC UTF-8 filename bytes, then SHA-512 digest bytes',
            missing_answers: 'encoded as empty fields in Q1/Q2/Q3 order',
            context_sha512: result.contextSha512,
            files: result.files,
            verified_on: verifiedOn || null
        };
    }

    function validateManifest(expected, result) {
        if (!expected || expected.protocol !== PROTOCOL_ID || expected.version !== VERSION) {
            throw new Error('Manifest is not Security Utils Recovery Protocol v1');
        }
        if (expected.context_sha512 !== result.contextSha512) {
            throw new Error('Inputs do not match the manifest; a value or recovery file is missing or changed');
        }
    }

    return { VERSION, PROTOCOL_ID, MAX_FILES, MAX_FILE_SIZE, derive, generateSeed, manifest, validateManifest };
}));
