'use strict';

const assert = require('assert');
const protocol = require('../js/recovery-protocol.js');

(async () => {
    const input = {
        seedHex: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        snapshotId: 'snapshot-α',
        answers: ['first', '', 'third'],
        files: [
            { name: 'z.txt', bytes: new TextEncoder().encode('z') },
            { name: 'a.txt', bytes: new TextEncoder().encode('alpha') }
        ]
    };

    const first = await protocol.derive(input);
    const second = await protocol.derive({ ...input, files: [...input.files].reverse() });
    assert.strictEqual(first.credential, second.credential, 'file selection order must not affect output');
    assert.strictEqual(first.credential, 'AZ2FB-zw4kL7CjEHFlY5RwmuhhhGahrNKWaYhnjgcRw');
    const manifest = protocol.manifest(input.snapshotId, first, '2026-11-03', 'a'.repeat(64));
    assert.doesNotThrow(() => protocol.validateManifest(manifest, first));
    assert.throws(() => protocol.validateManifest({ ...manifest, version: 2 }, first), /Protocol v1/);

    const changed = await protocol.derive({ ...input, snapshotId: 'snapshot-β' });
    assert.notStrictEqual(first.credential, changed.credential, 'changed input must change output');
    assert.throws(() => protocol.validateManifest(manifest, changed), /missing or changed/);
    await assert.rejects(() => protocol.derive({ ...input, seedHex: '00' }), /256 bits/);
    await assert.rejects(() => protocol.derive({ ...input, snapshotId: '' }), /Snapshot ID/);

    console.log('Recovery Protocol v1 known-answer and validation tests passed');
})().catch(error => {
    console.error(error);
    process.exitCode = 1;
});
