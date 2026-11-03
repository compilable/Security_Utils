(function () {
    'use strict';

    const form = document.getElementById('recovery-form');
    const seed = document.getElementById('recovery-seed');
    const output = document.getElementById('recovery-output');
    const status = document.getElementById('status');
    const deriveButton = document.getElementById('derive-button');
    const copyButton = document.getElementById('copy-button');
    const manifestButton = document.getElementById('manifest-button');
    let lastResult = null;
    let idleTimer = null;

    function setStatus(message, error) {
        status.textContent = message;
        status.className = error ? 'status error' : 'status';
    }

    function clearVisibleFields() {
        form.reset();
        output.value = '';
        lastResult = null;
        copyButton.disabled = true;
        manifestButton.disabled = true;
        setStatus('Visible fields cleared. JavaScript runtimes cannot guarantee memory erasure.');
    }

    function resetIdleTimer() {
        clearTimeout(idleTimer);
        idleTimer = setTimeout(clearVisibleFields, 120000);
    }

    async function selectedFiles() {
        const selected = Array.from(document.getElementById('recovery-files').files);
        return Promise.all(selected.map(async file => ({
            name: file.name,
            bytes: new Uint8Array(await file.arrayBuffer())
        })));
    }

    async function expectedManifest() {
        const file = document.getElementById('recovery-manifest').files[0];
        if (!file) return null;
        try {
            return JSON.parse(await file.text());
        } catch (error) {
            throw new Error('Manifest must be valid JSON');
        }
    }

    document.getElementById('generate-seed').addEventListener('click', () => {
        try {
            seed.value = RecoveryProtocol.generateSeed();
            setStatus('New seed generated. Store it separately; losing it makes recovery impossible.');
        } catch (error) {
            setStatus(error.message, true);
        }
    });

    form.addEventListener('submit', async event => {
        event.preventDefault();
        deriveButton.disabled = true;
        output.value = '';
        try {
            const result = await RecoveryProtocol.derive({
                seedHex: seed.value,
                snapshotId: document.getElementById('snapshot-id').value,
                answers: ['answer-1', 'answer-2', 'answer-3'].map(id => document.getElementById(id).value),
                files: await selectedFiles()
            });
            const expected = await expectedManifest();
            if (expected) RecoveryProtocol.validateManifest(expected, result);
            lastResult = result;
            output.value = lastResult.credential;
            seed.value = '';
            ['answer-1', 'answer-2', 'answer-3'].forEach(id => { document.getElementById(id).value = ''; });
            document.getElementById('recovery-files').value = '';
            copyButton.disabled = false;
            manifestButton.disabled = false;
            setStatus('Credential derived locally; private input fields were visibly cleared. Verify it on a disposable copy before recording a verification date.');
        } catch (error) {
            lastResult = null;
            setStatus(error.message, true);
        } finally {
            deriveButton.disabled = false;
        }
    });

    copyButton.addEventListener('click', async () => {
        try {
            if (!navigator.clipboard || !window.isSecureContext) throw new Error('Clipboard access requires HTTPS or localhost');
            await navigator.clipboard.writeText(output.value);
            setStatus('Copied. Clipboard history may retain the credential; clear it using your operating system.');
        } catch (error) {
            setStatus(error.message, true);
        }
    });

    manifestButton.addEventListener('click', () => {
        if (!lastResult) return;
        try {
            const verifiedOn = document.getElementById('verified-on').value;
            const checksum = document.getElementById('tool-build-sha256').value;
            const data = RecoveryProtocol.manifest(document.getElementById('snapshot-id').value, lastResult, verifiedOn, checksum);
            const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2) + '\n'], { type: 'application/json' }));
            const link = document.createElement('a');
            link.href = url;
            link.download = 'security-utils-recovery-v1-manifest.json';
            link.click();
            URL.revokeObjectURL(url);
        } catch (error) {
            setStatus(error.message, true);
        }
    });

    document.getElementById('clear-button').addEventListener('click', clearVisibleFields);
    ['click', 'keydown', 'input', 'change'].forEach(type => document.addEventListener(type, resetIdleTimer, { passive: true }));
    resetIdleTimer();

    if (!window.isSecureContext || !window.crypto || !window.crypto.subtle) {
        deriveButton.disabled = true;
        setStatus('Recovery Protocol v1 requires HTTPS or localhost with Web Crypto support.', true);
    }
}());
