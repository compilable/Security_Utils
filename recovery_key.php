<?php
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'");
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Deterministic Recovery Key — Protocol v1</title>
    <link rel="stylesheet" href="css/recovery-key.css">
</head>
<body>
<main>
    <p><a href="index.php">← Security Utilities</a></p>
    <h1>Deterministic Recovery Key</h1>
    <p>Protocol <strong>v1</strong> · HKDF-SHA-512 · 256-bit Base64URL output · fully offline</p>

    <section class="card warning">
        <strong>Do not replace an existing recovery credential in place.</strong>
        Add and test this credential on a disposable LUKS2/KDBX4 copy first. Keep the original software and inputs for old snapshots. This protocol still needs independent cryptographic review.
    </section>

    <form id="recovery-form" class="card">
        <label for="snapshot-id">Public snapshot ID</label>
        <input id="snapshot-id" maxlength="256" required autocomplete="off">
        <small>Exact NFC-normalized UTF-8 value. Whitespace is preserved.</small>

        <label for="recovery-seed">Private 256-bit seed</label>
        <input id="recovery-seed" type="password" pattern="[0-9A-Fa-f]{64}" maxlength="64" required autocomplete="off" spellcheck="false">
        <div class="buttons"><button id="generate-seed" type="button" class="secondary">Generate seed</button></div>
        <small>Exactly 64 hexadecimal characters. Store this independently from the manifest.</small>

        <label for="answer-1">Optional secret answer Q1</label>
        <input id="answer-1" type="password" maxlength="256" autocomplete="off">
        <label for="answer-2">Optional secret answer Q2</label>
        <input id="answer-2" type="password" maxlength="256" autocomplete="off">
        <label for="answer-3">Optional secret answer Q3</label>
        <input id="answer-3" type="password" maxlength="256" autocomplete="off">
        <small>Exact NFC-normalized UTF-8 values in Q1/Q2/Q3 order. Missing answers are explicit empty fields.</small>

        <label for="recovery-files">Optional recovery files</label>
        <input id="recovery-files" type="file" multiple>
        <small>Maximum 10 files and 5 MiB each. Ordered by normalized filename bytes, then SHA-512 digest bytes.</small>

        <label for="recovery-manifest">Optional expected v1 manifest</label>
        <input id="recovery-manifest" type="file" accept="application/json,.json">
        <small>Load a previous manifest to fail closed if an input or recovery file is missing, changed, or from another protocol version.</small>

        <div class="buttons">
            <button id="derive-button" type="submit">Derive credential</button>
            <button id="clear-button" type="button" class="secondary">Clear visible fields</button>
        </div>
    </form>

    <section class="card">
        <label for="recovery-output">Derived credential</label>
        <input id="recovery-output" type="password" readonly autocomplete="off">
        <div class="buttons"><button id="copy-button" type="button" disabled>Copy with warning</button></div>

        <label for="verified-on">Disposable-copy verification date</label>
        <input id="verified-on" type="date">
        <label for="tool-build-sha256">Release archive SHA-256</label>
        <input id="tool-build-sha256" pattern="[0-9A-Fa-f]{64}" maxlength="64" autocomplete="off" spellcheck="false">
        <small>Required when downloading a manifest. Copy it from the verified release <code>.sha256</code> file.</small>
        <div class="buttons"><button id="manifest-button" type="button" class="secondary" disabled>Download non-secret manifest</button></div>
        <p id="status" class="status" role="status" aria-live="polite"></p>
    </section>

    <section class="card">
        <h2>Protocol v1 encoding</h2>
        <p>The seed is HKDF input keying material. A SHA-512 digest of the versioned, tagged, length-prefixed canonical context is the salt. The fixed info string is <code>Security Utils Recovery Key v1</code>. No value is trimmed and no locale-sensitive ordering is used.</p>
        <p>Clearing fields only removes visible values. Browsers cannot guarantee secret memory erasure, and clipboard managers may retain copied credentials.</p>
    </section>
</main>
<script src="js/recovery-protocol.js"></script>
<script src="js/recovery-key.js"></script>
</body>
</html>
