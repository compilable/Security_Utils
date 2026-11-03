# Security Utilities 3.0.0

Offline-first browser utilities for deterministic recovery-key derivation, legacy hash compatibility, and image processing.

## What changed in 3.0.0

- Added the separate, versioned Recovery Protocol v1 with deterministic HKDF-SHA-512 derivation, manifests, validation, and cross-language test vectors.
- Reclassified the original password generator as a legacy compatibility tool, changed its default from MD5 to SHA-256, and documented its fixed algorithm-specific parameters.
- Replaced runtime CDN resources with pinned local assets covered by `THIRD_PARTY_ASSETS.sha256`.
- Updated and pinned the container to PHP 8.4.27, removed mutable `latest` images, and hardened local deployment with localhost-only publishing, a read-only root filesystem, temporary writable storage, and reduced capabilities.
- Restricted Flatpak and Snap permissions, corrected clipboard and memory-erasure claims, and removed production debug logging and insecure random fallbacks.
- Added automated security checks, Dependabot configuration, reproducible `3.0.0` archives, checksums, and provenance attestations for tagged GitHub builds.

## Security boundaries

- `recovery_key.php` implements the versioned deterministic Recovery Protocol v1. Use it only with a securely stored 256-bit seed.
- `password_hash_gen.php` is a legacy compatibility tool. Its bcrypt, scrypt, and Argon2 outputs use random salts and are intentionally not reproducible.
- Legacy repeat cycles are not a universal security work factor. Each password-hashing algorithm has different fixed parameters.
- Clearing a field only clears the visible DOM value; JavaScript cannot guarantee memory erasure.
- Clipboard copying is explicit and clipboard history may retain copied credentials.
- All runtime JavaScript, CSS, fonts, and cryptographic libraries are bundled locally. Runtime pages do not require internet access.
- The supplied Docker configuration listens on localhost only. Remote hosting requires TLS, authentication, and a separate security review.

Never replace an existing LUKS2/KDBX4 credential until the new credential unlocks a disposable test copy. Preserve the old tool and matching inputs for old snapshots.

## Recovery Protocol v1

Recovery Protocol v1 is separate from the legacy hash tool:

- Required secret: exactly 32 random bytes, entered as 64 hexadecimal characters.
- KDF: HKDF-SHA-512 using Web Crypto.
- Output: 32 bytes encoded as unpadded Base64URL.
- Context: protocol version, public snapshot ID, three ordered optional answers, and optional file records.
- Text: Unicode NFC followed by UTF-8; values are not trimmed.
- Fields: tagged and prefixed with unsigned 32-bit big-endian byte lengths.
- Files: maximum 10 files and 5 MiB each; represented by normalized filename, size, and SHA-512 content digest.
- File order: lexicographic UTF-8 filename bytes, then SHA-512 digest bytes. Locale-sensitive sorting is never used.
- Missing answers: explicit empty Q1/Q2/Q3 fields.
- Fixed HKDF info: `Security Utils Recovery Key v1`.

The downloadable non-secret manifest records these parameters, snapshot ID, release-archive SHA-256, context digest, file identifiers/digests, and an optional disposable-copy verification date. Loading that manifest makes derivation fail if the protocol version or canonical context differs. It never contains the private seed, answers, or derived credential. File digests may still reveal whether someone possesses a known file; protect the manifest when that matters.

HKDF is appropriate here because the protocol requires a high-entropy seed. Human answers and files provide context but are not treated as a replacement for seed entropy. The construction requires independent review before use as the sole recovery mechanism for irreplaceable data.

Follow [Recovery Protocol v1.md](Recovery%20Protocol%20v1.md) for enrollment, disposable LUKS2/KDBX4 verification, routine recovery, and failure handling.

## Run locally

Requirements: Docker with Compose, or PHP 8.4.27+ with `gd` and `fileinfo`.

```bash
git clone https://github.com/compilable/Security_Utils.git
cd Security_Utils
docker compose up -d --build
```

Open:

- Dashboard: <http://localhost:3020/>
- Recovery Protocol v1: <http://localhost:3020/recovery_key.php>
- Legacy hash compatibility: <http://localhost:3020/password_hash_gen.php>
- Image randomizer: <http://localhost:3020/image-randomizer.php>

Stop with `docker compose down`.

Native local-only run with the same PHP restrictions used by the installer:

```bash
php -d allow_url_fopen=0 \
    -d allow_url_include=0 \
    -d session.upload_progress.enabled=0 \
    -d expose_php=0 \
    -S 127.0.0.1:8070
```

Do not bind the PHP development server to a public interface.

## Offline verification

Verify vendored assets and run protocol vectors:

```bash
sha256sum --check THIRD_PARTY_ASSETS.sha256
node test/test_recovery_protocol.js
python3 test/test_recovery_protocol.py
test/security_checks.sh
```

The JavaScript and independent Python implementations must produce:

```text
AZ2FB-zw4kL7CjEHFlY5RwmuhhhGahrNKWaYhnjgcRw
```

for the committed Recovery Protocol v1 test vector. The test also checks file-order independence, changed-input divergence, invalid seeds, missing snapshot IDs, wrong manifest versions, and context mismatches caused by missing or changed inputs.

## Release process

`./build.sh release` creates:

- `build/release/security-utils-3.0.0.tar.gz`
- `build/release/security-utils-3.0.0.tar.gz.sha256`

A pushed `v3.0.0` tag runs the same tests and generates a Sigstore-backed provenance attestation. Verify the checksum and attestation from the directory containing the downloaded files:

```bash
sha256sum --check security-utils-3.0.0.tar.gz.sha256
gh attestation verify security-utils-3.0.0.tar.gz -R compilable/Security_Utils
```

Images and runtime sources are version-pinned. Do not publish mutable `latest` tags. `THIRD_PARTY_ASSETS.sha256` is the dependency lock for bundled browser assets.

## Recovery release gates

Automation cannot prove real recovery. Before calling a release recovery-ready, record successful checks for:

- a second computer;
- a second Linux distribution and supported browser;
- a disposable LUKS2 volume;
- a disposable KDBX4 database;
- an independently stored emergency credential;
- archived prior protocol vectors;
- an offline trusted-person drill using disposable data;
- independent cryptographic review of the protocol.

Use [RECOVERY_RELEASE_CHECKLIST.md](RECOVERY_RELEASE_CHECKLIST.md) for the sign-off record.

## Legacy compatibility tool

The legacy tool preserves its historical trimming, combination, and repeat-cycle behavior so existing outputs remain reproducible where the selected algorithm itself is deterministic. SHA-256 is now the safe default; MD5 remains only for legacy integrity compatibility. Random-salt bcrypt, scrypt, and Argon2 remain suitable for password verification but not deterministic recovery.

See `password_hash_gen_doc.html` for exact limitations and parameters.

## Deployment notes

- Docker publishes only `127.0.0.1:3020` and uses the default seccomp profile, a read-only root filesystem, limited writable temporary filesystems, and reduced capabilities.
- The Flatpak manifest uses Freedesktop 25.08 and an offline profile without host filesystem or network access.
- The Snap manifest uses strict confinement with local server binding but no outbound-network, home, or desktop permission.
- The image has also been exercised with Docker networking disabled. Normal Compose runs use Docker's bridge network so the localhost-published UI remains reachable; PHP URL fetching is disabled and browser CSP restricts connections. Flatpak and Snap package execution remain release-checklist items.
- Remote deployment is intentionally not configured. Put authentication and HTTPS in front of the application only after a separate threat review.

## Vendored dependencies

- Bootstrap 5.3.8
- Bootstrap Icons 1.13.1
- CryptoJS 4.2.0
- bcryptjs 2.4.3
- scrypt-js 3.0.1
- argon2-browser 1.18.0

Exact hashes are in `THIRD_PARTY_ASSETS.sha256`. Licenses remain in the upstream distributions and are summarized in `THIRD_PARTY_ASSETS.md`.

## License

MIT. See `LICENSE` when present in the source distribution.
