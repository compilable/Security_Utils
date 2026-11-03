# Recovery Protocol v1 runbook

Version: Security Utilities 3.0.0  
Protocol: `security-utils-recovery-v1`  
Audience: the owner and the trusted person responsible for an offline recovery drill

## Stop conditions

Do not use this protocol as the only way to recover valuable data. Stop if any of these are true:

- the original LUKS2/KDBX4 credential or an independent emergency credential is unavailable;
- the release archive or checksum cannot be verified;
- the exact seed, snapshot ID, answers, recovery files, and v1 manifest cannot be preserved separately;
- a disposable copy has not been successfully unlocked and inspected;
- the tool reports a manifest, protocol-version, or context mismatch.

Never remove an existing working credential during enrollment or a drill. Never test against the only copy of valuable data. Recovery Protocol v1 has not received independent cryptographic approval.

## Artifacts and storage boundaries

| Artifact | Classification | Storage rule |
|---|---|---|
| 64-character private seed | Secret and essential | Keep offline in at least two protected locations, separate from the manifest. |
| Optional Q1/Q2/Q3 answers | Secret | Preserve exact spelling, whitespace, case, and question order with the seed. |
| Optional recovery files | Potentially secret and essential | Preserve exact file contents and filenames; do not edit, rename, or re-encode them. |
| Derived credential | Secret | Enter it directly where practical; do not keep it in notes, shell history, or chat. |
| v1 manifest | Non-secret protocol metadata, but privacy-sensitive | Store with the archived tool, not with the seed. File names and hashes may reveal possession of known files. |
| Release archive and `.sha256` file | Public integrity material | Archive the exact version used for enrollment. |
| Independent emergency credential | Secret | Store separately from all protocol inputs and verify it independently. |

The seed is the high-entropy secret. Answers and files add context; they do not compensate for a lost or weak seed.

## 1. Prepare the workstation

Use a trusted computer and a supported browser on `localhost`. Close unrelated applications, disable screen sharing and recording, and disconnect the computer from external networks after obtaining the verified release.

From the directory containing a downloaded release:

```bash
sha256sum --check security-utils-3.0.0.tar.gz.sha256
```

From a source checkout, run the committed checks:

```bash
cd /path/to/Security_Utils
./test/security_checks.sh
```

Start the local service:

```bash
docker compose up -d --build
docker compose ps
```

Confirm that the service is healthy and open:

<http://localhost:3020/recovery_key.php>

Do not expose port 3020 on a public interface. Stop the service after the procedure with `docker compose down`.

## 2. Define immutable recovery inputs

Record the following plan before deriving anything:

| Field | Planned value or location |
|---|---|
| Snapshot ID | ______________________________ |
| Q1 used? | Yes / No |
| Q2 used? | Yes / No |
| Q3 used? | Yes / No |
| Recovery file locations | ______________________________ |
| Seed copy A location | ______________________________ |
| Seed copy B location | ______________________________ |
| Emergency credential location | ______________________________ |
| Release archive location | ______________________________ |

Choose a stable, public snapshot ID such as `vault-name/2026-11-03`. Whitespace is significant and is not trimmed. Keep the same Q1/Q2/Q3 positions forever; an unused answer is an explicit empty field.

Use at most 10 recovery files, each no larger than 5 MiB. Copies must retain their exact content and filename. Selection order does not matter because the protocol defines its own bytewise order.

## 3. Create and protect the private seed

On the trusted offline workstation, generate 32 random bytes as 64 hexadecimal characters:

```bash
openssl rand -hex 32
```

Store the seed immediately in two protected offline locations. Verify both copies character-for-character. Do not pass the seed as a command-line argument, because command lines may be logged.

You may instead use the page's **Generate seed** button, but do so only when you already have a trusted way to capture and verify the hidden field. Losing the seed makes recovery impossible.

## 4. Perform the first derivation

1. Enter the exact public snapshot ID.
2. Paste the 64-character private seed.
3. Enter Q1/Q2/Q3 exactly as planned. Leave intentionally unused answers empty.
4. Select the planned recovery files.
5. Leave **Optional expected v1 manifest** empty for this first derivation.
6. Select **Derive credential**.
7. Confirm that the page reports successful local derivation. The seed, answers, and selected recovery files are visibly cleared automatically.

The derived credential remains available for two minutes of inactivity. JavaScript cannot guarantee that cleared values are erased from memory.

## 5. Save the preliminary manifest

Have the verified release archive checksum ready. Read the first field from its checksum file rather than retyping it:

```bash
cut -d ' ' -f1 security-utils-3.0.0.tar.gz.sha256
```

1. Leave **Disposable-copy verification date** empty.
2. Enter the 64-character release archive SHA-256.
3. Select **Download non-secret manifest**.
4. Rename the download to include the snapshot ID and `pre-verification`, without modifying its JSON content.
5. Store it with the archived release, separately from the seed.

This preliminary manifest is required to detect missing, altered, or wrong-version inputs during the verification derivation.

## 6. Enroll only on a disposable copy

### LUKS2

Set `DEVICE` only after confirming that it is a disposable copy. A wrong device path can affect real data.

```bash
lsblk -f
sudo cryptsetup luksDump /dev/REPLACE_WITH_DISPOSABLE_DEVICE
```

Make a protected header backup before changing keyslots:

```bash
sudo cryptsetup luksHeaderBackup /dev/REPLACE_WITH_DISPOSABLE_DEVICE \
    --header-backup-file luks2-disposable-header.img
```

Protect the header backup as sensitive recovery material. Add the derived credential interactively:

```bash
sudo cryptsetup luksAddKey /dev/REPLACE_WITH_DISPOSABLE_DEVICE
```

Enter an existing working passphrase when requested, then enter the derived credential as the new passphrase. Do not use a command-line argument or temporary plaintext key file.

Test the new credential without creating a mapping:

```bash
sudo cryptsetup open --test-passphrase /dev/REPLACE_WITH_DISPOSABLE_DEVICE
```

A zero exit status confirms that a keyslot accepted the entered credential. Keep the old keyslot and separately test the independent emergency credential.

### KDBX4 / KeePassXC

1. Make a copy of the KDBX4 database and pause any synchronization for that copy.
2. Open the copy with its existing credentials.
3. In KeePassXC, open the database security settings and set the derived credential as the password. Retain any intended key-file or hardware-key factors.
4. Save under a new filename; never overwrite the only known-good database.
5. Close KeePassXC completely.
6. Reopen the new copy with the derived credential and all other configured factors.
7. Inspect representative entries, attachments, and history.
8. Confirm that the independent emergency credential or preserved original database also remains usable.

## 7. Re-derive, validate, and finalize the manifest

After the disposable LUKS2 or KDBX4 test succeeds:

1. Return to the recovery page. Re-enter the exact snapshot ID, seed, Q1/Q2/Q3 answers, and recovery files.
2. Select the preliminary manifest in **Optional expected v1 manifest**.
3. Select **Derive credential**.
4. Stop if the page reports a protocol-version or context mismatch. Do not create a replacement manifest to hide the mismatch.
5. Confirm that the derived credential unlocks the disposable copy again.
6. Enter the successful verification date and the verified release archive SHA-256.
7. Download the final manifest and give it an immutable snapshot-specific filename.
8. Keep the preliminary manifest as an audit artifact or clearly mark it superseded; do not confuse it with the verified manifest.

## 8. Routine recovery procedure

1. Obtain the archived Security Utilities 3.0.0 release, its checksum, and the final v1 manifest.
2. Verify the release checksum before execution.
3. Move to a trusted offline workstation and start the application on localhost.
4. Enter the exact snapshot ID, private seed, ordered answers, and exact recovery files.
5. Load the final v1 manifest before selecting **Derive credential**.
6. Stop on any validation error. Never omit a failing manifest or substitute a newly generated seed.
7. Use the derived credential to unlock a copy first, then the intended recovery target.
8. Clear the visible fields, clear clipboard history if copying was unavoidable, close the browser, and stop the local service.
9. Record the recovery date, operator, tool checksum, target, and outcome without recording secrets.

## 9. Failure handling

| Failure | Required action |
|---|---|
| Release checksum fails | Do not run the archive. Obtain a trusted copy. |
| Manifest protocol/version error | Use the archived v1 tool and the correct v1 manifest. Do not silently upgrade. |
| Context mismatch | Check snapshot ID, answer positions, whitespace, filenames, file contents, and missing files. Do not generate a replacement manifest. |
| Derived credential is rejected | Stop after checking keyboard layout and copied characters. Test the independent emergency credential and preserved original. |
| Seed is missing or uncertain | Stop. The seed cannot be reconstructed from the manifest or derived credential. |
| Recovery file was changed or renamed | Restore the exact archived file. A similar replacement is not equivalent. |
| Clipboard was used | Assume clipboard history may retain the credential and clear it using the operating system. |
| Only working credential would be removed | Stop. Create and verify another independent credential first. |

## 10. Drill and audit record

Complete this record for every enrollment and scheduled drill:

| Item | Record |
|---|---|
| Snapshot ID | |
| Tool version | Security Utilities 3.0.0 |
| Release SHA-256 | |
| Manifest filename and SHA-256 | |
| Test computer / OS / browser | |
| Disposable LUKS2 result | Pass / Fail / N/A |
| Disposable KDBX4 result | Pass / Fail / N/A |
| Emergency credential result | Pass / Fail |
| Second-person drill result | Pass / Fail |
| Operator / reviewer | |
| Verification date | |
| Notes without secrets | |

Also complete [RECOVERY_RELEASE_CHECKLIST.md](RECOVERY_RELEASE_CHECKLIST.md). Do not call the process recovery-ready while required gates remain unchecked.

## References

- [Security Utilities README](README.md)
- [Recovery release checklist](RECOVERY_RELEASE_CHECKLIST.md)
- [cryptsetup `luksAddKey` manual](https://gitlab.com/cryptsetup/cryptsetup/-/blob/master/man/cryptsetup-luksAddKey.8.adoc)
- [cryptsetup `open` manual](https://man7.org/linux/man-pages/man8/cryptsetup-open.8.html)
- [KeePassXC documentation](https://keepassxc.org/docs/)

