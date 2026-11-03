# Recovery release checklist

Release/tag: __________  Commit: __________  Reviewer: __________  Date: __________

- [ ] `test/security_checks.sh` passes from a clean checkout.
- [ ] Recovery Protocol v1 JavaScript and independent Python known-answer vectors pass.
- [ ] The application derives the vector with all networking disabled.
- [ ] The portable archive checksum and GitHub artifact attestation verify.
- [ ] A second computer reproduces the known-answer credential.
- [ ] A second Linux distribution/browser reproduces it.
- [ ] A disposable LUKS2 volume unlocks with the derived credential.
- [ ] A disposable KDBX4 database unlocks with the derived credential.
- [ ] An independently stored emergency credential unlocks each disposable fixture.
- [ ] Prior released protocol vectors still pass using archived builds.
- [ ] A trusted person completes an offline drill using disposable data and written instructions.
- [ ] An independent cryptographic reviewer approves protocol changes.

Do not mark a release recovery-ready with unchecked items. Never run these drills against the only copy of valuable data.
