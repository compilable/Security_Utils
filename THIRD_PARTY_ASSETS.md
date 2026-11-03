# Vendored browser assets

The application serves these files locally so credential-processing pages work without network access. Verify them with `sha256sum --check THIRD_PARTY_ASSETS.sha256`.

| Asset | Version | License | Source |
|---|---:|---|---|
| Bootstrap | 5.3.8 | MIT | https://github.com/twbs/bootstrap |
| Bootstrap Icons | 1.13.1 | MIT | https://github.com/twbs/icons |
| CryptoJS | 4.2.0 | MIT | https://github.com/brix/crypto-js |
| bcryptjs | 2.4.3 | MIT | https://github.com/dcodeIO/bcrypt.js |
| scrypt-js | 3.0.1 | MIT | https://github.com/ricmoo/scrypt-js |
| argon2-browser | 1.18.0 | MIT | https://github.com/antelle/argon2-browser |

The exact retrieved bytes—not mutable package aliases—are locked by the checksum file. Review upstream licenses when updating an asset.
