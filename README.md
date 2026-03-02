# git-crypt-revived

**Transparent file encryption in Git** -- a modernized fork of [AGWA/git-crypt](https://github.com/AGWA/git-crypt).

git-crypt enables transparent encryption and decryption of files in a git repository. Files which you choose to protect are encrypted when committed, and decrypted when checked out. git-crypt lets you freely share a repository containing a mix of public and private content. Developers without the secret key can still clone and commit to a repository with encrypted files, so you can store secrets alongside your code without locking down your entire repository.

## What's Different in This Fork

This fork picks up where AGWA/git-crypt left off (v0.8.0) and adds:

- Modernized CI pipeline (GitHub Actions with multi-platform build matrix)
- CMake build system alongside the original Makefile
- Docker-based development environment
- Catch2 unit test framework with crypto and key roundtrip tests
- Source reorganization into `src/` directory structure

### Roadmap

The following features are planned but **not yet implemented**:

- **age encryption support** -- use [age](https://age-encryption.org/) and SSH keys as an alternative to GPG
- **SOPS integration** -- bridge to Mozilla SOPS for structured file encryption
- **2FA via YubiKey / Shamir's Secret Sharing** -- hardware-backed two-factor authentication
- **Wallet-based identity and access control** -- decentralized identity for key management
- **Cryptographic audit trails** -- verifiable log of encryption/decryption events
- **Signed access logging** -- tamper-evident access records

## Installation

### Build from Source

**Requirements**: C++11 compiler (gcc 4.9+ or clang), OpenSSL, GNU Make

```bash
git clone https://github.com/appmaestro-ai/git-crypt.git
cd git-crypt
make
make install PREFIX=/usr/local
```

For macOS with Homebrew OpenSSL:

```bash
OPENSSL_PREFIX="$(brew --prefix openssl)"
make CXXFLAGS="-Wall -pedantic -Wno-long-long -O2 -std=c++11 -I${OPENSSL_PREFIX}/include" \
     LDFLAGS="-L${OPENSSL_PREFIX}/lib -lcrypto"
```

See [INSTALL.md](INSTALL.md) for detailed build instructions including CMake and Docker options.

### Homebrew (future)

Homebrew formula support is planned for a future release.

## Quick Start

```bash
# 1. Initialize git-crypt in your repository
cd my-repo
git-crypt init

# 2. Specify which files to encrypt via .gitattributes
echo 'secrets/** filter=git-crypt diff=git-crypt' >> .gitattributes
echo '*.key filter=git-crypt diff=git-crypt' >> .gitattributes
git add .gitattributes
git commit -m "Configure git-crypt"

# 3. Add files -- they are encrypted transparently on commit
echo "API_KEY=s3cret" > secrets/config.env
git add secrets/config.env
git commit -m "Add encrypted secrets"

# 4. Share access via GPG
git-crypt add-gpg-user alice@example.com

# 5. Or export a symmetric key to share manually
git-crypt export-key /path/to/shared-key
```

After a collaborator clones the repository:

```bash
# Unlock with GPG (automatic key selection)
git-crypt unlock

# Or unlock with a symmetric key
git-crypt unlock /path/to/shared-key
```

## Command Reference

| Command | Description |
|---|---|
| `git-crypt init` | Generate a key and prepare the repo for encryption |
| `git-crypt init -k NAME` | Initialize a named key for multi-key setups |
| `git-crypt status` | Show encryption status of all files |
| `git-crypt status -e` | Show only encrypted files |
| `git-crypt status -f` | Fix files that should be encrypted but aren't |
| `git-crypt lock` | Encrypt all files in the working copy |
| `git-crypt unlock` | Decrypt the repo using GPG |
| `git-crypt unlock KEYFILE` | Decrypt the repo using a symmetric key file |
| `git-crypt add-gpg-user USER` | Grant a GPG user access to encrypted files |
| `git-crypt export-key FILE` | Export the symmetric key to a file |
| `git-crypt help` | Show help information |
| `git-crypt version` | Print the installed version |

## Security

git-crypt encrypts files using AES-256 in CTR mode with a synthetic IV derived from the SHA-1 HMAC of the file. This is provably semantically secure under deterministic chosen-plaintext attack -- it leaks no information beyond whether two files are identical.

## Limitations

- Not designed for encrypting most or all files in a repository. Best suited for a few sensitive files (keys, credentials) in an otherwise public repo.
- Does not encrypt file names, commit messages, symlink targets, or other metadata.
- Does not support revoking access to previously granted users (no key rotation).
- Encrypted files are not compressible by git's delta compression.
- Not compatible with some third-party git GUIs.

See the man page (`git-crypt help`) for full details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, testing, and how to submit pull requests.

## License

git-crypt-revived is licensed under the [GNU General Public License v3](COPYING).

Originally written by [Andrew Ayer](https://www.agwa.name) (agwa@andrewayer.name). See [AUTHORS](AUTHORS) and [THANKS.md](THANKS.md) for contributors.
