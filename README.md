# git-crypt-revived

**Transparent file encryption in Git** -- a modernized fork of [AGWA/git-crypt](https://github.com/AGWA/git-crypt).

git-crypt enables transparent encryption and decryption of files in a git repository. Files which you choose to protect are encrypted when committed, and decrypted when checked out. git-crypt lets you freely share a repository containing a mix of public and private content. Developers without the secret key can still clone and commit to a repository with encrypted files, so you can store secrets alongside your code without locking down your entire repository.

## What's New in This Fork

This fork picks up where AGWA/git-crypt left off (v0.8.0) and adds significant new functionality:

### Modern Encryption Backends
- **age encryption** -- use [age](https://age-encryption.org/) as a modern, simpler alternative to GPG
- **SSH key support** -- encrypt to collaborators' existing `ssh-ed25519` or `ssh-rsa` keys via age
- **YubiKey PIV** -- hardware-backed authentication via [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey)

### Secret Management
- **SOPS integration** -- bridge to [Mozilla SOPS](https://github.com/getsops/sops) for structured file encryption (YAML, JSON, ENV)
- **Credentials directory** -- `credentials-init` command to set up a `.credentials/` pattern with encryption pre-configured
- **Key rotation** -- `rotate-key` generates a new key version and re-wraps for all recipients

### Advanced Security
- **Shamir's Secret Sharing** -- split keys into M-of-N shares for threshold-based access (`split-key` / `unlock --shares`)
- **Wallet-based identity** -- Ethereum wallet signatures as age-compatible identities (`add-wallet-recipient`)
- **Cryptographic audit trail** -- SHA-256 hash-chained access log with tamper detection (`audit-log` / `verify-audit`)
- **On-chain anchoring** -- publish audit log hashes to a blockchain for immutability (`anchor-audit`)
- **Pre-commit hook** -- prevent accidental plaintext commits of files that should be encrypted (`install-hooks`)
- **Signed commit verification** -- verify GPG/SSH signatures on commits that touch encrypted files (`verify-commits`)
- **.gitattributes tamper detection** -- `status` command detects when encryption attributes are removed

### User Management
- **Remove GPG users** -- revoke a GPG user's access (`rm-gpg-user`)
- **List GPG users** -- show all GPG user fingerprints per key (`ls-gpg-users`)
- **Remove age recipients** -- revoke an age recipient's access (`rm-age-recipient`)
- **Refresh** -- force re-checkout of all encrypted files after key changes (`refresh`)
- **Machine-parseable status** -- `status -m` outputs TSV for scripting

### Infrastructure
- **GitHub Actions CI** -- multi-platform build matrix (Ubuntu gcc/clang, macOS clang, CMake)
- **CMake build system** -- parallel build system alongside the original Makefile
- **Docker dev environment** -- containerized build and development
- **Catch2 test framework** -- unit tests for crypto and key roundtrip operations
- **Source reorganization** -- code moved to `src/` directory structure
- **Homebrew formula** -- install via Homebrew tap
- **Release workflow** -- automated cross-platform binary builds on tag push

## Installation

### Homebrew

```bash
brew tap ramene/tap
brew install git-crypt-revived
```

### Build from Source (Make)

**Requirements**: C++11 compiler (gcc 4.9+ or clang), OpenSSL libcrypto, GNU Make

```bash
git clone https://github.com/ramene/git-crypt.git
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

### Build from Source (CMake)

```bash
cmake -B build
cmake --build build
sudo cmake --install build
```

### Docker

```bash
docker compose run --rm dev bash
# Inside container:
make clean && make && make test
```

See [INSTALL.md](INSTALL.md) for detailed instructions including man page building, Debian packaging, and Windows support.

### Optional Dependencies

These are only needed for specific features and are **not** required for core git-crypt functionality:

| Feature | Dependency | Install |
|---|---|---|
| age encryption | [age](https://age-encryption.org/) | `brew install age` / `apt install age` |
| YubiKey support | [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey) | `brew install age-plugin-yubikey` |
| SOPS integration | [sops](https://github.com/getsops/sops) | `brew install sops` / `apt install sops` |
| Wallet identity | Ethereum wallet (MetaMask, etc.) | N/A |

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

# 4. Share access via GPG, age, or symmetric key
git-crypt add-gpg-user alice@example.com
git-crypt add-age-recipient age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw...
git-crypt export-key /path/to/shared-key

# 5. Install the pre-commit hook to prevent plaintext leaks
git-crypt install-hooks
```

After a collaborator clones the repository:

```bash
# Unlock with GPG (automatic key selection)
git-crypt unlock

# Unlock with a symmetric key
git-crypt unlock /path/to/shared-key

# Unlock with age identity
git-crypt unlock --age

# Unlock with SSH key via age
git-crypt unlock --age --identity ~/.ssh/id_ed25519
```

## Command Reference

### Core Commands

| Command | Description |
|---|---|
| `init` | Generate a key and prepare the repo for encryption |
| `init -k NAME` | Initialize a named key for multi-key setups |
| `init -f` | Force re-initialization of an existing repo |
| `status` | Show encryption status of all files |
| `status -e` | Show only encrypted files |
| `status -f` | Fix files that should be encrypted but aren't |
| `status -m` | Machine-parseable output (TSV format) |
| `lock` | Encrypt all files in the working copy |
| `unlock` | Decrypt the repo using GPG or age |
| `unlock KEYFILE` | Decrypt using a symmetric key file |
| `unlock --shares F1 F2 ...` | Decrypt by combining Shamir key shares |
| `unlock --age` | Decrypt using age identity |
| `unlock --wallet ADDR` | Decrypt using wallet-derived identity |
| `refresh` | Force re-checkout of all encrypted files |
| `export-key FILE` | Export the symmetric key to a file |
| `export-key --version N` | Export a specific key version |
| `help [COMMAND]` | Show help information |
| `version` | Print the installed version |

### GPG Commands

| Command | Description |
|---|---|
| `add-gpg-user USERID` | Grant a GPG user access to encrypted files |
| `rm-gpg-user USERID` | Revoke a GPG user's access |
| `ls-gpg-users` | List all GPG user fingerprints per key |

### Age Commands

| Command | Description |
|---|---|
| `add-age-recipient RECIPIENT` | Add an age public key as a collaborator |
| `add-age-recipient --ssh KEYFILE` | Add an SSH public key as a collaborator |
| `rm-age-recipient RECIPIENT` | Revoke an age recipient's access |

### Key Management

| Command | Description |
|---|---|
| `rotate-key` | Generate a new key version and re-wrap for all recipients |
| `split-key` | Split the symmetric key into M-of-N Shamir shares |

### Security Commands

| Command | Description |
|---|---|
| `install-hooks` | Install pre-commit hook to prevent plaintext leaks |
| `verify-commits` | Verify GPG/SSH signatures on commits touching encrypted files |

### SOPS Integration

| Command | Description |
|---|---|
| `sops-config` | Generate `.sops.yaml` for structured file encryption |
| `credentials-init` | Create `.credentials/` directory with encryption setup |

### Audit & Wallet Commands

| Command | Description |
|---|---|
| `audit-log` | Display the cryptographic audit trail |
| `verify-audit` | Verify audit log hash chain integrity |
| `anchor-audit` | Publish audit log hash to blockchain |
| `add-wallet-recipient ADDR` | Add an Ethereum wallet as a collaborator |

## Security

git-crypt encrypts files using AES-256 in CTR mode with a synthetic IV derived from the SHA-1 HMAC of the file. This is provably semantically secure under deterministic chosen-plaintext attack -- it leaks no information beyond whether two files are identical.

Key wrapping supports GPG (RSA, ECC) and age (X25519) backends. See [doc/SECURITY.md](doc/SECURITY.md) for the full threat model, key management best practices, and security recommendations.

For post-quantum cryptography considerations, see [doc/post-quantum-readiness.md](doc/post-quantum-readiness.md).

## Limitations

- Not designed for encrypting most or all files in a repository. Best suited for a few sensitive files (keys, credentials) in an otherwise public repo.
- Does not encrypt file names, commit messages, symlink targets, or other metadata.
- Key rotation (`rotate-key`) re-encrypts going forward but does not retroactively protect historical content encrypted with the old key.
- Encrypted files are not compressible by git's delta compression.
- Not compatible with some third-party git GUIs.

See the man page (`git-crypt help`) and [doc/SECURITY.md](doc/SECURITY.md) for full details.

## Documentation

| Document | Description |
|---|---|
| [INSTALL.md](INSTALL.md) | Detailed build and installation instructions |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, code style, and how to contribute |
| [doc/SECURITY.md](doc/SECURITY.md) | Threat model and security best practices |
| [doc/age-migration-guide.md](doc/age-migration-guide.md) | Migrating from GPG to age encryption |
| [doc/post-quantum-readiness.md](doc/post-quantum-readiness.md) | Post-quantum cryptography assessment |
| [doc/multiple_keys.md](doc/multiple_keys.md) | Using multiple named keys |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, testing, and how to submit pull requests.

## License

git-crypt-revived is licensed under the [GNU General Public License v3](COPYING).

Originally written by [Andrew Ayer](https://www.agwa.name) (agwa@andrewayer.name). See [AUTHORS](AUTHORS) and [THANKS.md](THANKS.md) for contributors.
