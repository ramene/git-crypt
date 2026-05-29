# git-crypt-revived: Complete Feature Walkthrough

A comprehensive guide to all enhanced features in git-crypt-revived v0.9.0, covering the credentials workflow, age encryption with YubiKey support, wallet-based identity, Shamir key splitting, cryptographic audit trails, on-chain anchoring, SOPS integration, and the licensing module.

## Prerequisites

Install git-crypt-revived from a binary release:

```bash
# Download for your platform from:
# https://github.com/ramene/git-crypt/releases/tag/v0.9.0
curl -L https://github.com/ramene/git-crypt/releases/download/v0.9.0/git-crypt-v0.9.0-macos-arm64 -o git-crypt
chmod +x git-crypt
sudo mv git-crypt /usr/local/bin/

# Verify
git-crypt version
# → git-crypt 0.9.0
```

Install companion tools:

```bash
# age — modern encryption (required for age/wallet/yubikey features)
brew install age

# age-plugin-yubikey — YubiKey PIV support
brew install age-plugin-yubikey

# Foundry (cast) — blockchain interaction (required for wallet + anchor-audit)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# sops — structured secret encryption (optional, for sops-config)
brew install sops
```

Build the licensing module (optional, for Part 9):

```bash
cd git-crypt
make -f Makefile.license
make -f Makefile.license install PREFIX=/usr/local
git-crypt-license version
```

---

## Part 1: The `.credentials/` Pattern

The `credentials-init` command creates a standardized, pre-encrypted directory for all your secrets.

```bash
# Start a fresh repo
mkdir my-secure-project && cd my-secure-project
git init
git-crypt init

# Add yourself as a recipient first
age-keygen -o ~/.config/age/keys.txt 2>/dev/null || true
AGE_PUB=$(grep "public key:" ~/.config/age/keys.txt | awk '{print $NF}')
git-crypt add-age-recipient "$AGE_PUB"

# Now create the credentials directory
git-crypt credentials-init
```

What this creates:

```
.credentials/
├── .gitattributes          ← Auto-encrypts everything in this dir
├── README.md               ← Not encrypted (excluded in .gitattributes)
├── env.production          ← Template: DATABASE_URL=, SECRET_KEY=, etc.
├── env.staging             ← Template: same vars, staging values
├── api-keys.env            ← Template: STRIPE_KEY=, AWS_SECRET=, etc.
└── certificates/
    └── .gitkeep            ← Drop .pem/.key files here
```

The `.gitattributes` inside `.credentials/` automatically encrypts every file except itself and the README:

```
* filter=git-crypt diff=git-crypt
.gitattributes !filter !diff
README.md !filter !diff
```

With SOPS integration (for partial encryption of YAML/JSON — encrypts values but keeps keys readable):

```bash
git-crypt credentials-init --sops
# Also creates .credentials/.sops.yaml using your existing age recipients
```

Now add your actual secrets:

```bash
cat > .credentials/env.production << 'EOF'
DATABASE_URL=postgres://admin:r3alP4ss@db.prod.example.com:5432/myapp
STRIPE_SECRET_KEY=sk_live_51ABC...
JWT_SECRET=my-super-secret-jwt-signing-key
EOF

cat > .credentials/certificates/deploy.pem << 'EOF'
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
EOF

git add .credentials/
git commit -m "Add encrypted credentials"
```

Verify encryption:

```bash
git-crypt status -e
# .credentials/env.production: encrypted
# .credentials/env.staging: encrypted
# .credentials/api-keys.env: encrypted
# .credentials/certificates/deploy.pem: encrypted
```

---

## Part 2: YubiKey-Backed Encryption

This is the hardware 2FA path. Your YubiKey's PIV slot holds an age identity — the private key never leaves the hardware.

### Step 1: Set up your YubiKey

```bash
# Check that your YubiKey is detected
age-plugin-yubikey --list

# If this is your first time, generate an age identity on the YubiKey PIV slot:
age-plugin-yubikey --generate

# This will output something like:
#   recipient: age1yubikey1q2k8j...
#   identity:  age-plugin-yubikey-1q2k8j...
#
# The RECIPIENT (age1yubikey1...) is the public key — safe to share
# The IDENTITY is stored ON the YubiKey hardware — cannot be extracted
```

### Step 2: Add YubiKey as a git-crypt recipient

```bash
cd my-secure-project

# --yubikey flag auto-discovers all YubiKey identities via the plugin
git-crypt add-age-recipient --yubikey

# Output:
#   Found 1 YubiKey identities:
#     age1yubikey1q2k8j...
#   Adding age1yubikey1q2k8j... to key 'default'...
```

What happened: git-crypt ran `age-plugin-yubikey --list`, parsed the `age1yubikey1...` recipient strings, and wrapped the symmetric key to each one.

### Step 3: Unlock with YubiKey

On a fresh clone (or after `git-crypt lock`):

```bash
git clone https://github.com/YOU/my-secure-project.git fresh-clone
cd fresh-clone

# Unlock — age will automatically invoke age-plugin-yubikey
# Your YubiKey will blink, asking you to touch it
git-crypt unlock --age

# That's it. Touch the YubiKey when it blinks = decrypted.
# No passwords, no key files on disk. Hardware-only.
```

### Troubleshooting YubiKey

```bash
# Verify the plugin is installed and sees your key
age-plugin-yubikey --list
# Should show: age1yubikey1q...

# If the plugin can't find your key:
# - Make sure the YubiKey is inserted
# - Make sure you generated an identity first (--generate)
# - On macOS, you may need: brew install pinentry-mac

# Test age encryption directly (outside git-crypt):
echo "test" | age -r age1yubikey1q2k8j... -o /tmp/test.age
age -d -i age-plugin-yubikey-1q2k8j... /tmp/test.age
# Should output "test" after you touch the YubiKey

# Multiple YubiKeys? add-age-recipient --yubikey adds ALL of them.
# Remove a specific one:
git-crypt rm-age-recipient age1yubikey1q2k8j...
```

---

## Part 3: Wallet-Based Identity (Ethereum)

This is the decentralized identity path. Your Ethereum wallet signature is deterministically derived into an age-compatible X25519 key. No GPG, no age keygen, no key files — just your wallet.

### How It Works Under the Hood

```
Ethereum wallet address (0x...)
    ↓
Sign deterministic challenge: "git-crypt wallet identity for <repo>"
    ↓
Signature bytes (65 bytes)
    ↓
SHA-256("git-crypt-wallet-key-derivation" || sig)
    ↓
SHA-256(result)  ← double-hash for key stretching
    ↓
X25519 clamp (RFC 7748)
    ↓
Bech32 encode → AGE-SECRET-KEY-1...
    ↓
age-keygen -y → age1... (recipient)
```

The same wallet + same repo always produces the same age identity — deterministic and reproducible.

### Step 1: Install Foundry (provides `cast`)

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Verify
cast --version
```

### Step 2: Import or create a wallet in `cast`

```bash
# Import an existing private key (e.g., from MetaMask)
cast wallet import my-wallet --interactive
# Paste your private key when prompted

# Or create a new one
cast wallet new
```

### Step 3: Add wallet recipient

```bash
cd my-secure-project

# YOUR_ADDRESS is your 0x... Ethereum address
git-crypt add-wallet-recipient 0xYOUR_ADDRESS_HERE

# What happens:
# 1. cast signs the challenge message with your wallet
# 2. The signature is double-SHA256'd and clamped to X25519
# 3. The derived age public key wraps the symmetric key
# 4. Wrapped key stored at .git-crypt/keys/default/0/wallet/0xYOUR_ADDRESS.age
# 5. Metadata stored at .git-crypt/keys/default/0/wallet/0xYOUR_ADDRESS.meta
```

### Step 4: Unlock with wallet

```bash
git-crypt unlock --wallet 0xYOUR_ADDRESS_HERE

# cast signs the same challenge → same signature → same age key → decrypt
# Touch YubiKey if your cast wallet is hardware-backed
```

### Configuring the Signer

```bash
# Point to a different signing tool
git config wallet.signer /path/to/signer

# Point to a different age binary
git config age.program /path/to/age
```

---

## Part 4: Cryptographic Audit Trail

Every lock/unlock/add-recipient/rotate operation is logged in a SHA-256 hash-chained append-only log. Each entry references the hash of the previous entry — tampering with any entry breaks the chain.

### Viewing the Audit Log

```bash
git-crypt audit-log

# Output:
# 2026-03-02T14:30:00Z  unlock  age  ramene  default  3 files  a1b2c3d4...
# 2026-03-02T14:35:00Z  lock    age  ramene  default  3 files  e5f6a7b8...
# 2026-03-02T14:40:00Z  add_recipient  age1q...  age  default    c9d0e1f2...

# Show only the last 5 entries
git-crypt audit-log -n 5

# Show and verify in one shot
git-crypt audit-log --verify
# Hash chain: VALID (12 entries)
# [entries listed]
```

### Verifying Chain Integrity

```bash
git-crypt verify-audit

# Output on success:
# Audit log: VALID
# 12 entries verified
# First entry: 2026-03-02T14:30:00Z
# Last entry:  2026-03-02T15:10:00Z
# Exit code: 0

# Output on tampering:
# Audit log: BROKEN at entry 7 of 12
# Tampered entry: 2026-03-02T14:50:00Z
# Exit code: 1
```

### Log Format

Stored at `.git/git-crypt/audit.log`:

```
TIMESTAMP     IDENTITY        IDENTITY_TYPE   OPERATION       KEY_NAME        FILES   PREV_HASH       ENTRY_HASH
```

Each entry's hash = `SHA-256(timestamp + identity + identity_type + operation + key_name + prev_hash)`. The first entry's `prev_hash` is `"0"`.

---

## Part 5: On-Chain Audit Anchoring (BASE Sepolia)

This publishes the SHA3-256 hash of your entire audit log to an Ethereum-compatible chain. It proves your audit log existed in its exact state at a specific point in time — immutable, publicly verifiable.

### Step 1: Configure for BASE Sepolia

```bash
# Set your RPC endpoint and funded address
git config audit.rpc-url https://sepolia.base.org
git config audit.from 0xYOUR_FUNDED_ADDRESS

# Make sure cast knows your wallet
cast wallet import audit-signer --interactive
```

You need a small amount of Sepolia ETH on BASE for gas. Get it from the [BASE Sepolia Faucet](https://www.coinbase.com/faucets/base-ethereum-goerli-faucet).

### Step 2: Anchor

```bash
git-crypt anchor-audit

# What happens:
# 1. Verifies audit chain integrity (refuses if broken)
# 2. Computes SHA3-256 of all entry hashes concatenated
# 3. Sends a self-transfer tx: cast send --rpc-url ... --account FROM FROM 0xSTATE_HASH
# 4. Records tx hash locally in .git/git-crypt/anchors.log
# 5. Logs the anchor operation itself in the audit trail
#
# Output:
# Audit chain: VALID (15 entries)
# State hash: 0xa1b2c3d4e5f6...
# Transaction: 0x7890abcdef12...
# Anchored to BASE Sepolia at block 12345678
```

The tx is a self-transfer (cheapest possible on-chain data storage). The state hash is embedded as calldata. Anyone can verify it on-chain:

```bash
# View the tx on Basescan
open "https://sepolia.basescan.org/tx/0x7890abcdef12..."
# The "Input Data" field contains your audit state hash
```

### Step 3: List previous anchors

```bash
git-crypt anchor-audit --list

# 2026-03-02T15:00:00Z  a1b2c3d4...  0x7890ab...  https://sepolia.base.org  15 entries
# 2026-03-05T10:00:00Z  e5f6a7b8...  0xbcde01...  https://sepolia.base.org  28 entries
```

### Using SKALE Instead

SKALE has zero gas fees — ideal for frequent anchoring:

```bash
git config audit.rpc-url https://mainnet.skalenodes.com/v1/YOUR_SKALE_CHAIN
git config audit.from 0xYOUR_ADDRESS

git-crypt anchor-audit
# Same flow, zero gas cost on SKALE
```

---

## Part 6: Shamir's Secret Sharing (M-of-N Key Splitting)

Split your symmetric key into shares that require a threshold to reconstruct. Information-theoretic security — fewer than M shares reveal zero information about the key.

```bash
# Split into 5 shares, any 3 can reconstruct
git-crypt split-key -n 5 -m 3 -o ~/keyshares/project

# Creates:
#   ~/keyshares/project.1
#   ~/keyshares/project.2
#   ~/keyshares/project.3
#   ~/keyshares/project.4
#   ~/keyshares/project.5

# Distribute to different custodians / storage locations:
#   share.1 → Your password manager
#   share.2 → USB in a fireproof safe
#   share.3 → Trusted colleague
#   share.4 → Bank safety deposit box
#   share.5 → Encrypted cloud backup

# Any 3 shares unlock:
git-crypt unlock --shares ~/keyshares/project.1 ~/keyshares/project.3 ~/keyshares/project.5

# 2 shares? Cryptographically useless. Zero information leakage.
```

---

## Part 7: SOPS Bridge

For structured files (YAML, JSON, ENV) where you want keys visible but values encrypted — useful for config files where you need to see the structure:

```bash
# Generate .sops.yaml using your existing age recipients
git-crypt sops-config

# Or with custom patterns
git-crypt sops-config -p 'config\.ya?ml$' -p '\.env\..+$'

# Now use sops directly on structured files:
sops secrets.yaml
# Opens $EDITOR — values are decrypted for editing, encrypted on save
# Keys (field names) remain in plaintext for readability
```

---

## Part 8: Security Hardening

```bash
# Install pre-commit hook (prevents plaintext leaks)
git-crypt install-hooks

# Verify all commits touching encrypted files are signed
git-crypt verify-commits

# Check for .gitattributes tampering
git-crypt status
# WARNING: file.txt appears encrypted but lacks filter attributes

# Machine-parseable status for CI scripts
git-crypt status -m
# .credentials/env.production encrypted       yes     default
# .credentials/deploy.pem     encrypted       yes     default

# Rotate key after removing a collaborator
git-crypt rm-age-recipient age1old...
git-crypt rotate-key
git-crypt refresh
```

---

## Part 9: Licensing Module

The licensing module provides per-user, per-operation license management with SSH-signed credentials, portable export/import, and optional on-chain anchoring. It ships as a separate binary (`git-crypt-license`) so existing workflows are unaffected.

### Building the license binary

```bash
cd git-crypt
make -f Makefile.license
make -f Makefile.license install PREFIX=/usr/local

# Verify
git-crypt-license version
```

### Initialize licensing in a repository

```bash
cd my-secure-project

git-crypt-license init
# Licensing initialized.
# Issuer fingerprint: SHA256:abc123...
```

This creates `.git-crypt/licenses/` and records your SSH signing key fingerprint as the issuer. Licensing is per-repo — each repository has its own issuer.

### Issue a license

```bash
# Get the recipient's SSH key fingerprint
ssh-keygen -l -f ~/.ssh/id_ed25519.pub | awk '{print $2}'
# SHA256:xyz789...

# Issue a license valid for 90 days, all operations
git-crypt-license issue --to SHA256:xyz789... --scope "*" --expires 90d
# License issued: a1b2c3d4e5f6a7b8
#   To:       SHA256:xyz789...
#   Scope:    *
#   Expires:  2026-06-01T14:30:00Z

# Issue a license scoped to specific operations
git-crypt-license issue --to SHA256:xyz789... --scope "unlock,status" --expires 1y

# Include a wallet address for on-chain features
git-crypt-license issue --to SHA256:xyz789... --wallet 0xABC... --scope "*" --expires 90d
```

Duration formats: `90d` (days), `12w` (weeks), `6m` (months), `1y` (years), or an ISO 8601 date like `2027-01-01T00:00:00Z`.

### Manage licenses

```bash
# List active licenses
git-crypt-license list
# a1b2c3d4e5f6a7b8  SHA256:xyz789...  *  2026-06-01T14:30:00Z  active

# List all licenses including revoked and expired
git-crypt-license list --all

# JSON output (for x402 integration)
git-crypt-license list --json

# Show full license details
git-crypt-license show a1b2c3d4e5f6a7b8
# License ID:    a1b2c3d4e5f6a7b8
# Fingerprint:   SHA256:xyz789...
# Scope:         *
# Issued:        2026-03-02T14:30:00Z
# Expires:       2026-06-01T14:30:00Z
# Status:        active
# Signatures:    valid

# Verify signatures and validity
git-crypt-license verify a1b2c3d4e5f6a7b8
# License:     a1b2c3d4e5f6a7b8
# Status:      active
# Valid:       yes
# Signatures:  verified
```

### Export and import

Licenses are portable — export from one repo and import into another:

```bash
# Export to a file (default: <id>.license)
git-crypt-license export a1b2c3d4e5f6a7b8
# License exported to a1b2c3d4e5f6a7b8.license

# Export to a custom filename
git-crypt-license export a1b2c3d4e5f6a7b8 ~/licenses/project.license

# Import into another repository
cd /other/repo
git-crypt-license init
git-crypt-license import ~/licenses/a1b2c3d4e5f6a7b8.license
# License imported: a1b2c3d4e5f6a7b8
```

### License checks (gating)

The `check` command verifies the current user has a valid license for an operation:

```bash
# Check if you can unlock
git-crypt-license check --operation unlock
# License valid for operation: unlock  (exit 0)

# Check wildcard (any operation)
git-crypt-license check
# License valid for operation: *  (exit 0)
```

**Backward compatibility**: If licensing is not initialized in a repository (no `.git-crypt/licenses/issuer.txt`), `check` always returns exit 0. Existing repos without licensing are completely unaffected.

### Revocation

```bash
# Revoke a license
git-crypt-license revoke a1b2c3d4e5f6a7b8
# License a1b2c3d4e5f6a7b8 revoked.

# Verify: check now fails
git-crypt-license check --operation unlock
# No valid license for operation: unlock  (exit 1)

# Revoked licenses are hidden from list but visible with --all
git-crypt-license list         # empty
git-crypt-license list --all   # shows revoked license

# Anchor revocation on-chain (requires cast + funded wallet)
git-crypt-license revoke a1b2c3d4e5f6a7b8 --anchor \
    --rpc-url https://sepolia.base.org \
    --from 0xYOUR_ADDRESS
```

### On-chain anchoring

Anchor a license hash to a blockchain for immutable proof of issuance:

```bash
git-crypt-license anchor a1b2c3d4e5f6a7b8 \
    --rpc-url https://sepolia.base.org \
    --from 0xYOUR_ADDRESS
# License hash:  e5f6a7b8c9d0...
# Anchoring to:  https://sepolia.base.org
# From:          0xYOUR_ADDRESS
# Transaction:   0x1234abcd...
# Anchor published successfully.

# Verify the anchor
git-crypt-license verify a1b2c3d4e5f6a7b8 --onchain
# On-chain:    confirmed
# Tx hash:     0x1234abcd...
```

### x402 License Server

The licensing module includes an HTTP server implementing the x402 payment protocol for automated license issuance:

```bash
# Start the server
git-crypt-license serve --port 8402 --rpc-url https://sepolia.base.org

# Endpoints:
#   GET  /health    → 200 OK
#   GET  /verify    → 402 Payment Required (or 200 if licensed)
#   GET  /licenses  → JSON list of licenses
#   POST /issue     → Issue license after payment confirmation
```

See the [.onboarding](https://github.com/ramene/git-crypt-onboarding) repo for a hands-on walkthrough and automated E2E test harness (`test-licensing.sh`).

---

## Full Lifecycle Example

```bash
# === SETUP ===
mkdir vault && cd vault && git init
git-crypt init
git-crypt credentials-init --sops
git-crypt add-age-recipient --yubikey           # hardware key
git-crypt add-wallet-recipient 0xABC...         # wallet identity
git-crypt install-hooks

# === WORK ===
echo "SECRET=hunter2" > .credentials/env.production
git add . && git commit -m "Add production secrets"
git remote add origin https://github.com/YOU/vault.git
git push -u origin master

# === BACKUP ===
git-crypt split-key -n 5 -m 3 -o ~/safe/vault-key
git-crypt export-key ~/safe/vault-master.key

# === AUDIT ===
git-crypt audit-log --verify
git config audit.rpc-url https://sepolia.base.org
git config audit.from 0xYOUR_ADDRESS
git-crypt anchor-audit

# === COLLABORATOR LIFECYCLE ===
git-crypt add-age-recipient age1newperson...
# ... later ...
git-crypt rm-age-recipient age1newperson...
git-crypt rotate-key
git-crypt refresh
git-crypt anchor-audit    # anchor the rotation event

# === LICENSING ===
git-crypt-license init
git-crypt-license issue --to SHA256:abc... --scope "*" --expires 90d
git-crypt-license check --operation unlock   # gate operations
git-crypt-license anchor LICENSE_ID --rpc-url https://sepolia.base.org --from 0xABC...
```
