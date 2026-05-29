# git-crypt-trustless: Complete Guide

Trustless license verification via EVM smart contracts for git-crypt-revived.

## Table of Contents

1. [Overview and Architecture](#1-overview-and-architecture)
2. [Prerequisites and Installation](#2-prerequisites-and-installation)
3. [Quick Start with Local Anvil](#3-quick-start-with-local-anvil)
4. [Smart Contracts Deep Dive](#4-smart-contracts-deep-dive)
5. [Merkle Audit Trail](#5-merkle-audit-trail)
6. [Zero-Knowledge Proofs (Phase 2)](#6-zero-knowledge-proofs-phase-2)
7. [Private Chain Deployment](#7-private-chain-deployment)
8. [Migration from git-crypt-license](#8-migration-from-git-crypt-license)
9. [CLI Reference](#9-cli-reference)
10. [E2E Testing](#10-e2e-testing)

---

## 1. Overview and Architecture

### Trust-Based vs Trustless

| Property | git-crypt-license (trust-based) | git-crypt-trustless |
|----------|--------------------------------|---------------------|
| **Authority** | Repo owner is sole authority | Smart contract is source of truth |
| **Verification** | Check local files + signatures | Query on-chain state (multi-RPC) |
| **Audit trail** | Linear hash chain (tamper-evident) | Merkle tree with on-chain root (tamper-proof) |
| **Privacy** | Plaintext fingerprints in files | Keccak256 hashes on-chain |
| **Revocation** | Owner edits local file | On-chain transaction (immutable record) |
| **Trust model** | Trust the repo owner | Trust the smart contract (code is law) |

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    git-crypt-trustless                       │
│                    (C++ CLI binary)                          │
├─────────────┬──────────────┬────────────┬──────────────────┤
│ Config      │ Chain        │ Merkle     │ RPC Consensus    │
│ (git config │ (cast calls) │ (local     │ (M-of-N          │
│  + env vars)│              │  tree)     │  agreement)      │
└──────┬──────┴──────┬───────┴─────┬──────┴────────┬─────────┘
       │             │             │               │
       │        ┌────▼────┐  ┌────▼────┐     ┌────▼────┐
       │        │  cast   │  │ .dat    │     │ RPC 1   │
       │        │  send/  │  │ file    │     │ RPC 2   │
       │        │  call   │  │ (local) │     │ RPC 3   │
       │        └────┬────┘  └─────────┘     └────┬────┘
       │             │                            │
  ┌────▼─────────────▼────────────────────────────▼────┐
  │              EVM Chain (any)                         │
  │  ┌──────────────────┐  ┌──────────────────┐        │
  │  │ LicenseRegistry  │  │  MerkleAudit     │        │
  │  │ (source of truth)│  │  (root commits)  │        │
  │  └──────────────────┘  └──────────────────┘        │
  └────────────────────────────────────────────────────┘
```

### Key Design Decisions

- **keccak256 hashes for privacy**: Licensee fingerprints and scopes stored as hashes, not plaintext. Verifiable by parties who know the original value.
- **bytes16 for license IDs**: Maps directly to existing 16-hex-char format.
- **View functions are free**: No gas cost for reads (verify, show, list).
- **Multi-RPC consensus**: Query N endpoints, require M agreement. Protects against compromised nodes.
- **Merkle tree for audit**: O(log n) proof size, selective disclosure, on-chain root anchoring.

---

## 2. Prerequisites and Installation

### Required Tools

| Tool | Purpose | Install |
|------|---------|---------|
| **Foundry** | Smart contract development, `cast` CLI | `curl -L https://foundry.paradigm.xyz \| bash && foundryup` |
| **OpenSSL** | Cryptographic operations | System package manager |
| **C++11 compiler** | Build git-crypt-trustless | `gcc` or `clang` |
| **GNU Make** | Build system | System package manager |

### Optional Tools (Phase 2)

| Tool | Purpose | Install |
|------|---------|---------|
| **circom** | ZK circuit compiler | `npm install -g circom` |
| **snarkjs** | ZK proof generation | `npm install -g snarkjs` |

### Build

```bash
# Build the binary
make -f Makefile.trustless

# Run C++ tests
make -f Makefile.trustless test

# Run contract tests
make -f Makefile.trustless test-contracts

# Install
make -f Makefile.trustless install PREFIX=/usr/local
```

---

## 3. Quick Start with Local Anvil

```bash
# 1. Start local chain
anvil &

# 2. Deploy contracts
export GIT_CRYPT_TRUSTLESS_PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
git-crypt-trustless init --rpc-url http://127.0.0.1:8545 --deploy --chain-id 31337

# 3. Issue a license
git-crypt-trustless issue \
    --to "SHA256:your-ssh-fingerprint" \
    --scope "unlock,lock" \
    --expires "90d"

# 4. Verify it
git-crypt-trustless verify <LICENSE_ID>

# 5. Commit audit root
git-crypt-trustless audit-root

# 6. Generate and verify Merkle proof
git-crypt-trustless audit-prove --entry 0 --output proof.json
git-crypt-trustless audit-verify --proof proof.json

# 7. Check configuration
git-crypt-trustless config

# 8. Kill Anvil when done
kill %1
```

---

## 4. Smart Contracts Deep Dive

### LicenseRegistry.sol

The canonical source of truth for license state.

**Data Structure**:
```solidity
struct OnChainLicense {
    bytes16  id;             // 16 hex chars packed
    bytes32  licenseeHash;   // keccak256(fingerprint)
    address  licenseeWallet; // Ethereum address
    bytes32  scopeHash;      // keccak256(scope_string)
    uint64   issuedAt;       // Unix timestamp
    uint64   expiresAt;      // Unix timestamp
    uint8    status;         // 0=active, 1=revoked
    bytes32  contentHash;    // SHA-256 of full license
}
```

**Gas Costs** (approximate):
| Operation | Gas | Mainnet (~$4/op) | L2 (~$0.01/op) | Private Chain |
|-----------|-----|-------------------|-----------------|---------------|
| `issue()` | ~60K | ~$4 | ~$0.01 | Free |
| `revoke()` | ~20K | ~$1.50 | ~$0.005 | Free |
| `verify()` | 0 (view) | Free | Free | Free |
| `getLicense()` | 0 (view) | Free | Free | Free |

**Access Control**:
- `owner`: Can add/remove issuers
- `issuers`: Can issue and revoke licenses
- Anyone: Can read/verify

### MerkleAudit.sol

On-chain Merkle root commitments for tamper-proof audit trails.

**Key insight**: Only the 32-byte root is stored on-chain. The full tree is maintained locally. Any entry can be independently proven with O(log n) sibling hashes.

---

## 5. Merkle Audit Trail

### Why Merkle Trees (vs Linear Hash Chain)

| Property | Linear Hash Chain | Merkle Tree |
|----------|-------------------|-------------|
| **Proof size** | O(n) | O(log n) |
| **Selective disclosure** | Must reveal all preceding | Prove one entry alone |
| **On-chain cost** | Push full state hash | Push single 32-byte root |
| **Corruption impact** | Everything after | Only affected subtree |

### How It Works

1. Each license operation (issue, revoke) appends a leaf hash to the local Merkle tree
2. The tree is rebuilt (O(n log n))
3. The root is committed on-chain via `MerkleAudit.commitRoot()`
4. Any entry can later be independently verified against the on-chain root

### Proof Verification

For a tree with 8 leaves, proving leaf 5:
```
          root
         /    \
       H01      H23
      /   \    /   \
    H0  H1  H2  H3
   / \ / \ / \ / \
  L0 L1 L2 L3 L4 L5 L6 L7
```
Proof = [L4, H3, H01]. Three hashes instead of eight.

### Storage

- **Local**: `.git-crypt/trustless/merkle.dat` — binary file `[4-byte leaf_count][32-byte hashes...]`
- **On-chain**: Array of `RootCommitment{root, timestamp, leafCount, committer}`

---

## 6. Zero-Knowledge Proofs (Phase 2)

> **Note**: ZK proofs are designed but not implemented in v0.1.0. This section documents the planned architecture.

### Purpose

Prove "I have a valid license for operation X" without revealing:
- Which license ID
- Who it was issued to
- When it expires

### Circuit Design

**Public inputs** (known to verifier):
1. `scopeHash` — Poseidon hash of requested operation
2. `currentTimestamp` — Unix timestamp
3. `contractRoot` — Merkle root of on-chain licenses

**Private witness** (known only to prover):
1. License fields (id, fingerprint, scope, timestamps, status)
2. Merkle inclusion proof (path + indices)

**Constraints**:
1. License is active (status === 0)
2. Not expired (expiresAt > currentTimestamp)
3. Already issued (issuedAt <= currentTimestamp)
4. Scope matches (Poseidon(scope) === scopeHash)
5. On-chain inclusion (Merkle proof validates against contractRoot)

### Setup

```bash
cd circuits
npm install circomlib
bash setup.sh
```

### Groth16 vs PLONK

| Factor | Groth16 (v1) | PLONK (future) |
|--------|-------------|----------------|
| Proof size | 128 bytes | ~800 bytes |
| Prover time | 2-5 seconds | 5-15 seconds |
| Verification gas | ~200K | ~300K |
| Setup | Per-circuit | Universal |

---

## 7. Private Chain Deployment

### Configuration

```bash
# Git config (persistent per-repo)
git config trustless.rpc-url "http://your-rpc:8545"
git config trustless.chain-id "12345"
git config trustless.registry-address "0x..."
git config trustless.audit-address "0x..."
git config trustless.from-address "0x..."

# Environment overrides (higher precedence)
export GIT_CRYPT_TRUSTLESS_RPC_URL="http://your-rpc:8545"
export GIT_CRYPT_TRUSTLESS_PRIVATE_KEY="0x..."
```

### Multi-RPC Consensus

```bash
git config trustless.rpc-urls "http://rpc1:8545,http://rpc2:8545,http://rpc3:8545"
git config trustless.rpc-threshold "2"  # 2/3 must agree
```

Queries all RPCs, requires M/N agreement. Disagreements logged to stderr.

### Deployment Targets

| Target | Gas Cost | Use Case |
|--------|----------|----------|
| **Anvil** | Free | Local development/testing |
| **Besu/Quorum** | Free | Corporate/private chains |
| **Arbitrum/Base/Optimism** | ~$0.01/op | Public L2 |
| **Ethereum mainnet** | ~$4/issue | High-value use cases |

### Deploy to Any Chain

```bash
# Using the binary
export GIT_CRYPT_TRUSTLESS_PRIVATE_KEY="0x..."
git-crypt-trustless deploy --rpc-url http://your-chain:8545

# Using the shell script
cd contracts
RPC_URL="http://your-chain:8545" PRIVATE_KEY="0x..." bash deploy.sh
```

---

## 8. Migration from git-crypt-license

### Check Migration Candidates

```bash
git-crypt-trustless migrate --dry-run --all
```

### Migrate All Licenses

```bash
git-crypt-trustless migrate --all
```

### Migrate a Single License

```bash
git-crypt-trustless migrate --id <LICENSE_ID>
```

### What Happens During Migration

1. Load license from `.git-crypt/licenses/<id>/`
2. Compute keccak256 hashes for fingerprint and scope
3. Call `issue()` on the LicenseRegistry contract
4. If the original license was revoked, call `revoke()` on-chain too

---

## 9. CLI Reference

| Command | Description | On-chain? |
|---------|-------------|-----------|
| `init` | Connect to existing contracts or deploy new ones | Deploy tx |
| `deploy` | Deploy fresh contracts to configured RPC | Deploy tx |
| `issue --to FP --scope OPS --expires DUR` | Issue license on-chain | Write tx |
| `verify ID` | Verify from contract (multi-RPC) | Read (free) |
| `revoke ID` | Revoke on-chain | Write tx |
| `list [--all] [--json]` | List from contract | Read (free) |
| `show ID` | Show from contract | Read (free) |
| `check [--operation OP]` | Check current user's license | Read (free) |
| `export ID [FILE]` | Export from on-chain to file | Read (free) |
| `import FILE` | Import file, register on-chain | Write tx |
| `migrate [--all]` | Migrate git-crypt-license data | Write txs |
| `prove` | Generate ZK proof (Phase 2) | Local |
| `verify-proof` | Verify ZK proof (Phase 2) | Read (free) |
| `audit-root` | Commit Merkle root on-chain | Write tx |
| `audit-prove --entry N` | Generate Merkle proof | Local |
| `audit-verify --proof FILE` | Verify Merkle proof | Read (free) |
| `config` | Show configuration | Local |
| `serve --port PORT` | HTTP server | N/A |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `GIT_CRYPT_TRUSTLESS_RPC_URL` | Primary RPC endpoint |
| `GIT_CRYPT_TRUSTLESS_RPC_URLS` | Comma-separated multi-RPC endpoints |
| `GIT_CRYPT_TRUSTLESS_RPC_THRESHOLD` | M-of-N consensus threshold |
| `GIT_CRYPT_TRUSTLESS_CHAIN_ID` | EVM chain ID |
| `GIT_CRYPT_TRUSTLESS_REGISTRY_ADDRESS` | LicenseRegistry contract address |
| `GIT_CRYPT_TRUSTLESS_AUDIT_ADDRESS` | MerkleAudit contract address |
| `GIT_CRYPT_TRUSTLESS_FROM_ADDRESS` | Sender address |
| `GIT_CRYPT_TRUSTLESS_PRIVATE_KEY` | Private key (env only, never in git config) |

---

## 10. E2E Testing

### Run All Tests

```bash
# C++ unit tests (config, Merkle tree)
make -f Makefile.trustless test

# Solidity contract tests
make -f Makefile.trustless test-contracts

# Full E2E (starts Anvil, deploys, runs all commands)
make -f Makefile.trustless test-e2e

# Everything combined
make -f Makefile.trustless test-all
```

### E2E Test Sequence (18 tests)

1. Start Anvil, deploy contracts
2. `init` — connects to contracts
3. `config` — shows configuration
4. `issue` — license appears on-chain
5. `verify` — reads from contract
6. `list` — shows issued license
7. `show` — displays details
8. `check --operation unlock` — passes
9. `export` — writes .license file
10. `import` — registers on-chain
11. `audit-root` — commits Merkle root
12. `audit-prove --entry 0` — generates proof
13. `audit-verify` — validates against root
14. `revoke` — revokes on-chain
15. `verify` after revoke — returns 1
16. `check` after revoke — fails
17. `list --all` — shows revoked
18. Server smoke test — /health returns 200
