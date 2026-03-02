# Post-Quantum Cryptography Readiness Assessment

## Executive Summary

git-crypt-revived's symmetric encryption core (AES-256-CTR) is already
quantum-resistant per NIST guidance.  The primary exposure is in the
asymmetric key-wrapping layer (GPG/age), where RSA and curve25519 keys
are vulnerable to Shor's algorithm on a cryptographically relevant
quantum computer (CRQC).  This document catalogs every cryptographic
primitive, assesses its post-quantum security, and outlines a concrete
migration path.

## Current Cryptographic Inventory

### Symmetric Primitives (Internal — crypto.cpp)

| Primitive | Usage | Key Size | PQ Security | Notes |
|-----------|-------|----------|-------------|-------|
| AES-256-CTR | File encryption (clean filter) | 256-bit | **Safe** | Grover's reduces effective security to 128-bit — still adequate |
| HMAC-SHA-1 | Synthetic IV derivation | 512-bit key, 160-bit output | **Safe** | Used as PRF for nonce, not as collision-resistant hash |
| SHA-256 | Age recipient identifier hashing | — | **Safe** | Preimage resistance ~128-bit post-quantum |
| CSPRNG | Key generation (OpenSSL RAND_bytes) | — | **Safe** | OS entropy; no asymmetric component |

**Assessment**: The symmetric layer requires **no changes** for
post-quantum readiness.  AES-256 with 128-bit post-quantum security
exceeds all foreseeable quantum attack capabilities.

### Asymmetric Primitives (External — GPG/age wrappers)

| Primitive | Usage | PQ Security | Vulnerability |
|-----------|-------|-------------|---------------|
| RSA (GPG) | Key wrapping for GPG users | **Vulnerable** | Shor's algorithm factors RSA in polynomial time |
| ECDH/EdDSA (GPG) | Key wrapping for GPG ECC keys | **Vulnerable** | Shor's solves ECDLP in polynomial time |
| X25519 (age) | Key wrapping for age recipients | **Vulnerable** | Shor's solves ECDLP in polynomial time |
| Ed25519 (SSH keys via age) | Key wrapping for SSH key recipients | **Vulnerable** | Same as above |

**Assessment**: All asymmetric key-wrapping is vulnerable.  However,
git-crypt delegates this entirely to external tools (gpg, age binaries),
so the migration path is to adopt PQ-safe versions of those tools.

### Shamir Secret Sharing (Internal — shamir.cpp)

| Primitive | Usage | PQ Security | Notes |
|-----------|-------|-------------|-------|
| GF(256) polynomial evaluation | Key splitting/combining | **Safe** | Information-theoretic security; no computational assumptions |

**Assessment**: Shamir's Secret Sharing is unconditionally secure
(information-theoretic), not dependent on any computational hardness
assumption.  **No changes needed.**

## Threat Model

### Harvest Now, Decrypt Later (HNDL)

The primary quantum threat to git-crypt users is the "harvest now,
decrypt later" scenario:

1. An adversary captures `.gpg` or `.age` wrapped key files from a
   repository's `.git-crypt/keys/` directory
2. Years later, a CRQC becomes available
3. The adversary unwraps the symmetric key using quantum factoring/ECDLP
4. All encrypted files (past and present) are decryptable

**Mitigation**: The symmetric key itself (AES-256) remains safe.  The
risk is entirely in the asymmetric wrapper protecting that symmetric key.

### Attack Surface Analysis

```
Repository Contents
├── .git-crypt/keys/<name>/<ver>/*.gpg   ← RSA/ECC wrapped (VULNERABLE)
├── .git-crypt/keys/<name>/<ver>/*.age   ← X25519 wrapped (VULNERABLE)
├── Encrypted file blobs                 ← AES-256-CTR (SAFE)
└── HMAC-derived nonces                  ← HMAC-SHA1 (SAFE)
```

## Migration Strategy

### Phase 1: Monitor and Prepare (Now → NIST PQC standardization)

**Status**: NIST has finalized ML-KEM (FIPS 203), ML-DSA (FIPS 204),
and SLH-DSA (FIPS 205) as post-quantum standards.

**Actions**:
- [x] Document current cryptographic inventory (this document)
- [ ] Track GPG post-quantum support (GnuPG project PQC roadmap)
- [ ] Track age post-quantum support (filippo.io/age PQC discussion)
- [ ] Track OpenSSL 3.x PQC provider support for ML-KEM

### Phase 2: Hybrid Key Wrapping (When tools support PQC)

The recommended approach is **hybrid encryption**: combine a classical
algorithm with a post-quantum algorithm so that security degrades
gracefully if either is broken.

**For GPG users**:
- GnuPG will need to support ML-KEM + X25519 hybrid key encapsulation
- git-crypt requires no code changes — it shells out to `gpg`
- Users re-run `add-gpg-user` with their new PQ-hybrid GPG key

**For age users**:
- The age project is expected to add a PQ-safe recipient type
  (likely ML-KEM-768 hybrid with X25519, similar to the `age-plugin-sntrup761` plugin)
- git-crypt requires no code changes — it shells out to `age`
- Users re-run `add-age-recipient` with their new PQ recipient string

**For SSH key users**:
- OpenSSH 9.x already supports `sntrup761x25519-sha512` hybrid key exchange
- When age supports PQ SSH key types, git-crypt inherits this via `--ssh`

### Phase 3: Key Rotation (After PQC tools are deployed)

Once users have PQ-safe keys:

1. `git-crypt rotate-key` — generates a new symmetric key version
2. `git-crypt add-gpg-user` / `add-age-recipient` — wraps new version
   with PQ-safe keys
3. Old `.gpg`/`.age` files in the repository history remain vulnerable
   to HNDL attacks on past key versions, but the current key version
   is PQ-safe going forward

### Phase 4: Full PQC (Long-term)

If SHA-1 deprecation becomes a concern (unlikely for HMAC usage):
- Replace HMAC-SHA-1 with HMAC-SHA-256 or KMAC-256
- This would require a key file format version bump (currently v2)
- AES-256 key and nonce derivation would need matching updates

## Code Change Requirements

### No Changes Needed
- `crypto.cpp` / `crypto-openssl-11.cpp` — AES-256-CTR is PQ-safe
- `shamir.cpp` — Information-theoretic security
- `key.cpp` — Symmetric key format is PQ-safe
- `commands.cpp` clean/smudge filters — Uses only symmetric primitives

### Changes When External Tools Are Ready
- `gpg.cpp` — No code changes; GPG binary handles PQC transparently
- `age.cpp` — No code changes; age binary handles PQC transparently
- Help text updates to mention PQ key types

### Optional Future Improvements
- Add `--pq-check` flag to `status` command to warn about non-PQ key wrappings
- Add key wrapping algorithm metadata to the share file format
- Consider HMAC-SHA-256 upgrade path for new key format version

## NIST PQC Standards Reference

| Standard | Algorithm | Type | Use Case |
|----------|-----------|------|----------|
| FIPS 203 | ML-KEM (Kyber) | KEM | Key encapsulation (replaces RSA/ECDH key exchange) |
| FIPS 204 | ML-DSA (Dilithium) | Signature | Digital signatures (replaces RSA/ECDSA signing) |
| FIPS 205 | SLH-DSA (SPHINCS+) | Signature | Stateless hash-based signatures (conservative alternative) |

## Timeline Estimates

| Milestone | Estimated Date | Dependency |
|-----------|---------------|------------|
| NIST PQC final standards | 2024 (done) | — |
| OpenSSL 3.x ML-KEM provider | 2025-2026 | OpenSSL project |
| GnuPG PQC key support | 2026-2027 | GnuPG project |
| age PQC recipient type | 2026-2027 | filippo.io/age |
| git-crypt help text updates | After tool support | This project |
| Optional --pq-check flag | After tool support | This project |

## Recommendations

1. **No immediate action required** — the symmetric core is PQ-safe
2. **Monitor upstream** — GPG, age, and OpenSSL PQC development
3. **Encourage key rotation** when PQ-safe key types become available
4. **Document for users** that HNDL risk applies to wrapped keys in
   repository history
5. **Consider hybrid wrapping** as the default recommendation once
   tools support it, rather than pure-PQ algorithms
