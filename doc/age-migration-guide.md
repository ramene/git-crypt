# Migrating from GPG to age Encryption

> **DRAFT -- This feature is not yet implemented.** This document describes the planned age encryption support for git-crypt-revived. The commands and workflows below do not exist yet and are subject to change.

## Why Migrate from GPG to age?

[age](https://age-encryption.org/) is a modern file encryption tool designed as a simpler replacement for GPG. Key advantages for git-crypt users:

- **Simplicity**: No keyrings, trust models, or configuration files. A single key pair is all you need.
- **SSH key reuse**: age supports encrypting to existing SSH keys (`ssh-ed25519` and `ssh-rsa`), so collaborators don't need to manage a separate GPG identity.
- **Small keys**: age keys are short and easy to share (a single line of text).
- **No key server dependency**: No reliance on the PGP Web of Trust or key server infrastructure.
- **Auditable**: age has a simple, well-documented file format designed for modern cryptographic review.

## Planned Workflow

### Adding an age Recipient

```bash
# Add a collaborator by their age public key
git-crypt add-age-user age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

# Add a collaborator by their SSH public key
git-crypt add-age-user ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host

# Add from a public key file
git-crypt add-age-user --key-file /path/to/recipient.pub

# Add to a named key (multi-key setup)
git-crypt add-age-user -k staging age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
```

### Unlocking with age

```bash
# Unlock using the default age identity (~/.config/age/keys.txt)
git-crypt unlock --age

# Unlock using an SSH private key
git-crypt unlock --age --identity ~/.ssh/id_ed25519

# Unlock using a specific age identity file
git-crypt unlock --age --identity /path/to/age-key.txt
```

### How It Will Work

1. **Key wrapping**: The repository's symmetric AES-256 key is encrypted (wrapped) to each age recipient, similar to how it currently works with GPG. Wrapped keys are stored in `.git-crypt/keys/default/0/age/` alongside the existing GPG-wrapped keys.

2. **SSH key support**: When an SSH public key is provided, age encrypts the symmetric key using the corresponding age-compatible algorithm. `ssh-ed25519` keys are converted to X25519 for encryption. `ssh-rsa` keys use RSA-OAEP.

3. **Coexistence with GPG**: age and GPG recipients can coexist on the same repository. A user only needs one method to unlock.

4. **Identity resolution**: On `unlock --age`, git-crypt will search for age identities in this order:
   - `--identity` flag (if provided)
   - `$AGE_IDENTITY` environment variable
   - `~/.config/age/keys.txt` (default age key location)
   - SSH agent keys (via `ssh-agent`)

## Migration Steps (Planned)

For an existing repository using GPG-only encryption:

```bash
# Step 1: Ensure the repo is unlocked
git-crypt unlock

# Step 2: Add age recipients for each collaborator
git-crypt add-age-user age1...  # Alice's age key
git-crypt add-age-user ssh-ed25519 AAAA...  # Bob's SSH key

# Step 3: Collaborators can now unlock with age
git-crypt unlock --age

# Step 4 (optional): Remove GPG recipients if no longer needed
git-crypt rm-gpg-user alice@example.com
```

Existing GPG users can continue to unlock with GPG. Migration can be incremental -- there is no requirement to switch all users at once.

## age Key Management

### Generating an age Key Pair

```bash
# Install age
brew install age        # macOS
apt install age         # Debian/Ubuntu

# Generate a new key pair
age-keygen -o ~/.config/age/keys.txt
# Public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
```

### Using Existing SSH Keys

No additional key generation is needed. Share your existing SSH public key:

```bash
cat ~/.ssh/id_ed25519.pub
# ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host
```

The repository administrator uses this public key with `add-age-user`.

## Security Considerations

- age uses modern, well-audited cryptographic primitives (X25519, ChaCha20-Poly1305).
- SSH key support means users can leverage existing key management infrastructure and hardware tokens (e.g., FIDO2 keys for SSH).
- The underlying repository encryption (AES-256-CTR with HMAC-SHA1 synthetic IV) remains unchanged. Only the key wrapping layer changes.
- As with GPG mode, revoking access requires re-keying (a limitation of the symmetric key design).

## Status

This feature is tracked on the [project board](https://github.com/users/ramene/projects/8). Contributions and feedback are welcome via GitHub issues.
