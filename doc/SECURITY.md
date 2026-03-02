# git-crypt Security Model and Threat Analysis

## Overview

git-crypt provides **transparent file-level encryption** for Git repositories. It uses Git's clean/smudge filter mechanism to automatically encrypt files when they are committed and decrypt them when they are checked out.

**Core design goal**: Protect sensitive files at rest on remote Git servers, while remaining transparent to developers with access to the key.

## What git-crypt Protects Against

### Data at Rest on Remote Servers
git-crypt encrypts file contents before they are pushed to remote repositories. An attacker who gains read access to the remote server (e.g., a compromised GitHub/GitLab account, stolen backup, or breached CI system) will see only encrypted blobs for protected files.

- **Encryption**: AES-256-CTR with HMAC-SHA1 derived synthetic IV
- **Key wrapping**: Symmetric keys can be wrapped per-user via GPG or age
- **Scope**: File contents only; filenames, directory structure, file sizes, and commit metadata are NOT encrypted

### Passive Network Observers
Since encryption happens before data leaves the local machine, network eavesdroppers observing Git push/fetch traffic cannot read encrypted file contents (in addition to TLS transport encryption).

### Unauthorized Server Administrators
Hosting provider employees or compromised CI/CD systems that can read the bare repository cannot decrypt protected files without the symmetric key.

## What git-crypt Does NOT Protect Against

### Malicious Collaborators with Commit Access
A collaborator who has been granted the decryption key (via GPG, age, or symmetric key) has full access to encrypted content. Additionally:

- They can **modify encrypted files** and push changes
- They can **modify `.gitattributes`** to remove encryption attributes, causing future edits to be committed in plaintext (mitigated by the tamper detection in `git-crypt status`)
- They can **exfiltrate** decrypted content through unencrypted files, commit messages, branch names, or other metadata

### Key Compromise
If the symmetric key is leaked, all past and future encrypted content is compromised. git-crypt does not provide forward secrecy — a single key encrypts all versions of all files associated with that key name.

**Mitigation**: Use `git-crypt rotate-key` to generate a new key version. Note that historical content encrypted with the old key remains vulnerable if the old key was compromised.

### Metadata Leakage
git-crypt does **not** encrypt:
- **Filenames and paths**: An attacker can see which files exist and their names
- **File sizes**: Encrypted file sizes correlate to plaintext sizes (plus a small constant header overhead)
- **Commit messages**: All commit metadata is in plaintext
- **Directory structure**: The repository layout is fully visible
- **Commit timestamps and authors**: All Git metadata is unencrypted
- **Diff patterns**: The number and timing of changes to encrypted files are visible

### Repository History
Encrypted files that were **ever committed in plaintext** (before `.gitattributes` was configured) remain in plaintext in the Git history. Use `git-crypt status -f` to detect and fix these, but note that `git filter-branch` or `BFG Repo-Cleaner` may be needed to fully remove plaintext from history.

### Local Machine Compromise
When files are checked out (decrypted), they exist in plaintext on the local filesystem. An attacker with access to a developer's machine can read decrypted files directly.

## Threat Models

### 1. Passive Observer (Low Threat)
**Scenario**: Attacker can read the remote repository but cannot modify it.
**Protection level**: **Strong**. Encrypted files are protected by AES-256-CTR.
**Residual risk**: Metadata leakage (filenames, sizes, structure).

### 2. Compromised Remote / Stolen Backup (Medium Threat)
**Scenario**: Attacker obtains a copy of the bare repository.
**Protection level**: **Strong** for file contents. Equivalent to Passive Observer.
**Residual risk**: Same metadata leakage. Attacker can also see all branch names and tags.

### 3. Malicious Collaborator (High Threat)
**Scenario**: A person with legitimate repository access and decryption keys acts maliciously.
**Protection level**: **Limited**. git-crypt cannot prevent a keyholder from exfiltrating data.
**Mitigations**:
- `git-crypt verify-commits` detects unsigned commits that modified encrypted files
- `git-crypt status` detects `.gitattributes` tampering (encrypted blobs with missing filter attributes)
- Pre-commit hook prevents accidental plaintext commits
- GPG/age key wrapping allows per-user access revocation (via `rm-gpg-user`)
- `git-crypt rotate-key` allows key rotation after revoking a user
- Code review and branch protection rules are the primary defense

### 4. Supply Chain Attack (High Threat)
**Scenario**: Attacker compromises the git-crypt binary or its dependencies.
**Protection level**: **None** if the binary is compromised.
**Mitigations**:
- Verify git-crypt binary integrity (GPG-signed releases when available)
- Use package manager versions from trusted sources
- Pin dependencies and audit OpenSSL version

### 5. Targeted Key Extraction (Critical Threat)
**Scenario**: Attacker specifically targets the symmetric key file.
**Protection level**: Key files are protected with filesystem permissions (0600 on Unix, ACL-restricted on Windows).
**Mitigations**:
- Keys stored in `.git/git-crypt/keys/` with restricted permissions
- GPG/age wrapping means the symmetric key is protected by the user's private key
- Never commit symmetric keys to the repository
- Use hardware-backed keys (YubiKey via age-plugin-yubikey) for additional protection

## Key Management Best Practices

1. **Use GPG or age key wrapping** instead of sharing symmetric keys directly. This allows per-user access control and revocation.

2. **Never share symmetric keys via insecure channels**. If you must share a symmetric key file, use an encrypted channel (GPG-encrypted email, Signal, etc.).

3. **Rotate keys when removing collaborators**. After running `rm-gpg-user`, use `rotate-key` to generate a new key version. The removed user still has access to historical content encrypted with the old key.

4. **Use separate key names for different sensitivity levels**. git-crypt supports multiple named keys, allowing you to grant different access levels to different teams.

5. **Enable the pre-commit hook**. Run `git-crypt install-hooks` to install a hook that prevents accidental plaintext commits of files that should be encrypted.

6. **Periodically audit with `verify-commits`**. Run `git-crypt verify-commits` to check that all commits modifying encrypted files are GPG-signed.

7. **Back up your keys securely**. If all copies of the key are lost, encrypted content cannot be recovered.

8. **Review `.gitattributes` changes carefully**. Changes to `.gitattributes` can silently disable encryption for specific files.

## Known Limitations

1. **No forward secrecy**: A compromised key decrypts all historical content encrypted with that key version.

2. **Deterministic encryption**: The same file content produces the same encrypted output (given the same key), which could theoretically leak information about whether two files have identical contents. (The synthetic IV derived from HMAC-SHA1 of the content provides semantic security for distinct content.)

3. **No integrity protection beyond Git**: git-crypt relies on Git's SHA-1 (or SHA-256) object hashing for integrity. It does not add an independent authentication tag to encrypted content.

4. **Filter bypass risk**: If Git is configured to skip clean/smudge filters (e.g., `git add --no-filters` or `GIT_NO_FILTERS=1`), files can be committed in plaintext. The pre-commit hook mitigates this.

5. **Large file performance**: All encryption/decryption happens in the clean/smudge filters, which are invoked per-file on checkout/commit. Very large encrypted files may impact performance.

## Recommendations for High-Security Environments

- **Require signed commits** on all branches that contain encrypted files. Use `git-crypt verify-commits` in CI to enforce this.
- **Use branch protection rules** to prevent force-pushes and require pull request reviews for changes to encrypted files and `.gitattributes`.
- **Install the pre-commit hook** on all developer machines to prevent plaintext leaks.
- **Use hardware-backed keys** (YubiKey) for GPG or age key material.
- **Consider separate repositories** for extremely sensitive data, rather than relying solely on file-level encryption within a shared repository.
- **Implement audit logging** to track who accesses encrypted content and when.
- **Regularly rotate keys** and review the list of authorized users.
- **Do not use git-crypt for**: passwords that should be in a secrets manager, API keys that should be in environment variables, or any data requiring fine-grained access control beyond "all or nothing" per key name.
