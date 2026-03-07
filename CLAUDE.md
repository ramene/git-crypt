# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**git-crypt-revived** — A modernized fork of AGWA/git-crypt (v0.8.0) with enhanced security features including age encryption support, SOPS integration, 2FA via YubiKey/Shamir's Secret Sharing, wallet-based identity and access control, cryptographic audit trails, and signed access logging.

## Build & Development

```bash
make                    # Build git-crypt binary
make ENABLE_MAN=yes     # Build with man pages
make install PREFIX=/usr/local
make clean
```

**Dependencies**: C++11 compiler, OpenSSL libcrypto, GNU Make

## Architecture

- **Entry**: `git-crypt.cpp` → `commands.cpp` (~1,800 lines, ALL commands)
- **Crypto**: AES-256-CTR with HMAC-SHA1 derived synthetic IV
- **Git Integration**: clean/smudge filters for transparent encryption
- **Key Format**: Symmetric key file format (`.git/git-crypt/keys/`)
- **GPG Integration**: Wrapped symmetric keys per GPG user

### Key Source Files
- `commands.cpp` — All command implementations (lock, unlock, init, export-key, add-gpg-user, status)
- `crypto.cpp` — AES-256 encryption/decryption and key derivation
- `key.cpp` — Key file format and management
- `gpg.cpp` — GPG key wrapping
- `git-filters.cpp` — Git clean/smudge filter implementation
- `parse_options.cpp` — CLI argument parsing

### Known Gaps (from analysis)
- 3 unimplemented stubs: `rm-gpg-user`, `ls-gpg-users`, `refresh`
- 26 TODO comments in commands.cpp
- Zero test infrastructure
- No CI test pipeline (build-only)

## GitHub Project Board

See `CLAUDE-secrets.md` (git-crypt encrypted) for board ID and internal URLs.

## Prompting Guide

See `CLAUDE-prompting.md` for situation-first examples of effective prompts for this project.

## Memory Bank System

* **CLAUDE-activeContext.md** - Current session state, goals, and progress
* **CLAUDE-patterns.md** - Established code patterns and conventions
* **CLAUDE-decisions.md** - Architecture decisions and rationale
* **CLAUDE-troubleshooting.md** - Common issues and proven solutions

# currentDate
Today's date is 2026-03-02.
