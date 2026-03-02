# Change Log

## v0.9.0 (2026-03-02)

### Modern Encryption Backends
* Add age encryption backend as an alternative to GPG (`add-age-recipient`, `rm-age-recipient`).
* Add SSH key support (`--ssh` flag) for encrypting to existing `ssh-ed25519` / `ssh-rsa` keys via age.
* Add YubiKey PIV hardware authentication via age-plugin-yubikey.

### Core Commands
* Implement `rm-gpg-user` to revoke GPG user access.
* Implement `ls-gpg-users` to list all GPG user fingerprints per key.
* Implement `refresh` to force re-checkout of all encrypted files.
* Implement `rotate-key` for symmetric key rotation with re-wrapping for all recipients.
* Add machine-parseable status output (`status -m`).
* Add `-f` / `--force` flag for forced re-initialization.
* Add `--version` flag to `export-key` for exporting specific key versions.

### Secret Management
* Add SOPS bridge (`sops-config`) for structured file encryption (YAML, JSON, ENV).
* Add `.credentials/` directory pattern (`credentials-init`) with pre-configured encryption.

### Advanced Security
* Implement Shamir's Secret Sharing for M-of-N key splitting (`split-key`, `unlock --shares`).
* Add wallet-based identity using Ethereum wallet signatures (`add-wallet-recipient`, `unlock --wallet`).
* Add SHA-256 hash-chained cryptographic audit trail (`audit-log`, `verify-audit`).
* Add on-chain audit log anchoring (`anchor-audit`).
* Add pre-commit hook for plaintext leak prevention (`install-hooks`).
* Add signed commit verification for commits touching encrypted files (`verify-commits`).
* Add `.gitattributes` tamper detection to `status` command.
* Implement Windows `create_protected_file` with proper ACL permissions.

### Code Quality
* Fix hardcoded key version 0 in GPG unlock path.
* Improve error messages with key name context throughout.

### Infrastructure
* Add Catch2 unit test framework with crypto and key roundtrip tests.
* Add GitHub Actions CI pipeline (Ubuntu gcc/clang, macOS clang, CMake).
* Add GitHub Actions release workflow with cross-platform binary builds.
* Add CMake build system alongside the original Makefile.
* Add Docker-based development environment (Dockerfile.dev, docker-compose.yml).
* Add Homebrew formula for installation.
* Reorganize source files into `src/` directory structure.

### Documentation
* Add security model and threat analysis documentation (doc/SECURITY.md).
* Add post-quantum cryptography readiness assessment (doc/post-quantum-readiness.md).
* Add GPG-to-age migration guide (doc/age-migration-guide.md).
* Add practical examples section to man page.
* Rewrite README.md and CONTRIBUTING.md for the fork.

## v0.8.0 (2025-09-23)
* Remove OpenSSL 1.0 support, fix compilation with OpenSSL 3.
* Avoid use of problematic short GPG key IDs.

## v0.7.0 (2022-04-21)
* Avoid "argument list too long" errors on macOS.
* Fix handling of "-" arguments.
* Minor documentation improvements.

## v0.6.0 (2017-11-26)
* Add support for OpenSSL 1.1 (still works with OpenSSL 1.0).
* Switch to C++11 (gcc 4.9 or higher now required to build).
* Allow GPG to fail on some keys (makes unlock work better if there are
  multiple keys that can unlock the repo but only some are available).
* Allow the repo state directory to be configured with the
  git-crypt.repoStateDir git config option.
* Respect the gpg.program git config option.
* Don't hard code path to git-crypt in .git/config on Linux (ensures
  repo continues to work if git-crypt is moved).
* Ensure git-crypt's gpg files won't be treated as text by Git.
* Minor improvements to build system, documentation.

## v0.5.0 (2015-05-30)
* Drastically speed up lock/unlock when used with Git 1.8.5 or newer.
* Add git-crypt(1) man page (pass `ENABLE_MAN=yes` to make to build).
* Add --trusted option to `git-crypt gpg-add-user` to add user even if
  GPG doesn't trust user's key.
* Improve `git-crypt lock` usability, add --force option.
* Ignore symlinks and other non-files when running `git-crypt status`.
* Fix compilation on old versions of Mac OS X.
* Fix GPG mode when with-fingerprint enabled in gpg.conf.
* Minor bug fixes and improvements to help/error messages.

## v0.4.2 (2015-01-31)
* Fix unlock and lock under Git 2.2.2 and higher.
* Drop support for versions of Git older than 1.7.2.
* Minor improvements to some help/error messages.

## v0.4.1 (2015-01-08)
* Important usability fix to ensure that the .git-crypt directory
  can't be encrypted by accident (see
  [the release notes](RELEASE_NOTES-0.4.1.md) for more information).

## v0.4 (2014-11-16)
(See [the release notes](RELEASE_NOTES-0.4.md) for important details.)
* Add optional GPG support: GPG can be used to share the repository
  between one or more users in lieu of sharing a secret key.
* New workflow: the symmetric key is now stored inside the .git
  directory.  Although backwards compatibility has been preserved
  with repositories created by old versions of git-crypt, the
  commands for setting up a repository have changed.  See the
  release notes file for details.
* Multiple key support: it's now possible to encrypt different parts
  of a repository with different keys.
* Initial `git-crypt status` command to report which files are
  encrypted and to fix problems that are detected.
* Numerous usability, documentation, and error reporting improvements.
* Major internal code improvements that will make future development
  easier.
* Initial experimental Windows support.

## v0.3 (2013-04-05)
* Fix `git-crypt init` on newer versions of Git.  Previously,
  encrypted files were not being automatically decrypted after running
  `git-crypt init` with recent versions of Git.
* Allow `git-crypt init` to be run even if the working tree contains
  untracked files.
* `git-crypt init` now properly escapes arguments to the filter
  commands it configures, allowing both the path to git-crypt and the
  path to the key file to contain arbitrary characters such as spaces.

## v0.2 (2013-01-25)
* Numerous improvements to `git-crypt init` usability.
* Fix gitattributes example in [README](README.md): the old example
  showed a colon after the filename where there shouldn't be one.
* Various build fixes and improvements.

## v0.1 (2012-11-29)
* Initial release.
