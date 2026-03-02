# Contributing to git-crypt-revived

Thanks for your interest in contributing to git-crypt-revived! This project is a modernized fork of [AGWA/git-crypt](https://github.com/AGWA/git-crypt) and welcomes contributions in the form of code, documentation, bug reports, or anything else that improves the project.

Since git-crypt is security-sensitive software, the bar for contributions is higher than average. Please don't be discouraged by this, but be prepared for patches to possibly go through several rounds of feedback and improvement before being accepted.

## Development Environment Setup

### Prerequisites

| Software | Debian/Ubuntu | macOS | RHEL/CentOS |
|---|---|---|---|
| C++11 compiler (gcc 4.9+ or clang) | `g++` | Xcode CLT | `gcc-c++` |
| GNU Make | `make` | Xcode CLT | `make` |
| OpenSSL development headers | `libssl-dev` | `brew install openssl` | `openssl-devel` |
| Git 1.7.2+ | `git` | `git` | `git` |

### Option 1: Build with Make (recommended)

```bash
git clone https://github.com/appmaestro-ai/git-crypt.git
cd git-crypt
make
```

To build with man pages (requires `xsltproc`):

```bash
make ENABLE_MAN=yes
```

On macOS, you may need to specify OpenSSL paths:

```bash
OPENSSL_PREFIX="$(brew --prefix openssl)"
make CXXFLAGS="-Wall -pedantic -Wno-long-long -O2 -std=c++11 -I${OPENSSL_PREFIX}/include" \
     LDFLAGS="-L${OPENSSL_PREFIX}/lib -lcrypto"
```

### Option 2: Build with CMake

```bash
cmake -B build
cmake --build build
```

### Option 3: Build with Docker

```bash
# Standalone build
docker build -f Dockerfile.dev -t git-crypt-dev .
docker run --rm git-crypt-dev

# Interactive development (edit on host, build in container)
docker compose run --rm dev bash
# Inside the container:
make clean && make
```

## Running Tests

Unit tests use the [Catch2](https://github.com/catchorg/Catch2) framework:

```bash
make test
```

This builds and runs the test runner at `tests/test_runner`. Always run tests before submitting a pull request.

## Code Style Guide

- **Language**: C++11 (no C++14 or later features)
- **Indentation**: Tabs with a width of 8
- **Braces**: Opening brace on the same line as the statement
- **Naming**: `snake_case` for functions and variables, `PascalCase` for types
- **Headers**: Use `.hpp` extension for C++ headers
- **Includes**: Standard library first, then project headers
- Mimic the existing code style as closely as possible

### Key Source Files

| File | Purpose |
|---|---|
| `src/commands.cpp` | All command implementations (init, lock, unlock, status, etc.) |
| `src/crypto.cpp` | AES-256 encryption/decryption, key derivation |
| `src/key.cpp` | Key file format and management |
| `src/gpg.cpp` | GPG key wrapping and interaction |
| `src/git-crypt.cpp` | Entry point, argument parsing, command dispatch |
| `src/parse_options.cpp` | CLI argument parsing utilities |
| `src/util.cpp` | Shared utility functions |
| `man/git-crypt.xml` | Man page source (DocBook XML) |

## Submitting Changes

### Before You Start

- Open an issue on GitHub to discuss any non-trivial changes before you start coding.
- Check existing issues and the [project board](https://github.com/users/ramene/projects/8) to avoid duplicate work.

### Branch Naming

Use descriptive branch names with a category prefix:

- `feature/age-encryption` -- new features
- `fix/unlock-error-handling` -- bug fixes
- `docs/contributing-guide` -- documentation
- `refactor/key-management` -- code refactoring
- `test/crypto-edge-cases` -- test additions

### Commit Messages

Follow the existing commit style: imperative mood, concise summary line.

```
Add practical examples section to man page

Longer description if needed, explaining the motivation
and any important details about the change.
```

- First line: imperative summary, ~50 characters
- Blank line, then optional body wrapping at 72 characters
- Reference issues where relevant: `Fixes #123`

### Pull Request Process

1. Fork the repository and create your branch from `master`.
2. Make your changes, following the code style guide above.
3. Add or update tests for any new functionality.
4. Run `make clean && make && make test` and ensure everything passes.
5. Rebase your changes onto the latest `master` to minimize merge commits.
6. Open a pull request with a clear description of what changed and why.

## License

By contributing to git-crypt-revived, you agree that your contributions will be licensed under the [GNU General Public License v3](COPYING).
