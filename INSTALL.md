### Dependencies

To build git-crypt, you need:

| Software                        | Debian/Ubuntu package | RHEL/CentOS package | macOS              |
|---------------------------------|-----------------------|---------------------|--------------------|
| Make                            | make                  | make                | Xcode CLT          |
| A C++11 compiler (e.g. gcc 4.9+)| g++                  | gcc-c++             | Xcode CLT          |
| OpenSSL development files       | libssl-dev            | openssl-devel       | `brew install openssl` |

To use git-crypt, you need:

| Software                        | Debian/Ubuntu package | RHEL/CentOS package | macOS              |
|---------------------------------|-----------------------|---------------------|--------------------|
| Git 1.7.2 or newer              | git                   | git                 | git                |
| OpenSSL                         | openssl               | openssl             | openssl            |

Note: Git 1.8.5 or newer is recommended for best performance.

### Optional Dependencies

These are only needed for specific features:

| Feature                | Software                                                              | Install                                |
|------------------------|-----------------------------------------------------------------------|----------------------------------------|
| age encryption         | [age](https://age-encryption.org/)                                    | `brew install age` / `apt install age` |
| YubiKey support        | [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey)     | `brew install age-plugin-yubikey`      |
| SOPS integration       | [sops](https://github.com/getsops/sops)                              | `brew install sops` / `apt install sops` |


### Building git-crypt (Make)

Run:

    make
    make install

To install to a specific location:

    make install PREFIX=/usr/local

Or, just copy the git-crypt binary to wherever is most convenient for you.


### Building git-crypt (CMake)

CMake is supported as an alternative build system:

    cmake -B build
    cmake --build build
    sudo cmake --install build

To specify an install prefix:

    cmake -B build -DCMAKE_INSTALL_PREFIX=/usr/local
    cmake --build build
    sudo cmake --install build


### Building with Docker

A Docker-based development environment is provided for consistent builds:

    # Build and run tests in a container
    docker compose run --rm dev make clean && make && make test

    # Interactive development shell
    docker compose run --rm dev bash

The Docker image includes all required build dependencies (gcc, OpenSSL headers, CMake, Make).


### Running Tests

Unit tests use the Catch2 framework:

    make test

This builds and runs the test runner at `tests/test_runner`.


### Building The Man Page

To build and install the git-crypt(1) man page, pass `ENABLE_MAN=yes` to make:

    make ENABLE_MAN=yes
    make ENABLE_MAN=yes install

xsltproc is required to build the man page.  Note that xsltproc will access
the Internet to retrieve its stylesheet unless the Docbook stylesheet is
installed locally and registered in the system's XML catalog.


### Installing via Homebrew

Using the Homebrew package manager:

    brew tap ramene/tap
    brew install git-crypt-revived


### Building A Debian Package

Debian packaging can be found in the 'debian' branch of the project Git
repository.  The package is built using git-buildpackage as follows:

    git checkout debian
    git-buildpackage -uc -us


### Installing On Mac OS X

For macOS, you may need to specify the Homebrew OpenSSL path:

    OPENSSL_PREFIX="$(brew --prefix openssl)"
    make CXXFLAGS="-Wall -pedantic -Wno-long-long -O2 -std=c++11 -I${OPENSSL_PREFIX}/include" \
         LDFLAGS="-L${OPENSSL_PREFIX}/lib -lcrypto"


### Windows Support

git-crypt builds on Windows with MinGW. Windows support includes proper ACL-based
file permissions for key files. You will need to pass your own CXX, CXXFLAGS, and
LDFLAGS variables to make. Bug reports and patches are welcome.
