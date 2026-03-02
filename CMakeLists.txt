cmake_minimum_required(VERSION 3.10)
project(git-crypt VERSION 0.8.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Source files (matches Makefile OBJFILES)
set(SOURCES
    src/git-crypt.cpp
    src/commands.cpp
    src/crypto.cpp
    src/gpg.cpp
    src/age.cpp
    src/key.cpp
    src/util.cpp
    src/parse_options.cpp
    src/coprocess.cpp
    src/fhstream.cpp
    src/crypto-openssl-11.cpp
)

# Main binary
add_executable(git-crypt ${SOURCES})
target_include_directories(git-crypt PRIVATE ${CMAKE_SOURCE_DIR}/src ${OPENSSL_INCLUDE_DIR})
target_link_libraries(git-crypt PRIVATE OpenSSL::Crypto)
target_compile_options(git-crypt PRIVATE -Wall -pedantic -Wno-long-long)

# Install
install(TARGETS git-crypt DESTINATION bin)

# Man page (optional, requires xsltproc)
option(ENABLE_MAN "Build man pages" OFF)
if(ENABLE_MAN)
    find_program(XSLTPROC xsltproc)
    if(XSLTPROC)
        set(DOCBOOK_XSL "http://cdn.docbook.org/release/xsl-nons/current/manpages/docbook.xsl")
        add_custom_command(
            OUTPUT ${CMAKE_BINARY_DIR}/man/man1/git-crypt.1
            COMMAND ${XSLTPROC}
                --param man.output.in.separate.dir 1
                --stringparam man.output.base.dir ${CMAKE_BINARY_DIR}/man/
                --param man.output.subdirs.enabled 1
                --param man.authors.section.enabled 1
                ${DOCBOOK_XSL}
                ${CMAKE_SOURCE_DIR}/man/git-crypt.xml
            DEPENDS ${CMAKE_SOURCE_DIR}/man/git-crypt.xml
            COMMENT "Generating man page"
        )
        add_custom_target(man ALL DEPENDS ${CMAKE_BINARY_DIR}/man/man1/git-crypt.1)
        install(FILES ${CMAKE_BINARY_DIR}/man/man1/git-crypt.1 DESTINATION share/man/man1)
    else()
        message(WARNING "xsltproc not found, man pages will not be built")
    endif()
endif()

# Test placeholder
option(BUILD_TESTS "Build tests" OFF)
if(BUILD_TESTS)
    enable_testing()
    # Tests will be added here when test infrastructure is created
endif()
