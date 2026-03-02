#
# Copyright (c) 2015 Andrew Ayer
#
# See COPYING file for license information.
#

CXXFLAGS ?= -Wall -pedantic -Wno-long-long -O2
CXXFLAGS += -std=c++11
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

ENABLE_MAN ?= no
DOCBOOK_XSL ?= http://cdn.docbook.org/release/xsl-nons/current/manpages/docbook.xsl

SRCDIR = src

OBJFILES = \
    $(SRCDIR)/git-crypt.o \
    $(SRCDIR)/commands.o \
    $(SRCDIR)/crypto.o \
    $(SRCDIR)/gpg.o \
    $(SRCDIR)/age.o \
    $(SRCDIR)/shamir.o \
    $(SRCDIR)/sops.o \
    $(SRCDIR)/audit.o \
    $(SRCDIR)/key.o \
    $(SRCDIR)/util.o \
    $(SRCDIR)/parse_options.o \
    $(SRCDIR)/coprocess.o \
    $(SRCDIR)/fhstream.o

OBJFILES += $(SRCDIR)/crypto-openssl-11.o
LDFLAGS += -lcrypto

# Object files needed by tests (shared library code, excluding git-crypt main)
TEST_LIB_OBJS = $(SRCDIR)/crypto.o $(SRCDIR)/crypto-openssl-11.o $(SRCDIR)/key.o $(SRCDIR)/util.o $(SRCDIR)/coprocess.o $(SRCDIR)/fhstream.o
TEST_SRCDIR = tests
TEST_OBJS = $(TEST_SRCDIR)/test_main.o $(TEST_SRCDIR)/test_crypto.o $(TEST_SRCDIR)/test_key.o
TEST_RUNNER = $(TEST_SRCDIR)/test_runner

XSLTPROC ?= xsltproc
DOCBOOK_FLAGS += --param man.output.in.separate.dir 1 \
		 --stringparam man.output.base.dir man/ \
		 --param man.output.subdirs.enabled 1 \
		 --param man.authors.section.enabled 1

all: build

#
# Build
#
BUILD_MAN_TARGETS-yes = build-man
BUILD_MAN_TARGETS-no =
BUILD_TARGETS := build-bin $(BUILD_MAN_TARGETS-$(ENABLE_MAN))

build: $(BUILD_TARGETS)

build-bin: git-crypt

git-crypt: $(OBJFILES)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJFILES) $(LDFLAGS)

$(SRCDIR)/util.o: $(SRCDIR)/util.cpp $(SRCDIR)/util-unix.cpp $(SRCDIR)/util-win32.cpp
$(SRCDIR)/coprocess.o: $(SRCDIR)/coprocess.cpp $(SRCDIR)/coprocess-unix.cpp $(SRCDIR)/coprocess-win32.cpp

build-man: man/man1/git-crypt.1

man/man1/git-crypt.1: man/git-crypt.xml
	$(XSLTPROC) $(DOCBOOK_FLAGS) $(DOCBOOK_XSL) man/git-crypt.xml

#
# Clean
#
CLEAN_MAN_TARGETS-yes = clean-man
CLEAN_MAN_TARGETS-no =
CLEAN_TARGETS := clean-bin $(CLEAN_MAN_TARGETS-$(ENABLE_MAN))

clean: $(CLEAN_TARGETS)

clean-bin:
	rm -f $(OBJFILES) git-crypt $(TEST_OBJS) $(TEST_RUNNER)

clean-man:
	rm -f man/man1/git-crypt.1

#
# Install
#
INSTALL_MAN_TARGETS-yes = install-man
INSTALL_MAN_TARGETS-no =
INSTALL_TARGETS := install-bin $(INSTALL_MAN_TARGETS-$(ENABLE_MAN))

install: $(INSTALL_TARGETS)

install-bin: build-bin
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 git-crypt $(DESTDIR)$(BINDIR)/

install-man: build-man
	install -d $(DESTDIR)$(MANDIR)/man1
	install -m 644 man/man1/git-crypt.1 $(DESTDIR)$(MANDIR)/man1/

#
# Test
#
$(TEST_SRCDIR)/%.o: $(TEST_SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -I$(SRCDIR) -I$(TEST_SRCDIR) -c -o $@ $<

$(TEST_RUNNER): $(TEST_OBJS) $(TEST_LIB_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(TEST_OBJS) $(TEST_LIB_OBJS) $(LDFLAGS)

test: $(TEST_RUNNER)
	./$(TEST_RUNNER)

.PHONY: all \
	build build-bin build-man \
	clean clean-bin clean-man \
	install install-bin install-man \
	test
