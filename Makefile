# Copyright (c) 2026 Third Level IT LLC. All rights reserved.
# VIRP — Verified Infrastructure Response Protocol
#
# Build with Cisco driver:     make CISCO=1
# Build with FortiGate driver: make FORTIGATE=1
# Build both:                  make CISCO=1 FORTIGATE=1
# Build without (default):     make

CC      = gcc
CFLAGS  = -Wall -Wextra -Werror -pedantic -std=c11 -O2 -g -fPIC
CFLAGS += -I./include -I./src/third_party $(CFLAGS_EXTRA)
# Header-dependency tracking: emit a .d file per object (-MMD, user headers
# only) with phony targets for each prereq (-MP, so a deleted/renamed header
# doesn't wedge the build). The generated .d files are -included below so a
# header change forces every dependent object to recompile — this is what
# prevents the stale-object / struct-ABI-mismatch class of bug.
CFLAGS += -MMD -MP
# LDFLAGS_EXTRA mirrors CFLAGS_EXTRA above. Use it — never override
# LDFLAGS on the command line: a command-line assignment beats the `+=`
# in the driver ifdef blocks below, so the driver libraries (-lcurl,
# -lssl, -lssh2) silently vanish and the link fails on every driver
# symbol at once.
LDFLAGS = -lcrypto -lpthread -lsqlite3 -lsodium $(LDFLAGS_EXTRA)

BUILD_DIR = build

# Core library objects
LIB_OBJS  = $(BUILD_DIR)/virp_crypto.o \
             $(BUILD_DIR)/virp_message.o \
             $(BUILD_DIR)/virp_driver.o \
             $(BUILD_DIR)/driver_mock.o \
             $(BUILD_DIR)/virp_onode.o \
             $(BUILD_DIR)/virp_chain.o \
             $(BUILD_DIR)/virp_federation.o \
             $(BUILD_DIR)/virp_seqstore.o \
             $(BUILD_DIR)/virp_session.o \
             $(BUILD_DIR)/virp_handshake.o \
             $(BUILD_DIR)/virp_transcript.o \
             $(BUILD_DIR)/virp_validator.o \
             $(BUILD_DIR)/virp_approval.o \
             $(BUILD_DIR)/virp_approver_registry.o \
             $(BUILD_DIR)/virp_obskey.o \
             $(BUILD_DIR)/virp_ssh_io.o \
             $(BUILD_DIR)/cJSON.o

# Optional Cisco driver (requires libssh2)
ifdef CISCO
  CFLAGS  += -DVIRP_DRIVER_CISCO
  LDFLAGS += -lssh2
  LIB_OBJS += $(BUILD_DIR)/driver_cisco.o
endif

# Optional FortiGate driver (requires libssh2)
ifdef FORTIGATE
  CFLAGS  += -DVIRP_DRIVER_FORTINET
  # libssh2 may already be linked via CISCO; add only if not already present
  ifndef CISCO
    LDFLAGS += -lssh2
  endif
  LIB_OBJS += $(BUILD_DIR)/driver_fortigate.o
endif

# Optional PAN-OS driver (requires libssh2)
ifdef PANOS
  CFLAGS  += -DVIRP_DRIVER_PALOALTO
  ifndef CISCO
    ifndef FORTIGATE
      LDFLAGS += -lssh2
    endif
  endif
  LIB_OBJS += $(BUILD_DIR)/driver_panos.o
endif

# Optional Cisco ASA driver (requires libssh2)
ifdef ASA
  CFLAGS  += -DVIRP_DRIVER_CISCO_ASA
  ifndef CISCO
    ifndef FORTIGATE
      ifndef PANOS
        LDFLAGS += -lssh2
      endif
    endif
  endif
  LIB_OBJS += $(BUILD_DIR)/driver_asa.o $(BUILD_DIR)/parser_asa.o
endif

# Optional Wazuh driver (requires libcurl — REST API, not SSH)
ifdef WAZUH
  CFLAGS  += -DVIRP_DRIVER_WAZUH $(shell pkg-config --cflags libcurl 2>/dev/null)
  LDFLAGS += $(shell pkg-config --libs libcurl 2>/dev/null || echo "-lcurl")
  LIB_OBJS += $(BUILD_DIR)/driver_wazuh.o
endif

# Optional Juniper JunOS driver (requires libssh2)
ifdef JUNIPER
  CFLAGS  += -DVIRP_DRIVER_JUNIPER
  ifndef CISCO
    ifndef FORTIGATE
      ifndef PANOS
        ifndef ASA
          LDFLAGS += -lssh2
        endif
      endif
    endif
  endif
  LIB_OBJS += $(BUILD_DIR)/driver_juniper.o
endif

# Optional Linux driver (requires libssh2)
ifdef LINUX
  CFLAGS  += -DVIRP_DRIVER_LINUX
  ifndef CISCO
    ifndef FORTIGATE
      LDFLAGS += -lssh2
    endif
  endif
  LIB_OBJS += $(BUILD_DIR)/driver_linux.o
endif

# Optional LibreNMS driver (requires libcurl — REST API, not SSH)
ifdef LIBRENMS
  CFLAGS  += -DVIRP_DRIVER_LIBRENMS $(shell pkg-config --cflags libcurl 2>/dev/null)
  ifndef WAZUH
    LDFLAGS += $(shell pkg-config --libs libcurl 2>/dev/null || echo "-lcurl")
  endif
  LIB_OBJS += $(BUILD_DIR)/driver_librenms.o
endif

# Optional Proxmox Backup Server driver — typed operations over REST.
# Needs libcurl like the other REST drivers, plus -lssl: the certificate
# pin is implemented with an OpenSSL verify callback (SSL_CTX_*), which
# the bare -lcrypto in the base LDFLAGS does not provide.
ifdef PBS
  CFLAGS  += -DVIRP_DRIVER_PBS $(shell pkg-config --cflags libcurl 2>/dev/null)
  ifndef WAZUH
    ifndef LIBRENMS
      LDFLAGS += $(shell pkg-config --libs libcurl 2>/dev/null || echo "-lcurl")
    endif
  endif
  LDFLAGS += -lssl
  LIB_OBJS += $(BUILD_DIR)/driver_pbs.o
endif

# Optional Zammad driver (requires libcurl — REST API, not SSH)
ifdef ZAMMAD
  CFLAGS  += -DVIRP_DRIVER_ZAMMAD $(shell pkg-config --cflags libcurl 2>/dev/null)
  ifndef WAZUH
    ifndef LIBRENMS
      ifndef PBS
        LDFLAGS += $(shell pkg-config --libs libcurl 2>/dev/null || echo "-lcurl")
      endif
    endif
  endif
  LIB_OBJS += $(BUILD_DIR)/driver_zammad.o
endif

# SSH host key verification — included when any SSH driver is enabled
ifneq (,$(or $(CISCO),$(FORTIGATE),$(PANOS),$(ASA),$(JUNIPER),$(LINUX)))
  LIB_OBJS += $(BUILD_DIR)/virp_ssh_hostkey.o
endif

# A failed build must not leave a RUNNABLE stale binary.
#
# Found 2026-08-09 while investigating two stale test results. When a
# test binary fails to compile, gcc never touches the output, so the
# PREVIOUS binary survives — and running it prints a full green pass
# that describes code which no longer exists. Reproduced directly:
# introduce a syntax error, `make` exits 2, the old binary is still
# there and still reports "236/236 passed".
#
# .DELETE_ON_ERROR does NOT cover this: it only deletes a target the
# recipe actually modified, and here the recipe never got that far. So
# every test-link recipe removes its target FIRST. A failed build then
# leaves no binary at all, and anyone who runs it gets "No such file or
# directory" instead of a fabricated pass.
#
# The safe way to run a suite remains `make test-<name>`, which will not
# run the binary if the build failed. Building the artifact path and
# then invoking it as a separate command defeats that, which is exactly
# the mistake that produced the stale numbers.
.DELETE_ON_ERROR:

LIB          = $(BUILD_DIR)/libvirp.a
SHLIB        = $(BUILD_DIR)/libvirp.so
TEST_BIN     = $(BUILD_DIR)/test_virp
FUZZ_BIN     = $(BUILD_DIR)/fuzz_virp
TOOL_BIN     = $(BUILD_DIR)/virp-tool
ONODE_BIN    = $(BUILD_DIR)/virp-onode
TEST_ONODE   = $(BUILD_DIR)/test_onode

.PHONY: all clean test fuzz test-onode test-chain test-federation test-interop shared

all: $(LIB) $(SHLIB) $(TEST_BIN) $(FUZZ_BIN) $(TOOL_BIN) $(ONODE_BIN) $(TEST_ONODE)

shared: $(SHLIB)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/virp_crypto.o: src/virp_crypto.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/virp_message.o: src/virp_message.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/virp_driver.o: src/virp_driver.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/driver_mock.o: src/drivers/driver_mock.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/driver_cisco.o: src/drivers/driver_cisco.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/driver_fortigate.o: src/drivers/driver_fortigate.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/driver_panos.o: src/driver_panos.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/driver_asa.o: src/drivers/driver_asa.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/parser_asa.o: src/drivers/parser_asa.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/driver_juniper.o: src/drivers/driver_juniper.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/driver_linux.o: src/drivers/driver_linux.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/driver_wazuh.o: src/drivers/driver_wazuh.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/driver_librenms.o: src/drivers/driver_librenms.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/driver_pbs.o: src/drivers/driver_pbs.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/driver_zammad.o: src/drivers/driver_zammad.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/virp_ssh_hostkey.o: src/virp_ssh_hostkey.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/virp_ssh_io.o: src/virp_ssh_io.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/cJSON.o: src/third_party/cJSON.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/virp_onode.o: src/virp_onode.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/virp_chain.o: src/virp_chain.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/virp_federation.o: src/virp_federation.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/virp_session.o: src/virp_session.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/virp_seqstore.o: src/virp_seqstore.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/virp_handshake.o: src/virp_handshake.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/virp_transcript.o: src/virp_transcript.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/virp_validator.o: src/virp_validator.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/virp_approval.o: src/virp_approval.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/virp_approver_registry.o: src/virp_approver_registry.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/virp_obskey.o: src/virp_obskey.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB): $(LIB_OBJS)
	ar rcs $@ $^

$(SHLIB): $(LIB_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

$(TEST_BIN): tests/test_virp.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(FUZZ_BIN): tests/fuzz_virp.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

# Git hash stamped into virp-tool for `virp --version` (helps catch a
# stale client talking to a newer daemon). Falls back to "unknown" when
# git is unavailable (e.g. tarball build).
GIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

# FORCE so the git hash stamped for `virp --version` always tracks HEAD,
# even when only unrelated files changed since the last build (one cheap
# recompile of virp_tool.c per make).
.PHONY: FORCE
FORCE:

$(TOOL_BIN): src/virp_tool.c $(LIB) FORCE
	$(CC) $(CFLAGS) -DVIRP_GIT_HASH='"$(GIT_HASH)"' $< $(LIB) $(LDFLAGS) -o $@
	ln -f $@ $(BUILD_DIR)/virp   # `virp approve <id>` alias

$(ONODE_BIN): src/virp_onode_main.c $(LIB)
	$(CC) $(CFLAGS) src/virp_onode_main.c $(LIB) $(LDFLAGS) -ljson-c -o $@

# Prod parser compiled with main() omitted (-DVIRP_ONODE_PROD_NO_MAIN) so
# the issue-#7 regression test in test_onode.c can link the real
# load_devices() without conflicting with the daemon's main().
$(BUILD_DIR)/virp_onode_prod_lib.o: src/virp_onode_prod.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DVIRP_ONODE_PROD_NO_MAIN -c $< -o $@

$(TEST_ONODE): tests/test_onode.c $(BUILD_DIR)/virp_onode_prod_lib.o $(LIB)
	$(CC) $(CFLAGS) $< $(BUILD_DIR)/virp_onode_prod_lib.o $(LIB) $(LDFLAGS) -ljson-c -o $@

test: $(TEST_BIN)
	./$(TEST_BIN)

fuzz: $(FUZZ_BIN)
	./$(FUZZ_BIN)

test-onode: $(TEST_ONODE)
	./$(TEST_ONODE)

# Shared SSH read path (finding N1 / 2a)
TEST_SSH_IO = $(BUILD_DIR)/test_ssh_io

$(TEST_SSH_IO): tests/test_ssh_io.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

.PHONY: test-ssh-io
test-ssh-io: $(TEST_SSH_IO)
	./$(TEST_SSH_IO)

# FortiGate reply scrubbing (finding N1 / 2c)
TEST_FG_SCRUB = $(BUILD_DIR)/test_driver_fortigate_scrub

# Built with the driver + hostkey objects explicitly, so the suite runs
# in the default battery even when the library was built without
# FORTIGATE=1.
$(BUILD_DIR)/fg_scrub_driver.o: src/drivers/driver_fortigate.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DVIRP_DRIVER_FORTINET -c $< -o $@

$(BUILD_DIR)/fg_scrub_hostkey.o: src/virp_ssh_hostkey.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DVIRP_DRIVER_FORTINET -c $< -o $@

$(TEST_FG_SCRUB): tests/test_driver_fortigate_scrub.c \
                  $(BUILD_DIR)/fg_scrub_driver.o \
                  $(BUILD_DIR)/fg_scrub_hostkey.o $(LIB)
	$(CC) $(CFLAGS) -DVIRP_DRIVER_FORTINET $< \
	    $(BUILD_DIR)/fg_scrub_driver.o $(BUILD_DIR)/fg_scrub_hostkey.o \
	    $(LIB) $(LDFLAGS) -lssh2 -o $@

.PHONY: test-fg-scrub
test-fg-scrub: $(TEST_FG_SCRUB)
	./$(TEST_FG_SCRUB)

# Cisco config credential scrubbing (show running-config GREEN gate)
TEST_CISCO_SCRUB = $(BUILD_DIR)/test_driver_cisco_scrub

# Built with the driver + hostkey objects explicitly, so the suite runs
# in the default battery even when the library was built without
# CISCO=1 — same arrangement as the FortiGate scrub suite above.
$(BUILD_DIR)/cisco_scrub_driver.o: src/drivers/driver_cisco.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DVIRP_DRIVER_CISCO -c $< -o $@

$(BUILD_DIR)/cisco_scrub_hostkey.o: src/virp_ssh_hostkey.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DVIRP_DRIVER_CISCO -c $< -o $@

$(TEST_CISCO_SCRUB): tests/test_driver_cisco_scrub.c \
                     $(BUILD_DIR)/cisco_scrub_driver.o \
                     $(BUILD_DIR)/cisco_scrub_hostkey.o $(LIB)
	$(CC) $(CFLAGS) -DVIRP_DRIVER_CISCO $< \
	    $(BUILD_DIR)/cisco_scrub_driver.o $(BUILD_DIR)/cisco_scrub_hostkey.o \
	    $(LIB) $(LDFLAGS) -lssh2 -o $@

.PHONY: test-cisco-scrub
test-cisco-scrub: $(TEST_CISCO_SCRUB)
	./$(TEST_CISCO_SCRUB)

# ASA config credential scrubbing (port of the cisco scrub)
TEST_ASA_SCRUB = $(BUILD_DIR)/test_driver_asa_scrub

# Built with the driver + parser + hostkey objects explicitly, so the
# suite runs in the default battery even when the library was built
# without ASA=1 — same arrangement as the cisco/FortiGate scrub suites.
$(BUILD_DIR)/asa_scrub_driver.o: src/drivers/driver_asa.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DVIRP_DRIVER_CISCO_ASA -c $< -o $@

$(BUILD_DIR)/asa_scrub_parser.o: src/drivers/parser_asa.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DVIRP_DRIVER_CISCO_ASA -c $< -o $@

$(BUILD_DIR)/asa_scrub_hostkey.o: src/virp_ssh_hostkey.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DVIRP_DRIVER_CISCO_ASA -c $< -o $@

$(TEST_ASA_SCRUB): tests/test_driver_asa_scrub.c \
                   $(BUILD_DIR)/asa_scrub_driver.o \
                   $(BUILD_DIR)/asa_scrub_parser.o \
                   $(BUILD_DIR)/asa_scrub_hostkey.o $(LIB)
	$(CC) $(CFLAGS) -DVIRP_DRIVER_CISCO_ASA $< \
	    $(BUILD_DIR)/asa_scrub_driver.o $(BUILD_DIR)/asa_scrub_parser.o \
	    $(BUILD_DIR)/asa_scrub_hostkey.o \
	    $(LIB) $(LDFLAGS) -lssh2 -o $@

.PHONY: test-asa-scrub
test-asa-scrub: $(TEST_ASA_SCRUB)
	./$(TEST_ASA_SCRUB)

# Chain and Federation tests
TEST_CHAIN = $(BUILD_DIR)/test_chain
TEST_FED   = $(BUILD_DIR)/test_federation

$(TEST_CHAIN): tests/test_chain.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(TEST_FED): tests/test_federation.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-chain: $(TEST_CHAIN)
	./$(TEST_CHAIN)

# Chain concurrency test (Item 3 hardening — shared prepared-statement race)
TEST_CHAIN_CONC = $(BUILD_DIR)/test_chain_concurrency

$(TEST_CHAIN_CONC): tests/test_chain_concurrency.c $(LIB)
	$(CC) $(CFLAGS) tests/test_chain_concurrency.c $(LIB) $(LDFLAGS) -o $@

test-chain-concurrency: $(TEST_CHAIN_CONC)
	./$(TEST_CHAIN_CONC)

test-federation: $(TEST_FED)
	./$(TEST_FED)

clean:
	rm -rf $(BUILD_DIR) $(DRIVER_BUILD_DIR)

# Pull in per-object header dependencies generated by -MMD (build/*.d).
# wildcard keeps the first-ever build (no .d files yet) from erroring.
-include $(wildcard $(BUILD_DIR)/*.d)

LIVE_TEST = $(BUILD_DIR)/virp-live-test

$(LIVE_TEST): tests/test_live.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-live: $(LIVE_TEST)
	./$(LIVE_TEST)

# Production O-Node (with device config loading via json-c)
ONODE_PROD = $(BUILD_DIR)/virp-onode-prod

$(ONODE_PROD): src/virp_onode_prod.c $(LIB)
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -ljson-c -o $@

# ---------------------------------------------------------------------------
# LAB-ONLY fault-injection daemon (adversarial test program, test #2).
#
# Builds build-fi/virp-onode-prod with -DVIRP_FAULT_INJECT so the VIRP_FI()
# crash points in virp_onode.c / virp_approval.c compile in. Without that
# define every call site expands to ((void)0) and emits no symbol, so the
# production binary is unaffected by their presence in the source.
#
# ISOLATION, deliberate and load-bearing:
#   - Objects go to BUILD_DIR=build-fi, NOT build/. An FI-instrumented .o must
#     never end up in build/libvirp.a where a later `make prod` could link it.
#     build/virp (the client these tests depend on) is likewise untouched.
#   - -DVIRP_FAULT_INJECT is passed via the existing CFLAGS_EXTRA hook so the
#     Makefile's own CFLAGS (includes, warnings, -MMD) are preserved rather
#     than overridden.
#
# NOT a dependency of `all`, `prod`, or `install`. Must never be installed as
# $(VIRP_INSTALL_BIN) or named in the systemd unit: it exists to be SIGKILLed
# mid-operation, and must only run in the foreground against an ISOLATED
# socket, chain DB and approval spool. Full contract in
# include/virp_fault_inject.h.
# ---------------------------------------------------------------------------
.PHONY: onode-fi
onode-fi:
	$(MAKE) BUILD_DIR=build-fi CFLAGS_EXTRA=-DVIRP_FAULT_INJECT \
	        LINUX=1 build-fi/virp-onode-prod
	@echo ""
	@echo "built build-fi/virp-onode-prod  — LAB ONLY"
	@echo "  never 'make install' this, never point the systemd unit at it,"
	@echo "  and only run it against an isolated socket/chain/spool."

# 'make prod' builds the prod O-Node with all production drivers enabled,
# including PAN-OS. Uses recursive $(MAKE) because the driver guards are
# `ifdef PANOS` / `ifdef CISCO` / etc., which are evaluated at Makefile
# parse time — target-specific variable assignments (`prod: PANOS := 1`)
# would not reach those guards. Kept distinct from `prod-full` so either
# name works and callers have a single driver-enabled build entry point.
.PHONY: prod
prod:
	$(MAKE) CISCO=1 FORTIGATE=1 PANOS=1 ASA=1 LINUX=1 WAZUH=1 JUNIPER=1 LIBRENMS=1 PBS=1 ZAMMAD=1 $(ONODE_PROD)

# Full production build — recursive make ensures all ifdef guards evaluate correctly
# SSH host key verification is strict: unknown keys are rejected.
.PHONY: prod-full
prod-full:
	$(MAKE) CISCO=1 FORTIGATE=1 PANOS=1 ASA=1 LINUX=1 WAZUH=1 JUNIPER=1 LIBRENMS=1 PBS=1 ZAMMAD=1 $(ONODE_PROD)

# Dev build — all drivers, TOFU enabled by default so lab devices work
# without pre-populating known_hosts. Do not run dev binaries in production.
.PHONY: dev-full
dev-full:
	$(MAKE) CISCO=1 FORTIGATE=1 PANOS=1 ASA=1 LINUX=1 WAZUH=1 JUNIPER=1 \
		CFLAGS_EXTRA="-DVIRP_SSH_TOFU_DEFAULT" all

# C/Go interop test
TEST_INTEROP = $(BUILD_DIR)/test_interop_c
GO_DIR       = implementations/go

$(TEST_INTEROP): tests/test_interop_c.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

# Artifact-based C<->Go interop tests. VIRP_INTEROP_BIN points the Go
# tests at the freshly built local binary so they run pre-deploy
# (unset, they fall back to the deployed /opt/virp/build path). The
# live-daemon test is NOT run here — it is fenced behind
# VIRP_LIVE_INTEROP=1 (see live-interop below) so the default battery
# never touches a live device.
# SKIPS with a warning when the Go toolchain is absent rather than failing
# the whole battery. Three separate environments (CT 211, virp-lab and
# virp-node2 on first build) hit `go: not found` here and reported a red
# battery for a missing optional toolchain, which trains people to read
# `all-tests` failures as noise. The C reference implementation is fully
# covered without Go; what is lost is the C↔Go wire-parity check, so the
# skip says so loudly instead of passing quietly.
test-interop: $(TEST_INTEROP)
	@if command -v go >/dev/null 2>&1; then \
	  cd $(GO_DIR) && VIRP_INTEROP_BIN=$(abspath $(TEST_INTEROP)) \
	    go test ./virp/ -run TestInterop -v -count=1; \
	else \
	  echo "  *** SKIPPING test-interop: no Go toolchain on PATH."; \
	  echo "      install it with: apt install golang-go"; \
	  echo "  *** C<->Go wire parity is NOT covered in this run."; \
	fi

# Opt-in ONLY: drives the deployed daemon and REAL devices
# (FORTIGATE-200G, SW-3850). Known stale — needs the framed-protocol
# rewrite (see TestInterop_LiveCONode) — and must run as a uid on the
# daemon's SO_PEERCRED allowlist.
.PHONY: live-interop
live-interop:
	cd $(GO_DIR) && VIRP_LIVE_INTEROP=1 \
		go test ./virp/ -run TestInterop_LiveCONode -v -count=1

# ASA driver tests
TEST_ASA = $(BUILD_DIR)/test_driver_asa

$(TEST_ASA): tests/test_driver_asa.c $(LIB)
ifndef ASA
	@echo "ERROR: test-asa requires ASA=1 — driver objects are not in libvirp.a."
	@echo "       Run:  make ASA=1 test-asa"
	@echo "       Or:   make test-drivers   (builds every driver and runs all driver suites)"
	@false
else
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@
endif

test-asa: $(TEST_ASA)
	./$(TEST_ASA)

# PAN-OS driver tests (build with PANOS=1 so driver_panos.o is in $(LIB))
TEST_PANOS = $(BUILD_DIR)/test_driver_panos

$(TEST_PANOS): tests/test_driver_panos.c $(LIB)
ifndef PANOS
	@echo "ERROR: test-panos requires PANOS=1 — driver objects are not in libvirp.a."
	@echo "       Run:  make PANOS=1 test-panos"
	@echo "       Or:   make test-drivers   (builds every driver and runs all driver suites)"
	@false
else
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@
endif

test-panos: $(TEST_PANOS)
	./$(TEST_PANOS)

# Cisco driver tests (KEX list — issue #5). Requires CISCO=1 so driver_cisco.o
# is built into libvirp.a; the test only exercises the in-process KEX accessor
# (no SSH).
TEST_CISCO = $(BUILD_DIR)/test_driver_cisco

$(TEST_CISCO): tests/test_driver_cisco.c $(LIB)
ifndef CISCO
	@echo "ERROR: test-cisco requires CISCO=1 — driver objects are not in libvirp.a."
	@echo "       Run:  make CISCO=1 test-cisco"
	@echo "       Or:   make test-drivers   (builds every driver and runs all driver suites)"
	@false
else
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@
endif

test-cisco: $(TEST_CISCO)
	./$(TEST_CISCO)

# FortiGate driver tests (BLACK tier + gate classifier). Requires
# FORTIGATE=1 so driver_fortigate.o is built into libvirp.a.
TEST_FORTIGATE = $(BUILD_DIR)/test_driver_fortigate_black

$(TEST_FORTIGATE): tests/test_driver_fortigate_black.c $(LIB)
ifndef FORTIGATE
	@echo "ERROR: test-fortigate requires FORTIGATE=1 — driver objects are not in libvirp.a."
	@echo "       Run:  make FORTIGATE=1 test-fortigate"
	@echo "       Or:   make test-drivers   (builds every driver and runs all driver suites)"
	@false
else
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@
endif

test-fortigate: $(TEST_FORTIGATE)
	./$(TEST_FORTIGATE)

# Cisco IOS/IOS-XE gate-classifier tests (build with CISCO=1)
TEST_CISCO_GATE = $(BUILD_DIR)/test_driver_cisco_gate

$(TEST_CISCO_GATE): tests/test_driver_cisco_gate.c $(LIB)
ifndef CISCO
	@echo "ERROR: test-cisco-gate requires CISCO=1 — driver objects are not in libvirp.a."
	@echo "       Run:  make CISCO=1 test-cisco-gate"
	@echo "       Or:   make test-drivers   (builds every driver and runs all driver suites)"
	@false
else
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@
endif

test-cisco-gate: $(TEST_CISCO_GATE)
	./$(TEST_CISCO_GATE)

# Linux/FRR vtysh gate-classifier tests (build with LINUX=1)
TEST_LINUX_GATE = $(BUILD_DIR)/test_driver_linux_gate

$(TEST_LINUX_GATE): tests/test_driver_linux_gate.c $(LIB)
ifndef LINUX
	@echo "ERROR: test-linux-gate requires LINUX=1 — driver objects are not in libvirp.a."
	@echo "       Run:  make LINUX=1 test-linux-gate"
	@echo "       Or:   make test-drivers   (builds every driver and runs all driver suites)"
	@false
else
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@
endif

test-linux-gate: $(TEST_LINUX_GATE)
	./$(TEST_LINUX_GATE)

# Concurrent onode_execute smoke test (connection lifetime race)
TEST_ONODE_CONC = $(BUILD_DIR)/test_onode_concurrency

$(TEST_ONODE_CONC): tests/test_onode_concurrency.c $(LIB)
	$(CC) $(CFLAGS) tests/test_onode_concurrency.c $(LIB) $(LDFLAGS) -o $@

test-onode-concurrency: $(TEST_ONODE_CONC)
	./$(TEST_ONODE_CONC)

# Wazuh driver tests (requires WAZUH=1 and live Wazuh Manager)
TEST_WAZUH = $(BUILD_DIR)/test_driver_wazuh

$(TEST_WAZUH): tests/test_driver_wazuh.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-wazuh: $(TEST_WAZUH)
	./$(TEST_WAZUH)

# LibreNMS driver tests (requires LIBRENMS=1; classifier tests are offline,
# live tests are fenced the same way the Wazuh suite is)
TEST_LIBRENMS = $(BUILD_DIR)/test_driver_librenms

$(TEST_LIBRENMS): tests/test_driver_librenms.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-librenms: $(TEST_LIBRENMS)
	./$(TEST_LIBRENMS)

# PBS typed-operation driver tests (requires PBS=1). Entirely offline:
# the grammar parser, op table, URL derivation, fingerprint parsing and
# gate classifier are all pure functions, so this suite never originates
# outbound contact and needs no live fence.
TEST_PBS = $(BUILD_DIR)/test_driver_pbs

$(TEST_PBS): tests/test_driver_pbs.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-pbs: $(TEST_PBS)
	./$(TEST_PBS)

# Typed-operation command hashing (FIX 1). Offline and pure.
TEST_TYPED_HASH = $(BUILD_DIR)/test_typed_op_hash

$(TEST_TYPED_HASH): tests/test_typed_op_hash.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-typed-hash: $(TEST_TYPED_HASH)
	./$(TEST_TYPED_HASH)

# Ingress encoded-NUL rejection (FIX 2). Offline — drives the real
# parse_request() through its fuzz wrapper, no socket.
TEST_INGRESS_NUL = $(BUILD_DIR)/test_ingress_nul

$(TEST_INGRESS_NUL): tests/test_ingress_nul.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-ingress-nul: $(TEST_INGRESS_NUL)
	./$(TEST_INGRESS_NUL)

# PBS oversized-response fail-closed boundaries. Offline: drives the real
# write callback and formatter directly, no socket.
TEST_PBS_TRUNC = $(BUILD_DIR)/test_pbs_truncation

$(TEST_PBS_TRUNC): tests/test_pbs_truncation.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-pbs-trunc: $(TEST_PBS_TRUNC)
	./$(TEST_PBS_TRUNC)

TEST_PBS_GATE = $(BUILD_DIR)/test_driver_pbs_gate

$(TEST_PBS_GATE): tests/test_driver_pbs_gate.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-pbs-gate: $(TEST_PBS_GATE)
	./$(TEST_PBS_GATE)

# Zammad REST gate-classifier tests (build with ZAMMAD=1). Offline —
# the suite classifies strings and never originates network contact.
TEST_ZAMMAD_GATE = $(BUILD_DIR)/test_driver_zammad_gate

$(TEST_ZAMMAD_GATE): tests/test_driver_zammad_gate.c $(LIB)
ifndef ZAMMAD
	@echo "ERROR: test-zammad-gate requires ZAMMAD=1 — driver objects are not in libvirp.a."
	@echo "       Run:  make ZAMMAD=1 test-zammad-gate"
	@echo "       Or:   make test-drivers   (builds every driver and runs all driver suites)"
	@false
else
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@
endif

test-zammad-gate: $(TEST_ZAMMAD_GATE)
	./$(TEST_ZAMMAD_GATE)

# Autopilot client unit tests (pure-python: baselines, corpus table,
# RBAC empty-result handling — no daemon, no devices)
test-autopilot:
	python3 tests/test_autopilot.py

test-config-backup:
	python3 tests/test_config_backup.py

# render-devices.sh: a placeholder the template names but autopilot.env
# omits must be FATAL, not a literal "${TOKEN}" handed to a device as a
# credential. Runs the real script against a sandbox via VIRP_RENDER_*;
# reads no production path and writes none.
.PHONY: test-render-devices
test-render-devices:
	@bash tests/test_render_devices.sh

# Compliance-evidence collector + its control-mapped report. Pure python
# against fakes: no daemon, no devices, no chain database. The report
# tests need reportlab and SKIP with a warning without it (same policy as
# test-virp-report) rather than failing the battery — the collector tests
# always run.
.PHONY: test-evidence
test-evidence:
	python3 tests/test_evidence.py

# Commitment-only observation grading. Pins the chain_append GATE 3
# decision that a body-less observation registers but grades
# UNVERIFIABLE — the reason accepting it is not a signature bypass.
# Pure-Python against report/verify.py; no daemon, no chain, no deps.
.PHONY: test-commitment-grading
test-commitment-grading:
	@echo "=== commitment-only observation grading ==="
	python3 tests/test_commitment_only_grading.py

# virp report — consumer-side chain PDF generator. Synthetic-chain tests run
# anywhere; the live-chain tests self-skip when /var/lib/virp/chain.db is
# absent, so this target is safe on a build host. Requires reportlab
# (report/requirements.txt); pure python, no system packages.
#
# SKIPS with a warning when reportlab is absent rather than failing the
# battery — same policy as test-interop below. A missing optional tool is a
# gap in coverage to report, not a broken tree.
test-virp-report:
	@if python3 -c "import reportlab" 2>/dev/null; then \
	  python3 tests/test_virp_report.py; \
	else \
	  echo "  *** SKIPPING test-virp-report: reportlab is not installed."; \
	  echo "      install it with: pip install -r report/requirements.txt"; \
	  echo "      (or the distro package, e.g. apt install python3-reportlab)"; \
	  echo "  *** The chain report generator is NOT covered in this run."; \
	fi

# Session negative-path tests
TEST_SESSION_NEG = $(BUILD_DIR)/test_session_negative

$(TEST_SESSION_NEG): tests/test_session_negative.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-session: $(TEST_SESSION_NEG)
	./$(TEST_SESSION_NEG)

# v2 observation negative tests (replay / staleness / substitution /
# session binding / wire format)
TEST_OBS_V2 = $(BUILD_DIR)/test_obs_v2

$(TEST_OBS_V2): tests/test_obs_v2.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-obs-v2: $(TEST_OBS_V2)
	./$(TEST_OBS_V2)

# Observation-signing key (Ed25519 obskey) custody tests
TEST_OBSKEY = $(BUILD_DIR)/test_obskey

$(TEST_OBSKEY): tests/test_obskey.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-obskey: $(TEST_OBSKEY)
	./$(TEST_OBSKEY)

# v3 (Ed25519-signed) observation build tests
TEST_OBS_ED25519 = $(BUILD_DIR)/test_obs_ed25519

$(TEST_OBS_ED25519): tests/test_obs_ed25519.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-obs-ed25519: $(TEST_OBS_ED25519)
	./$(TEST_OBS_ED25519)

# The forge-resistance contrast: HMAC verify-key holder can mint a
# valid observation (the BGP-test ceiling, reproduced); an Ed25519
# public-key holder cannot; tampered covered bytes fail.
TEST_OBS_FORGE = $(BUILD_DIR)/test_obs_ed25519_forge

$(TEST_OBS_FORGE): tests/test_obs_ed25519_forge.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-obs-ed25519-forge: $(TEST_OBS_FORGE)
	./$(TEST_OBS_FORGE)

# v3 verifier malformed-framing negative battery (review P1-2): every
# reject path executed with the exact expected error code.
TEST_OBS_NEG = $(BUILD_DIR)/test_obs_ed25519_neg

$(TEST_OBS_NEG): tests/test_obs_ed25519_neg.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-obs-ed25519-neg: $(TEST_OBS_NEG)
	./$(TEST_OBS_NEG)

# Session key derivation tests
TEST_SESSION_KEY = $(BUILD_DIR)/test_session_key

$(TEST_SESSION_KEY): tests/test_session_key.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-session-key: $(TEST_SESSION_KEY)
	./$(TEST_SESSION_KEY)

# Juniper JunOS driver tests
TEST_JUNIPER = $(BUILD_DIR)/test_driver_juniper

$(TEST_JUNIPER): tests/test_driver_juniper.c $(LIB)
ifndef JUNIPER
	@echo "ERROR: test-juniper requires JUNIPER=1 — driver objects are not in libvirp.a."
	@echo "       Run:  make JUNIPER=1 test-juniper"
	@echo "       Or:   make test-drivers   (builds every driver and runs all driver suites)"
	@false
else
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@
endif

test-juniper: $(TEST_JUNIPER)
	./$(TEST_JUNIPER)

# ProVerif proofs — re-check the v2 observation model. Requires the
# proverif binary (see proofs/README.md for build-from-source steps).
# Fails if any query stops proving.
.PHONY: proofs
proofs:
	@command -v proverif >/dev/null || { echo "proverif not installed — see proofs/README.md"; exit 1; }
	proverif proofs/virp_obs_v2.pv | tee /tmp/virp-proofs-run.out
	@grep -q "RESULT not attacker(mk\[\]) is true" /tmp/virp-proofs-run.out
	@grep -q "RESULT not attacker(kprobe\[\]) is true" /tmp/virp-proofs-run.out
	@grep -q "RESULT inj-event(accepted(.*)) ==> inj-event(signed(.*)) is true" /tmp/virp-proofs-run.out
	@echo "  PASS: all 3 ProVerif queries proved"

# Driver test suites — run in the default battery, not just on demand.
#
# The driver classifiers ARE the adversarial surface: tier gating, the
# separator policy, and the token-boundary rule all live there. A suite
# that only runs when someone remembers `make CISCO=1 test-cisco-gate` is
# a one-time check, not a regression guard.
#
# Recursive $(MAKE) because the driver guards are `ifdef CISCO` etc.,
# evaluated at Makefile parse time — the same reason `prod` recurses.
# BUILD_DIR is redirected so driver-enabled objects never mix with the
# default driver-less build's objects (both name e.g. virp_onode.o, but
# they are compiled with different -D flags; make cannot tell them apart
# by timestamp).
DRIVER_BUILD_DIR = build-drivers

.PHONY: test-drivers
test-drivers:
	@echo "=== driver test suites (cisco, cisco-gate, linux-gate, juniper, asa, panos, fortigate, wazuh, librenms, pbs, pbs-gate, zammad-gate, typed-hash, ingress-nul, pbs-trunc) ==="
	$(MAKE) BUILD_DIR=$(DRIVER_BUILD_DIR) CISCO=1 PANOS=1 ASA=1 JUNIPER=1 FORTIGATE=1 LINUX=1 WAZUH=1 LIBRENMS=1 PBS=1 ZAMMAD=1 \
	        test-cisco test-cisco-gate test-linux-gate test-juniper test-asa test-panos test-fortigate test-wazuh test-librenms \
	        test-pbs test-pbs-gate test-zammad-gate test-typed-hash test-ingress-nul test-pbs-trunc

# Live-contact fence — STRUCTURAL, not a list of known targets.
#
# a2c01ef fenced one target (TestInterop_LiveCONode) and the class was
# assumed covered. It was not: test-wazuh opened an unguarded connection
# to the production Wazuh manager for months. A hand-maintained list of
# "the live targets" goes stale exactly that way, so this scans for the
# PRIMITIVES instead: any tests/ or tools/ source that can originate
# outbound contact must carry a VIRP_LIVE_* opt-in guard.
#
# Detected primitives: a driver connect dispatch (->connect(), a libssh2
# handshake, a libcurl perform, or a raw AF_INET socket. AF_UNIX is not
# outbound and is deliberately not matched.
#
# The guard is in-source (a getenv that SKIPs unless set), matching
# tests/test_live.c and tests/test_driver_wazuh.c, so a guarded file is
# safe to run from any target.
.PHONY: check-live-fence
check-live-fence:
	@echo "=== checking live-contact sources are opt-in guarded ==="
	@fail=0; \
	for f in $$(ls tests/*.c tools/*.c 2>/dev/null); do \
	  if grep -qE '(->connect\(|libssh2_session_handshake\(|curl_easy_perform\(|socket\(AF_INET)' $$f; then \
	    if grep -q 'VIRP_LIVE_' $$f; then \
	      echo "    guarded: $$f"; \
	    else \
	      echo "FAIL: $$f can originate outbound network contact but has"; \
	      echo "      no VIRP_LIVE_* opt-in guard."; \
	      fail=1; \
	    fi; \
	  fi; \
	done; \
	if [ $$fail -ne 0 ]; then \
	  echo ""; \
	  echo "      Add an in-source guard that SKIPs unless the flag is set,"; \
	  echo "      as tests/test_live.c (VIRP_LIVE_SSH) and"; \
	  echo "      tests/test_driver_wazuh.c (VIRP_LIVE_WAZUH) do."; \
	  exit 1; \
	fi; \
	echo "  PASS: every live-capable test/tool source is opt-in guarded"

# Socket-path agreement — the daemon's compiled fallback
# (ONODE_SOCKET_PATH in include/virp_onode.h) and the client's default
# (ONODE_DEFAULT_SOCKET in src/virp_tool.c) must name the SAME socket, and
# neither may sit under /tmp.
#
# They had drifted: the client defaulted to /tmp/virp-onode.sock while the
# daemon defaulted to /run/virp/onode.sock, so out of the box the tool did
# not find the daemon — and /tmp is world-writable and shared, so a
# pre-created socket or symlink there is a local attack vector that
# SO_PEERCRED does not defend against (it authenticates the peer, not the
# path). Two constants in two files cannot be kept in step by review alone.
.PHONY: check-socket-path
check-socket-path:
	@echo "=== checking daemon/client socket-path agreement ==="
	@d=$$(sed -n 's/^#define[[:space:]]*ONODE_SOCKET_PATH[[:space:]]*"\(.*\)".*/\1/p' include/virp_onode.h); \
	 c=$$(sed -n 's/^#define[[:space:]]*ONODE_DEFAULT_SOCKET[[:space:]]*"\(.*\)".*/\1/p' src/virp_tool.c); \
	 if [ -z "$$d" ] || [ -z "$$c" ]; then \
	   echo "FAIL: could not read one of the defaults (daemon='$$d' client='$$c')"; exit 1; fi; \
	 if [ "$$d" != "$$c" ]; then \
	   echo "FAIL: socket-path drift."; \
	   echo "      daemon ONODE_SOCKET_PATH   = $$d  (include/virp_onode.h)"; \
	   echo "      client ONODE_DEFAULT_SOCKET = $$c  (src/virp_tool.c)"; \
	   echo "      They must name the same socket."; exit 1; fi; \
	 case "$$d" in /tmp/*) \
	   echo "FAIL: default socket '$$d' is under /tmp — world-writable and"; \
	   echo "      shared; a pre-created socket or symlink there is a local"; \
	   echo "      attack vector SO_PEERCRED does not defend against."; exit 1;; \
	 esac; \
	 echo "  PASS: daemon and client both default to $$d"

# Deploy unit-file check — a unit-file regression is invisible to the C
# battery. Approval mode refuses to start without a chain (see
# onode_setup_chain_and_approvals in src/virp_onode_prod.c), so the
# shipped unit MUST pass -c <chain.db> and -C <chain.key>.
# =========================================================================
# Deployment
#
# The installed artifacts live OUTSIDE any source worktree. This is the
# whole point: with ExecStart pointing into a git checkout, `make` in
# that checkout was a deployment, and Restart=always meant the next
# restart shipped it. Now a restart re-runs exactly what install-prod
# last put here, and installing is a deliberate act that refuses on a
# dirty tree.
# =========================================================================
VIRP_INSTALL_DIR ?= /usr/local/lib/virp
VIRP_INSTALL_BIN  = $(VIRP_INSTALL_DIR)/virp-onode-prod

# Scripts the unit executes. These are as load-bearing as the binary —
# an edit to render-devices.sh in a worktree would change daemon
# behaviour on the next restart just as surely as a rebuilt binary.
VIRP_INSTALL_SCRIPTS = deploy/render-devices.sh \
                       deploy/config-backup-access.sh \
                       deploy/evidence-access.sh \
                       deploy/netclaw-access.sh

# The timer-driven automations (autopilot cycle/comparator/chainwalk/
# corpus, config-backup, evidence) run these Python modules. They had the
# SAME defect as the daemon binary and it was missed at first: their units
# executed /opt/virp/autopilot/*.py, so an edit in the checkout changed
# what the next hourly timer ran. autopilot/ is self-contained — each
# entry point does sys.path.insert(0, dirname(__file__)) and imports only
# virp_autopilot — so installing the directory wholesale is sufficient.
VIRP_INSTALL_PY_DIR = $(VIRP_INSTALL_DIR)/autopilot
VIRP_INSTALL_PY     = autopilot/virp_autopilot.py \
                      autopilot/virp_config_backup.py \
                      autopilot/virp_evidence.py

.PHONY: install-prod
install-prod: prod deploy-capture
	@test -f $(ONODE_PROD) || { echo "FAIL: $(ONODE_PROD) was not built"; exit 1; }
	@st=$$(git status --porcelain 2>/dev/null); \
	 if [ -n "$$st" ]; then \
	     echo "FAIL: refusing to install from a dirty tree — what gets deployed"; \
	     echo "      must be exactly what a commit hash names:"; \
	     echo "$$st"; \
	     exit 1; \
	 fi
	@echo "=== installing to $(VIRP_INSTALL_DIR) (outside any worktree) ==="
	install -d -m 0755 $(VIRP_INSTALL_DIR)
	install -m 0755 $(ONODE_PROD) $(VIRP_INSTALL_BIN)
	install -m 0755 $(VIRP_INSTALL_SCRIPTS) $(VIRP_INSTALL_DIR)/
	install -d -m 0755 $(VIRP_INSTALL_PY_DIR)
	install -m 0644 $(VIRP_INSTALL_PY) $(VIRP_INSTALL_PY_DIR)/
	@echo
	@$(MAKE) --no-print-directory deploy-record

# The DEPLOYED.md stanza, generated rather than hand-written so it cannot
# drift from what is actually installed. Refuses on a dirty tree for the
# same reason install-prod does.
.PHONY: deploy-record
deploy-record:
	@test -f $(VIRP_INSTALL_BIN) || \
	    { echo "FAIL: $(VIRP_INSTALL_BIN) is not installed"; exit 1; }
	@st=$$(git status --porcelain 2>/dev/null); \
	 if [ -n "$$st" ]; then echo "FAIL: tree is dirty:"; echo "$$st"; exit 1; fi
	@echo "- **Commit**: \`$$(git rev-parse HEAD)\`"
	@echo "- **Branch**: \`$$(git rev-parse --abbrev-ref HEAD)\`"
	@echo "- **Tree at install**: clean (\`git status --porcelain\` empty)"
	@echo "- **Installed binary**: \`$(VIRP_INSTALL_BIN)\`"
	@echo "- **sha256**: \`$$(sha256sum $(VIRP_INSTALL_BIN) | awk '{print $$1}')\`"
	@for s in $(VIRP_INSTALL_SCRIPTS); do \
	    b=$$(basename $$s); \
	    echo "- **sha256** \`$(VIRP_INSTALL_DIR)/$$b\`: \`$$(sha256sum $(VIRP_INSTALL_DIR)/$$b | awk '{print $$1}')\`"; \
	 done
	@for s in $(VIRP_INSTALL_PY); do \
	    b=$$(basename $$s); \
	    echo "- **sha256** \`$(VIRP_INSTALL_PY_DIR)/$$b\`: \`$$(sha256sum $(VIRP_INSTALL_PY_DIR)/$$b | awk '{print $$1}')\`"; \
	 done

# =========================================================================
# Systemd units, capture and rollback
#
# install-prod above covers the binary, the unit's helper scripts and the
# autopilot Python. It does NOT cover the unit file itself, which is the
# third artifact class and the one that changes daemon CONFIGURATION
# rather than daemon code. Installing a unit is separated deliberately:
# it needs `systemctl daemon-reload` to take effect and it can change
# behaviour (environment, hardening, flags) without a single line of C
# changing.
# =========================================================================
VIRP_UNIT_SRC          = deploy/virp-onode.service
VIRP_UNIT_DST          = /etc/systemd/system/virp-onode.service
VIRP_DROPIN_DIR        = /etc/systemd/system/virp-onode.service.d
VIRP_WAZUH_DROPIN_SRC  = deploy/virp-onode-wazuh-lab.dropin.conf
VIRP_WAZUH_DROPIN_DST  = $(VIRP_DROPIN_DIR)/60-wazuh-lab.conf

# Where deploy-capture writes. One directory per capture, named by UTC
# timestamp, so rollback names a directory rather than a commit.
VIRP_CAPTURE_ROOT     ?= /var/backups/virp

# -------------------------------------------------------------------------
# deploy-capture — snapshot what is installed RIGHT NOW, before replacing
# it. This is what makes rollback a copy-back instead of a rebuild of an
# older commit: the bytes that were running are kept, so restoring them
# does not depend on the old source still building, on the toolchain, or
# on anyone identifying which commit produced them.
#
# Safe to run on a box with nothing installed yet: missing artifacts are
# recorded as absent rather than failing the capture.
# -------------------------------------------------------------------------
.PHONY: deploy-capture
deploy-capture:
	@ts=$$(date -u +%Y%m%dT%H%M%SZ); \
	 dst=$(VIRP_CAPTURE_ROOT)/$$ts; \
	 install -d -m 0700 $$dst; \
	 echo "=== capturing current install -> $$dst ==="; \
	 for f in $(VIRP_INSTALL_BIN) \
	          $(VIRP_INSTALL_DIR)/render-devices.sh \
	          $(VIRP_INSTALL_DIR)/config-backup-access.sh \
	          $(VIRP_INSTALL_DIR)/evidence-access.sh \
	          $(VIRP_INSTALL_DIR)/netclaw-access.sh; do \
	     if [ -f "$$f" ]; then cp -a "$$f" $$dst/; echo "  captured $$f"; \
	     else echo "  ABSENT   $$f"; fi; \
	 done; \
	 install -d -m 0700 $$dst/autopilot; \
	 for f in $(VIRP_INSTALL_PY_DIR)/*.py; do \
	     [ -f "$$f" ] && { cp -a "$$f" $$dst/autopilot/; echo "  captured $$f"; }; \
	 done; \
	 install -d -m 0700 $$dst/systemd; \
	 if [ -f $(VIRP_UNIT_DST) ]; then cp -a $(VIRP_UNIT_DST) $$dst/systemd/; \
	     echo "  captured $(VIRP_UNIT_DST)"; else echo "  ABSENT   $(VIRP_UNIT_DST)"; fi; \
	 if [ -d $(VIRP_DROPIN_DIR) ]; then cp -a $(VIRP_DROPIN_DIR) $$dst/systemd/dropins; \
	     echo "  captured $(VIRP_DROPIN_DIR)/"; fi; \
	 ( cd $$dst && find . -type f ! -name MANIFEST.sha256 -exec sha256sum {} \; | sort ) \
	     > $$dst/MANIFEST.sha256; \
	 echo "  wrote    $$dst/MANIFEST.sha256"; \
	 ln -sfn $$dst $(VIRP_CAPTURE_ROOT)/latest; \
	 echo; \
	 echo "  Roll back to this exact state with:"; \
	 echo "    sudo make rollback-prod ROLLBACK_FROM=$$dst"

# -------------------------------------------------------------------------
# install-units — the canonical unit only.
#
# The Wazuh lab drop-in is NOT installed here and that is the point: the
# canonical unit validates the Wazuh manager's certificate, and disabling
# that is a deliberate, manual act (see install-wazuh-lab-dropin). Wiring
# it into the default install path is exactly the defect ef6cfa6c fixed.
#
# Runs daemon-reload so systemd sees the new unit. Does NOT restart —
# restarting is a separate, deliberate step.
# -------------------------------------------------------------------------
# NOTE the prerequisite is check-deploy-unit-source, NOT check-deploy-unit.
# The full check now includes check-unit-drift, whose REMEDY is running
# install-units — depending on it here would mean a drifted host could
# not be repaired with make until it was already repaired. The source
# assertions (chain flags, no worktree Exec paths, no build-at-start, no
# VIRP_WAZUH_INSECURE in the canonical unit) still gate every install.
.PHONY: install-units
install-units: check-deploy-unit-source
	@test -f $(VIRP_UNIT_SRC) || { echo "FAIL: $(VIRP_UNIT_SRC) missing"; exit 1; }
	@st=$$(git status --porcelain 2>/dev/null); \
	 if [ -n "$$st" ]; then \
	     echo "FAIL: refusing to install a unit from a dirty tree:"; echo "$$st"; exit 1; fi
	install -d -m 0755 $(VIRP_DROPIN_DIR)
	install -m 0644 $(VIRP_UNIT_SRC) $(VIRP_UNIT_DST)
	systemctl daemon-reload
	@echo
	@echo "  Installed $(VIRP_UNIT_DST) and reloaded systemd."
	@echo "  NOT restarted — the new unit takes effect on the next restart."
	@echo "  If this host collects from a self-signed Wazuh manager, install"
	@echo "  the drop-in BEFORE restarting or Wazuh collection will fail:"
	@echo "    sudo make install-wazuh-lab-dropin"

# -------------------------------------------------------------------------
# install-wazuh-lab-dropin — opt-in, never automatic.
#
# Restores VIRP_WAZUH_INSECURE=1 for a lab manager presenting a
# self-signed certificate. This DISABLES certificate validation for the
# Wazuh driver. Only for a lab manager on a trusted segment; the real fix
# is VIRP_CA_BUNDLE pointing at the CA that signed the manager's cert.
# -------------------------------------------------------------------------
# install-devices-template — the device template is the THIRD artifact
# class (binary, unit, config) and until 2026-08-09 it had no install
# path at all: /etc/virp/devices.template.json was placed by hand, so
# the tracked file and the running one could diverge with nothing to
# notice — the same shape as the virp-onode.service drift found the same
# day. Explicit, never automatic: rendering happens at daemon start, so
# installing a template changes what the NEXT restart authenticates as.
#
# Refuses on a dirty tree for the reason install-prod does: what gets
# deployed must be exactly what a commit hash names.
VIRP_DEVICES_TEMPLATE_SRC = deploy/devices.template.json
VIRP_DEVICES_TEMPLATE_DST = /etc/virp/devices.template.json

.PHONY: install-devices-template
install-devices-template:
	@test -f $(VIRP_DEVICES_TEMPLATE_SRC) || \
	    { echo "FAIL: $(VIRP_DEVICES_TEMPLATE_SRC) missing"; exit 1; }
	@st=$$(git status --porcelain 2>/dev/null); \
	 if [ -n "$$st" ]; then \
	     echo "FAIL: refusing to install a template from a dirty tree:"; \
	     echo "$$st"; exit 1; fi
	@python3 -c "import json,sys; json.load(open('$(VIRP_DEVICES_TEMPLATE_SRC)'.replace(chr(36)+'{','')))" \
	    2>/dev/null || true
	install -m 0644 $(VIRP_DEVICES_TEMPLATE_SRC) $(VIRP_DEVICES_TEMPLATE_DST)
	@echo "  Installed $(VIRP_DEVICES_TEMPLATE_DST)."
	@echo "  It takes effect at the NEXT virp-onode restart, when"
	@echo "  render-devices.sh substitutes autopilot.env into it. A"
	@echo "  placeholder named here and absent there is FATAL at render,"
	@echo "  so the daemon will refuse to start rather than authenticate"
	@echo "  as a literal \$${TOKEN}. See tests/test_render_devices.sh."

.PHONY: install-wazuh-lab-dropin
install-wazuh-lab-dropin:
	@test -f $(VIRP_WAZUH_DROPIN_SRC) || \
	    { echo "FAIL: $(VIRP_WAZUH_DROPIN_SRC) missing"; exit 1; }
	install -d -m 0755 $(VIRP_DROPIN_DIR)
	install -m 0644 $(VIRP_WAZUH_DROPIN_SRC) $(VIRP_WAZUH_DROPIN_DST)
	systemctl daemon-reload
	@echo "  Installed $(VIRP_WAZUH_DROPIN_DST) — Wazuh TLS validation is now"
	@echo "  DISABLED for this host on the next restart. Remove it with:"
	@echo "    sudo rm $(VIRP_WAZUH_DROPIN_DST) && sudo systemctl daemon-reload"

# -------------------------------------------------------------------------
# rollback-prod — copy back a captured install. No rebuild, no git.
#
#   sudo make rollback-prod ROLLBACK_FROM=/var/backups/virp/<timestamp>
#   sudo make rollback-prod ROLLBACK_FROM=$(VIRP_CAPTURE_ROOT)/latest
#
# Verifies the capture's own manifest first, so a corrupted or partial
# capture is refused rather than half-restored. Does NOT restart.
# -------------------------------------------------------------------------
.PHONY: rollback-prod
rollback-prod:
	@test -n "$(ROLLBACK_FROM)" || \
	    { echo "FAIL: set ROLLBACK_FROM=<capture dir> (see $(VIRP_CAPTURE_ROOT))"; exit 1; }
	@test -d "$(ROLLBACK_FROM)" || \
	    { echo "FAIL: $(ROLLBACK_FROM) is not a directory"; exit 1; }
	@test -f "$(ROLLBACK_FROM)/MANIFEST.sha256" || \
	    { echo "FAIL: $(ROLLBACK_FROM)/MANIFEST.sha256 missing — not a capture"; exit 1; }
	@echo "=== verifying capture integrity ==="
	@cd "$(ROLLBACK_FROM)" && sha256sum --quiet -c MANIFEST.sha256 || \
	    { echo "FAIL: capture does not match its manifest; refusing to restore"; exit 1; }
	@echo "=== restoring from $(ROLLBACK_FROM) ==="
	@if [ -f "$(ROLLBACK_FROM)/virp-onode-prod" ]; then \
	     install -m 0755 "$(ROLLBACK_FROM)/virp-onode-prod" $(VIRP_INSTALL_BIN); \
	     echo "  restored $(VIRP_INSTALL_BIN)"; fi
	@for b in render-devices.sh config-backup-access.sh evidence-access.sh netclaw-access.sh; do \
	     if [ -f "$(ROLLBACK_FROM)/$$b" ]; then \
	         install -m 0755 "$(ROLLBACK_FROM)/$$b" $(VIRP_INSTALL_DIR)/$$b; \
	         echo "  restored $(VIRP_INSTALL_DIR)/$$b"; fi; \
	 done
	@if [ -d "$(ROLLBACK_FROM)/autopilot" ]; then \
	     install -d -m 0755 $(VIRP_INSTALL_PY_DIR); \
	     for f in "$(ROLLBACK_FROM)"/autopilot/*.py; do \
	         [ -f "$$f" ] && { install -m 0644 "$$f" $(VIRP_INSTALL_PY_DIR)/; \
	             echo "  restored $(VIRP_INSTALL_PY_DIR)/$$(basename $$f)"; }; \
	     done; fi
	@if [ -f "$(ROLLBACK_FROM)/systemd/virp-onode.service" ]; then \
	     install -m 0644 "$(ROLLBACK_FROM)/systemd/virp-onode.service" $(VIRP_UNIT_DST); \
	     echo "  restored $(VIRP_UNIT_DST)"; \
	     systemctl daemon-reload; fi
	@echo
	@echo "  Restored. NOT restarted — run when you are ready:"
	@echo "    sudo systemctl restart virp-onode && systemctl status virp-onode"

# Lint: the PBS driver must have NO way to weaken its certificate pin.
#
# Scoped deliberately to the PBS sources. driver_wazuh.c does carry a
# VIRP_WAZUH_INSECURE escape hatch for the lab manager's self-signed cert;
# that is pre-existing, documented in the unit file, and out of scope
# here — it is not silently blessed by this target's narrower reach.
#
# The word "insecure" is NOT banned: this driver's comments say, at
# length, that it has no insecure mode, and a lint that forbade saying so
# would be a lint against documentation. What is banned is the machinery
# an escape hatch would need.
.PHONY: check-pbs-pin
check-pbs-pin:
	@echo "=== checking the PBS driver has no TLS escape hatch ==="
	@if grep -nE 'CURLOPT_SSL_VERIFY(PEER|HOST)[[:space:]]*,[[:space:]]*0L?' \
	        src/drivers/driver_pbs.c; then \
	    echo "FAIL: PBS driver disables curl TLS verification"; exit 1; fi
	@if grep -n 'getenv' src/drivers/driver_pbs.c include/virp_driver_pbs.h; then \
	    echo "FAIL: the PBS driver reads an environment variable — no env var"; \
	    echo "      may exist that could weaken or bypass the certificate pin"; \
	    exit 1; fi
	@grep -q 'CURLOPT_SSL_VERIFYPEER, 1L' src/drivers/driver_pbs.c || \
	    { echo "FAIL: PBS driver does not enable CURLOPT_SSL_VERIFYPEER"; exit 1; }
	@grep -q 'SSL_CTX_set_cert_verify_callback' src/drivers/driver_pbs.c || \
	    { echo "FAIL: PBS driver has no pin verification callback"; exit 1; }
	@grep -q 'CURLOPT_FOLLOWLOCATION, 0L' src/drivers/driver_pbs.c || \
	    { echo "FAIL: PBS driver may follow redirects — a redirect is a URL"; \
	      echo "      the operation table did not derive"; exit 1; }
	@echo "  PASS: pin is mandatory, no env var, no redirect following"

# check-deploy-unit — the SOURCE assertions plus the installed-vs-tracked
# comparison.
#
# It was source-only until 2026-08-09, and that is how the last section
# below ("no VIRP_WAZUH_INSECURE in the canonical unit") stayed green
# for eight days while /etc/systemd/system/virp-onode.service carried
# exactly that line. The assertion was true of the file in git and false
# of the file that boots the daemon. Reading only the repo cannot detect
# that, by construction — so the drift comparison is now part of the
# same target rather than an optional extra somebody remembers to run.
.PHONY: check-deploy-unit
check-deploy-unit: check-deploy-unit-source check-unit-drift

# Installed vs tracked. Expected to FAIL on virp-lab today: the daemon
# unit carries VIRP_WAZUH_INSECURE=1 inline and virp-netclaw-egress.service
# is installed but tracked nowhere. Both are real; neither is silenced by
# widening deploy/unit-drift-allowlist.txt, which ships empty and says why.
.PHONY: check-unit-drift
check-unit-drift:
	@$(MAKE) --no-print-directory check-unit-drift-selftest
	@scripts/check-unit-drift.sh

# The checker must be able to fail. A drift checker that always passes is
# indistinguishable from a clean host — which is the failure mode being
# fixed here, one level up.
.PHONY: check-unit-drift-selftest
check-unit-drift-selftest:
	@echo "=== self-testing the unit drift checker ==="
	@scripts/check-unit-drift.sh --selftest

.PHONY: check-deploy-unit-source
check-deploy-unit-source:
	@echo "=== checking deploy/virp-onode.service for chain flags ==="
	@grep -Eq '^[[:space:]]*-c[[:space:]]+[^[:space:]]' deploy/virp-onode.service || \
	    { echo "FAIL: deploy/virp-onode.service is missing '-c <chain.db>' — approval mode will refuse to start"; exit 1; }
	@grep -Eq '^[[:space:]]*-C[[:space:]]+[^[:space:]]' deploy/virp-onode.service || \
	    { echo "FAIL: deploy/virp-onode.service is missing '-C <chain.key>' — approval mode will refuse to start"; exit 1; }
	@echo "  PASS: chain flags present in deploy/virp-onode.service"
	@echo "=== checking no unit executes a path inside a source worktree ==="
	@units=$$(ls deploy/*.service deploy/*.dropin.conf 2>/dev/null); \
	 bad=0; \
	 for u in $$units; do \
	     [ -f "$$u" ] || continue; \
	     if grep -E '^Exec(Start|StartPre|StartPost|Stop|Reload)=' "$$u" | \
	        grep -Eq '(/opt/virp|/root/|/home/|/build/|virp-dev)'; then \
	         echo "FAIL: $$u executes a path inside a source worktree —"; \
	         echo "      a restart would then deploy whatever the tree happens to hold."; \
	         grep -nE '^Exec(Start|StartPre|StartPost|Stop|Reload)=' "$$u" | \
	             grep -E '(/opt/virp|/root/|/home/|/build/|virp-dev)'; \
	         bad=1; \
	     fi; \
	 done; \
	 [ $$bad -eq 0 ] || exit 1
	@echo "  PASS: every Exec* path is an installed artifact"
	@echo "=== checking no unit rebuilds anything at start ==="
	@units=$$(ls deploy/*.service deploy/*.dropin.conf 2>/dev/null); \
	 bad=0; \
	 for u in $$units; do \
	     [ -f "$$u" ] || continue; \
	     if grep -E '^Exec[A-Za-z]*=' "$$u" | \
	        grep -Eq '(^|[^a-zA-Z])(make|gcc|cc|cargo|go build)([^a-zA-Z]|$$)'; then \
	         echo "FAIL: $$u builds at unit start — the CT 211 hazard."; \
	         bad=1; \
	     fi; \
	 done; \
	 [ $$bad -eq 0 ] || exit 1
	@echo "  PASS: no unit rebuilds from source at start"
	@echo "=== checking ExecStart matches the documented install path ==="
	@grep -Eq '^ExecStart=$(VIRP_INSTALL_BIN)([[:space:]]|\\\\|$$)' deploy/virp-onode.service || \
	    { echo "FAIL: ExecStart is not $(VIRP_INSTALL_BIN)"; exit 1; }
	@echo "  PASS: ExecStart=$(VIRP_INSTALL_BIN)"
	@echo "=== checking canonical unit does not disable Wazuh TLS ==="
	@if grep -Eq '^[[:space:]]*Environment=.*VIRP_WAZUH_INSECURE' deploy/virp-onode.service; then \
	     echo "FAIL: deploy/virp-onode.service sets VIRP_WAZUH_INSECURE —"; \
	     echo "      this disables Wazuh certificate validation for every"; \
	     echo "      install of the shipped unit. Insecure Wazuh is a manual,"; \
	     echo "      lab-only opt-in via deploy/virp-onode-wazuh-lab.dropin.conf."; \
	     exit 1; \
	 fi
	@echo "  PASS: no VIRP_WAZUH_INSECURE in canonical virp-onode.service (drop-in exempt)"

# Lint: fail build if sprintf( appears in src/ (use snprintf instead)
.PHONY: lint-sprintf
lint-sprintf:
	@echo "=== checking for banned sprintf in src/ ==="
	@if grep -rn 'sprintf(' src/ --include='*.c' --include='*.h' \
	     | grep -v '^src/third_party/' | grep -v 'snprintf('; then \
	     echo "FAIL: sprintf found — use snprintf"; exit 1; fi
	@echo "  PASS: no sprintf found"

# Lint: fail build if rand( or srand( appears in src/ outside driver_mock.c
.PHONY: lint-rand
lint-rand:
	@echo "=== checking for banned rand()/srand() in src/ ==="
	@if grep -rn 'rand(' src/ --include='*.c' | grep -v 'driver_mock.c' | grep -v 'RAND_bytes' | grep -v 'srand' | grep -v '/\*' | grep -v '^\s*//' ; then echo "FAIL: rand() found — use RAND_bytes"; exit 1; fi
	@if grep -rn 'srand(' src/ --include='*.c' | grep -v 'driver_mock.c' ; then echo "FAIL: srand() found — use RAND_bytes"; exit 1; fi
	@echo "  PASS: no banned rand/srand found"

# Lint: report any memcmp usage in src/ for human review (advisory, not fatal)
.PHONY: lint-memcmp
lint-memcmp:
	@echo "=== memcmp usage in src/ (advisory) ==="
	@grep -rn 'memcmp' src/ || echo "  (none found)"

# Structural check: no driver may reimplement the read-until-prompt loop.
# The four SSH drivers share src/virp_ssh_io.c; a private copy is how the
# four paths diverged in the first place (see SECURITY.md
# Observation-Body Integrity). Structural, not a hand-maintained list.
.PHONY: check-shared-readpath
check-shared-readpath:
	@echo "=== Checking SSH drivers use the shared read path ==="
	@fail=0; \
	for f in src/drivers/driver_cisco.c src/drivers/driver_asa.c \
	         src/drivers/driver_juniper.c src/driver_panos.c; do \
	  if grep -qE '^\s*static\s+ssize_t\s+[a-z_]*read_until_prompt' $$f; then \
	    echo "  FAIL: $$f defines its own read_until_prompt"; fail=1; \
	  fi; \
	  if ! grep -q 'virp_ssh_io.h' $$f; then \
	    echo "  FAIL: $$f does not include virp_ssh_io.h"; fail=1; \
	  fi; \
	  if grep -qE 'libssh2_channel_read' $$f | grep -v io_read; then \
	    :; \
	  fi; \
	done; \
	if [ $$fail -eq 0 ]; then echo "  OK: all four SSH drivers use the shared read path"; \
	else exit 1; fi

# ASan+UBSan test rebuild — runs full test suite under sanitizers
.PHONY: asan-test
asan-test:
	$(MAKE) clean
	$(MAKE) CC=gcc CFLAGS="$(CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer" \
	        LDFLAGS="$(LDFLAGS) -fsanitize=address,undefined"
	$(MAKE) CC=gcc CFLAGS="$(CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer" \
	        LDFLAGS="$(LDFLAGS) -fsanitize=address,undefined" $(TEST_SSH_IO) $(TEST_FG_SCRUB) $(TEST_CHAIN) \
	        $(TEST_OBSKEY) $(TEST_OBS_ED25519) $(TEST_OBS_FORGE) $(TEST_OBS_NEG)
	@echo "=== Running tests under ASan+UBSan ==="
	./$(TEST_BIN) 2>&1
	./$(TEST_ONODE) 2>&1
	./$(TEST_SSH_IO) 2>&1
	./$(TEST_FG_SCRUB) 2>&1
	./$(TEST_CHAIN) 2>&1
	./$(TEST_OBSKEY) 2>&1
	./$(TEST_OBS_ED25519) 2>&1
	./$(TEST_OBS_FORGE) 2>&1
	./$(TEST_OBS_NEG) 2>&1
	@echo "=== ASan+UBSan test run complete ==="
	# Leave no instrumented residue in the shared build/ tree. asan-test
	# already clean-builds at the start, so the tree is disposable; a
	# plain `make test-*` or the ctypes bridge (test-api) that links or
	# dlopens an ASan-instrumented artifact left here would fail with
	# '__asan_*' undefined-reference / 'ASan runtime does not come first'.
	# (asan-drivers is already isolated in build-asan-drivers/.) If asan-test
	# is INTERRUPTED before this line, run `make clean` once.
	@echo "=== cleaning instrumented build/ so later plain builds are safe ==="
	$(MAKE) --no-print-directory clean

# Driver suites under ASan+UBSan. Separate from asan-test because the
# driver objects need their -D guards, which are evaluated at Makefile
# parse time and so require a recursive $(MAKE) with the flags set.
#
# The PBS suites are the reason this exists: the typed-op parser is a
# hand-written byte-level state machine over attacker-supplied input,
# which is precisely the shape that needs a sanitizer rather than a
# passing assertion count.
.PHONY: asan-drivers
asan-drivers:
	rm -rf build-asan-drivers
	$(MAKE) BUILD_DIR=build-asan-drivers CC=gcc \
	        CFLAGS_EXTRA="-fsanitize=address,undefined -fno-omit-frame-pointer" \
	        LDFLAGS_EXTRA="-fsanitize=address,undefined" \
	        CISCO=1 PANOS=1 ASA=1 JUNIPER=1 FORTIGATE=1 LINUX=1 WAZUH=1 \
	        LIBRENMS=1 PBS=1 ZAMMAD=1 \
	        test-pbs test-pbs-gate test-typed-hash test-ingress-nul \
	        test-pbs-trunc test-linux-gate test-cisco-gate test-zammad-gate
	@echo "=== ASan+UBSan driver run complete ==="

# libFuzzer harness (requires clang)
FUZZ_LIBFUZZER = $(BUILD_DIR)/fuzz_libfuzzer

.PHONY: fuzz-libfuzzer
fuzz-libfuzzer: $(LIB)
	clang -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g \
	      -I./include tests/fuzz_libfuzzer.c $(LIB) $(LDFLAGS) \
	      -lstdc++ -o $(FUZZ_LIBFUZZER)
	@echo "Built $(FUZZ_LIBFUZZER) — run with: ./$(FUZZ_LIBFUZZER) [corpus_dir]"

# libFuzzer harness for the v3 public-key observation verifier — the
# most exposed parser in the tree (attacker bytes, no secret, run by
# third parties). Unlike fuzz-libfuzzer above, this target rebuilds
# libvirp itself with instrumentation (fuzzer-no-link+ASan+UBSan) into
# build-fuzz/ so coverage and sanitizers actually see the verifier's
# code, not just the harness.
FUZZ_OBS_DIR = build-fuzz
FUZZ_OBS_BIN = $(FUZZ_OBS_DIR)/fuzz_obs_ed25519

.PHONY: fuzz-obs-ed25519
fuzz-obs-ed25519:
	$(MAKE) BUILD_DIR=$(FUZZ_OBS_DIR) CC=clang \
	        CFLAGS_EXTRA="-fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer" \
	        $(FUZZ_OBS_DIR)/libvirp.a
	clang -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g \
	      -I./include -I./src/third_party tests/fuzz_obs_ed25519.c \
	      $(FUZZ_OBS_DIR)/libvirp.a $(LDFLAGS) -lstdc++ -o $(FUZZ_OBS_BIN)
	@echo "Built $(FUZZ_OBS_BIN) — run with: ./$(FUZZ_OBS_BIN) [corpus_dir]"

# Approval flow tests (propose -> approve -> apply). Depends on the CLI
# binary too: the suite drives `virp exec` / `virp chain tail` as
# subprocesses against a served test daemon.
TEST_APPROVAL = $(BUILD_DIR)/test_approval

$(TEST_APPROVAL): tests/test_approval.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-approval: $(TEST_APPROVAL) $(TOOL_BIN)
	./$(TEST_APPROVAL)

# Approver registry tests (Ed25519 + ECDSA-P256 verify, fixed KATs)
TEST_APPROVERS = $(BUILD_DIR)/test_approver_registry

$(TEST_APPROVERS): tests/test_approver_registry.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-approvers: $(TEST_APPROVERS)
	./$(TEST_APPROVERS)

# PKCS#11 approval signer (YubiKey PIV via OpenSC). Built into virp-tool
# only under VIRP_PKCS11 — uses the vendored minimal Cryptoki header and
# resolves the C_* entry points with dlsym at runtime.
$(BUILD_DIR)/virp_tool_pkcs11.o: src/virp_tool_pkcs11.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DVIRP_PKCS11 -c $< -o $@

.PHONY: virp-tool-pkcs11
virp-tool-pkcs11: $(LIB) $(BUILD_DIR)/virp_tool_pkcs11.o
	$(CC) $(CFLAGS) -DVIRP_PKCS11 -DVIRP_GIT_HASH='"$(GIT_HASH)"' \
	    src/virp_tool.c \
	    $(BUILD_DIR)/virp_tool_pkcs11.o $(LIB) $(LDFLAGS) -ldl \
	    -o $(BUILD_DIR)/virp-tool
	ln -f $(BUILD_DIR)/virp-tool $(BUILD_DIR)/virp

# Mock PKCS#11 module (test-only) — a shared object the signer dlopens.
$(BUILD_DIR)/mock_pkcs11.so: tests/mock_pkcs11.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -shared -fPIC $< -lcrypto -o $@

# PKCS#11 signer plumbing test: drive the signer against the mock module,
# verify the raw r||s signature through the daemon's registry verify path.
TEST_PKCS11 = $(BUILD_DIR)/test_pkcs11_plumbing

$(TEST_PKCS11): tests/test_pkcs11_plumbing.c $(BUILD_DIR)/virp_tool_pkcs11.o $(LIB)
	$(CC) $(CFLAGS) -DVIRP_PKCS11 $< $(BUILD_DIR)/virp_tool_pkcs11.o \
	    $(LIB) $(LDFLAGS) -ldl -o $@

test-pkcs11: $(TEST_PKCS11) $(BUILD_DIR)/mock_pkcs11.so
	./$(TEST_PKCS11)

# Response validator tests
TEST_VALIDATOR = $(BUILD_DIR)/test_validator

$(TEST_VALIDATOR): tests/test_validator.c $(LIB)
	rm -f $@
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-validator: $(TEST_VALIDATOR)
	./$(TEST_VALIDATOR)

# Opt-in end-to-end wire harness. Spins up virp-onode-prod and round-
# trips three cases through api/validator to prove the C dispatcher and
# the Python client agree on byte layout. Kept out of `make test` so the
# default suite stays fast and driver-free.
.PHONY: test-validator-e2e
test-validator-e2e: prod-full
	python3 tests/test_validator_e2e.py

# Python API server tests (auth guard, bind-safety guard, devices, key
# loading). Fenced like test-interop: skip with a warning when the API
# stack (fastapi/httpx) is absent, so all-tests stays runnable for a
# reviewer without the Python API dependencies rather than hard-failing.
.PHONY: test-api
test-api:
	@echo "=== VIRP API server tests (api/*.py) ==="
	@if python3 -c 'import fastapi, httpx' >/dev/null 2>&1; then \
	    if [ -f $(SHLIB) ] && nm $(SHLIB) 2>/dev/null | grep -q __asan; then \
	        echo "  NOTE: $(SHLIB) is ASan-instrumented — the ctypes bridge"; \
	        echo "        cannot dlopen it without the ASan runtime; rebuilding"; \
	        echo "        a plain libvirp.so."; \
	        $(MAKE) --no-print-directory clean >/dev/null; \
	    fi; \
	    $(MAKE) --no-print-directory shared >/dev/null; \
	    python3 -m pytest -q api/test_auth.py api/test_bind_guard.py \
	        api/test_devices.py api/test_gate_removed.py \
	        api/test_key_loading.py; \
	else \
	    echo "  *** SKIPPING test-api: fastapi/httpx not importable."; \
	    echo "      install them with: pip install fastapi httpx pytest"; \
	    echo "  *** The API auth + bind-safety guards are NOT covered in this run."; \
	fi

all-tests: check-deploy-unit check-pbs-pin check-live-fence check-socket-path check-shared-readpath test test-onode test-ssh-io test-fg-scrub test-cisco-scrub test-asa-scrub test-drivers test-autopilot test-config-backup test-render-devices test-evidence test-virp-report test-chain test-federation test-interop test-session test-session-key test-obs-v2 test-obskey test-obs-ed25519 test-obs-ed25519-forge test-obs-ed25519-neg test-validator test-approval test-approvers test-pkcs11 test-commitment-grading test-api
