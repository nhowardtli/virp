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
LDFLAGS = -lcrypto -lpthread -lsqlite3 -lsodium

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

# SSH host key verification — included when any SSH driver is enabled
ifneq (,$(or $(CISCO),$(FORTIGATE),$(PANOS),$(ASA),$(JUNIPER),$(LINUX)))
  LIB_OBJS += $(BUILD_DIR)/virp_ssh_hostkey.o
endif

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

$(BUILD_DIR)/virp_ssh_hostkey.o: src/virp_ssh_hostkey.c | $(BUILD_DIR)
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

$(LIB): $(LIB_OBJS)
	ar rcs $@ $^

$(SHLIB): $(LIB_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

$(TEST_BIN): tests/test_virp.c $(LIB)
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(FUZZ_BIN): tests/fuzz_virp.c $(LIB)
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

# Chain and Federation tests
TEST_CHAIN = $(BUILD_DIR)/test_chain
TEST_FED   = $(BUILD_DIR)/test_federation

$(TEST_CHAIN): tests/test_chain.c $(LIB)
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

$(TEST_FED): tests/test_federation.c $(LIB)
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
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-live: $(LIVE_TEST)
	./$(LIVE_TEST)

# Production O-Node (with device config loading via json-c)
ONODE_PROD = $(BUILD_DIR)/virp-onode-prod

$(ONODE_PROD): src/virp_onode_prod.c $(LIB)
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -ljson-c -o $@

# 'make prod' builds the prod O-Node with all production drivers enabled,
# including PAN-OS. Uses recursive $(MAKE) because the driver guards are
# `ifdef PANOS` / `ifdef CISCO` / etc., which are evaluated at Makefile
# parse time — target-specific variable assignments (`prod: PANOS := 1`)
# would not reach those guards. Kept distinct from `prod-full` so either
# name works and callers have a single driver-enabled build entry point.
.PHONY: prod
prod:
	$(MAKE) CISCO=1 FORTIGATE=1 PANOS=1 ASA=1 LINUX=1 WAZUH=1 JUNIPER=1 $(ONODE_PROD)

# Full production build — recursive make ensures all ifdef guards evaluate correctly
# SSH host key verification is strict: unknown keys are rejected.
.PHONY: prod-full
prod-full:
	$(MAKE) CISCO=1 FORTIGATE=1 PANOS=1 ASA=1 LINUX=1 WAZUH=1 JUNIPER=1 $(ONODE_PROD)

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
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

# Artifact-based C<->Go interop tests. VIRP_INTEROP_BIN points the Go
# tests at the freshly built local binary so they run pre-deploy
# (unset, they fall back to the deployed /opt/virp/build path). The
# live-daemon test is NOT run here — it is fenced behind
# VIRP_LIVE_INTEROP=1 (see live-interop below) so the default battery
# never touches a live device.
test-interop: $(TEST_INTEROP)
	cd $(GO_DIR) && VIRP_INTEROP_BIN=$(abspath $(TEST_INTEROP)) \
		go test ./virp/ -run TestInterop -v -count=1

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
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@
endif

test-cisco: $(TEST_CISCO)
	./$(TEST_CISCO)

# Cisco IOS/IOS-XE gate-classifier tests (build with CISCO=1)
TEST_CISCO_GATE = $(BUILD_DIR)/test_driver_cisco_gate

$(TEST_CISCO_GATE): tests/test_driver_cisco_gate.c $(LIB)
ifndef CISCO
	@echo "ERROR: test-cisco-gate requires CISCO=1 — driver objects are not in libvirp.a."
	@echo "       Run:  make CISCO=1 test-cisco-gate"
	@echo "       Or:   make test-drivers   (builds every driver and runs all driver suites)"
	@false
else
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@
endif

test-cisco-gate: $(TEST_CISCO_GATE)
	./$(TEST_CISCO_GATE)

# Concurrent onode_execute smoke test (connection lifetime race)
TEST_ONODE_CONC = $(BUILD_DIR)/test_onode_concurrency

$(TEST_ONODE_CONC): tests/test_onode_concurrency.c $(LIB)
	$(CC) $(CFLAGS) tests/test_onode_concurrency.c $(LIB) $(LDFLAGS) -o $@

test-onode-concurrency: $(TEST_ONODE_CONC)
	./$(TEST_ONODE_CONC)

# Wazuh driver tests (requires WAZUH=1 and live Wazuh Manager)
TEST_WAZUH = $(BUILD_DIR)/test_driver_wazuh

$(TEST_WAZUH): tests/test_driver_wazuh.c $(LIB)
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-wazuh: $(TEST_WAZUH)
	./$(TEST_WAZUH)

# Session negative-path tests
TEST_SESSION_NEG = $(BUILD_DIR)/test_session_negative

$(TEST_SESSION_NEG): tests/test_session_negative.c $(LIB)
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-session: $(TEST_SESSION_NEG)
	./$(TEST_SESSION_NEG)

# v2 observation negative tests (replay / staleness / substitution /
# session binding / wire format)
TEST_OBS_V2 = $(BUILD_DIR)/test_obs_v2

$(TEST_OBS_V2): tests/test_obs_v2.c $(LIB)
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-obs-v2: $(TEST_OBS_V2)
	./$(TEST_OBS_V2)

# Session key derivation tests
TEST_SESSION_KEY = $(BUILD_DIR)/test_session_key

$(TEST_SESSION_KEY): tests/test_session_key.c $(LIB)
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
	@echo "=== driver test suites (cisco, cisco-gate, juniper, asa, panos) ==="
	$(MAKE) BUILD_DIR=$(DRIVER_BUILD_DIR) CISCO=1 PANOS=1 ASA=1 JUNIPER=1 \
	        test-cisco test-cisco-gate test-juniper test-asa test-panos

# Deploy unit-file check — a unit-file regression is invisible to the C
# battery. Approval mode refuses to start without a chain (see
# onode_setup_chain_and_approvals in src/virp_onode_prod.c), so the
# shipped unit MUST pass -c <chain.db> and -C <chain.key>.
.PHONY: check-deploy-unit
check-deploy-unit:
	@echo "=== checking deploy/virp-onode.service for chain flags ==="
	@grep -Eq '^[[:space:]]*-c[[:space:]]+[^[:space:]]' deploy/virp-onode.service || \
	    { echo "FAIL: deploy/virp-onode.service is missing '-c <chain.db>' — approval mode will refuse to start"; exit 1; }
	@grep -Eq '^[[:space:]]*-C[[:space:]]+[^[:space:]]' deploy/virp-onode.service || \
	    { echo "FAIL: deploy/virp-onode.service is missing '-C <chain.key>' — approval mode will refuse to start"; exit 1; }
	@echo "  PASS: chain flags present in deploy/virp-onode.service"

# Lint: fail build if sprintf( appears in src/ (use snprintf instead)
.PHONY: lint-sprintf
lint-sprintf:
	@echo "=== checking for banned sprintf in src/ ==="
	@if grep -rn 'sprintf(' src/; then echo "FAIL: sprintf found — use snprintf"; exit 1; fi
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

# ASan+UBSan test rebuild — runs full test suite under sanitizers
.PHONY: asan-test
asan-test:
	$(MAKE) clean
	$(MAKE) CC=gcc CFLAGS="$(CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer" \
	        LDFLAGS="$(LDFLAGS) -fsanitize=address,undefined"
	@echo "=== Running tests under ASan+UBSan ==="
	./$(TEST_BIN) 2>&1
	./$(TEST_ONODE) 2>&1
	@echo "=== ASan+UBSan test run complete ==="

# libFuzzer harness (requires clang)
FUZZ_LIBFUZZER = $(BUILD_DIR)/fuzz_libfuzzer

.PHONY: fuzz-libfuzzer
fuzz-libfuzzer: $(LIB)
	clang -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g \
	      -I./include tests/fuzz_libfuzzer.c $(LIB) $(LDFLAGS) \
	      -lstdc++ -o $(FUZZ_LIBFUZZER)
	@echo "Built $(FUZZ_LIBFUZZER) — run with: ./$(FUZZ_LIBFUZZER) [corpus_dir]"

# Approval flow tests (propose -> approve -> apply). Depends on the CLI
# binary too: the suite drives `virp exec` / `virp chain tail` as
# subprocesses against a served test daemon.
TEST_APPROVAL = $(BUILD_DIR)/test_approval

$(TEST_APPROVAL): tests/test_approval.c $(LIB)
	$(CC) $(CFLAGS) $< $(LIB) $(LDFLAGS) -o $@

test-approval: $(TEST_APPROVAL) $(TOOL_BIN)
	./$(TEST_APPROVAL)

# Approver registry tests (Ed25519 + ECDSA-P256 verify, fixed KATs)
TEST_APPROVERS = $(BUILD_DIR)/test_approver_registry

$(TEST_APPROVERS): tests/test_approver_registry.c $(LIB)
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

all-tests: check-deploy-unit test test-onode test-drivers test-chain test-federation test-interop test-session test-session-key test-obs-v2 test-validator test-approval test-approvers test-pkcs11
