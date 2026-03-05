# Copyright (c) 2026 Third Level IT LLC. All rights reserved.
# VIRP — Verified Intent Routing Protocol
#
# Build with Cisco driver:     make CISCO=1
# Build with FortiGate driver: make FORTIGATE=1
# Build both:                  make CISCO=1 FORTIGATE=1
# Build without (default):     make

CC      = gcc
CFLAGS  = -Wall -Wextra -Werror -pedantic -std=c11 -O2 -g
CFLAGS += -I./include
LDFLAGS = -lcrypto -lpthread -lsqlite3 -lsodium

BUILD_DIR = build

# Core library objects
LIB_OBJS  = $(BUILD_DIR)/virp_crypto.o \
             $(BUILD_DIR)/virp_message.o \
             $(BUILD_DIR)/virp_driver.o \
             $(BUILD_DIR)/driver_mock.o \
             $(BUILD_DIR)/virp_onode.o \
             $(BUILD_DIR)/virp_chain.o \
             $(BUILD_DIR)/virp_federation.o

# Optional Cisco driver (requires libssh2)
ifdef CISCO
  CFLAGS  += -DVIRP_DRIVER_CISCO
  LDFLAGS += -lssh2
  LIB_OBJS += $(BUILD_DIR)/driver_cisco.o
endif

# Optional FortiGate driver (requires libcurl + libssh2)
ifdef FORTIGATE
  CFLAGS  += -DVIRP_DRIVER_FORTINET
  LDFLAGS += -lcurl
  # libssh2 may already be linked via CISCO; add only if not already present
  ifndef CISCO
    LDFLAGS += -lssh2
  endif
  LIB_OBJS += $(BUILD_DIR)/driver_fortigate.o
endif

LIB          = $(BUILD_DIR)/libvirp.a
TEST_BIN     = $(BUILD_DIR)/test_virp
FUZZ_BIN     = $(BUILD_DIR)/fuzz_virp
TOOL_BIN     = $(BUILD_DIR)/virp-tool
ONODE_BIN    = $(BUILD_DIR)/virp-onode
TEST_ONODE   = $(BUILD_DIR)/test_onode

.PHONY: all clean test fuzz test-onode test-chain test-federation

all: $(LIB) $(TEST_BIN) $(FUZZ_BIN) $(TOOL_BIN) $(ONODE_BIN) $(TEST_ONODE)

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

$(BUILD_DIR)/virp_onode.o: src/virp_onode.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/virp_chain.o: src/virp_chain.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/virp_federation.o: src/virp_federation.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB): $(LIB_OBJS)
	ar rcs $@ $^

$(TEST_BIN): tests/test_virp.c $(LIB)
	$(CC) $(CFLAGS) $< -L$(BUILD_DIR) -lvirp $(LDFLAGS) -o $@

$(FUZZ_BIN): tests/fuzz_virp.c $(LIB)
	$(CC) $(CFLAGS) $< -L$(BUILD_DIR) -lvirp $(LDFLAGS) -o $@

$(TOOL_BIN): src/virp_tool.c $(LIB)
	$(CC) $(CFLAGS) $< -L$(BUILD_DIR) -lvirp $(LDFLAGS) -o $@

$(ONODE_BIN): src/virp_onode_main.c src/virp_onode_json.c $(LIB)
	$(CC) $(CFLAGS) src/virp_onode_main.c src/virp_onode_json.c -L$(BUILD_DIR) -lvirp $(LDFLAGS) -o $@

$(TEST_ONODE): tests/test_onode.c $(LIB)
	$(CC) $(CFLAGS) $< -L$(BUILD_DIR) -lvirp $(LDFLAGS) -o $@

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
	$(CC) $(CFLAGS) $< -L$(BUILD_DIR) -lvirp $(LDFLAGS) -o $@

$(TEST_FED): tests/test_federation.c $(LIB)
	$(CC) $(CFLAGS) $< -L$(BUILD_DIR) -lvirp $(LDFLAGS) -o $@

test-chain: $(TEST_CHAIN)
	./$(TEST_CHAIN)

test-federation: $(TEST_FED)
	./$(TEST_FED)

clean:
	rm -rf $(BUILD_DIR)

LIVE_TEST = $(BUILD_DIR)/virp-live-test

$(LIVE_TEST): tests/test_live.c $(LIB)
	$(CC) $(CFLAGS) $< -L$(BUILD_DIR) -lvirp $(LDFLAGS) -o $@

test-live: $(LIVE_TEST)
	./$(LIVE_TEST)

# Production O-Node (with device config loading via json-c)
ONODE_PROD = $(BUILD_DIR)/virp-onode-prod

$(ONODE_PROD): src/virp_onode_prod.c $(LIB)
	$(CC) $(CFLAGS) $< -L$(BUILD_DIR) -lvirp $(LDFLAGS) -ljson-c -o $@

prod: $(ONODE_PROD)

all-tests: test test-onode test-chain test-federation
