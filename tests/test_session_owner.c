/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — session ownership is bound to the SO_PEERCRED peer uid (V39 item 3)
 *
 * THE FINDING (Aug 4 "all-or-nothing", one layer up). There is exactly ONE
 * v2 session per daemon and, until this branch, it belonged to nobody: any
 * uid the socket allowlist admits could SESSION_HELLO over another uid's
 * live session, SESSION_BIND it, run v2 EXECUTE against it, or
 * SESSION_CLOSE it. The session key derives from the O-Key and the
 * handshake transcript — never from the peer — so nothing downstream told
 * the two callers apart. One principal's actions could be attested inside
 * another principal's session, and any allowed uid could destroy a session
 * it did not open.
 *
 * WHAT IS PINNED HERE
 *   - the decision itself (onode_session_owner_refused_locked): no owner
 *     recorded is permissive, the owner is permitted, a DIFFERENT uid is
 *     refused, and the internal (uid_t)-1 caller is not gated;
 *   - ownership LAPSES with the session, so the ordinary serial workflow
 *     (uid A opens, uses, closes; uid B then opens) is unchanged — the
 *     guard is against concurrent misuse, not a durable lease;
 *   - a v2 EXECUTE from a foreign uid is refused VIRP_ERR_SESSION_FORBIDDEN
 *     (-54) BEFORE the gate, so nothing reaches the device;
 *   - the same-uid path is byte-for-byte what it was;
 *   - the netclaw bridge's exact action sequence — session_hello,
 *     session_bind, execute, chain_append — still passes end to end over a
 *     real socket as one uid.
 *
 * WHY THE DECISION IS EXPORTED RATHER THAN DRIVEN THROUGH THE SOCKET. The
 * socket path cannot be exercised from two different uids without root, and
 * a guard that can only be checked by hand is a guard that rots. This is
 * the same discipline onode_uid_request_refused() already follows for the
 * per-uid action allowlist, and for the same reason.
 *
 * RED PROOF: delete the onode_session_owner_refused_locked() call from the
 * obs_version==2 pre-flight in onode_execute_obs_ex() and
 * test_v2_execute_cross_uid_refused FAILS (the foreign uid executes).
 */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "virp.h"
#include "virp_chain.h"
#include "virp_context.h"
#include "virp_crypto.h"
#include "virp_driver.h"
#include "virp_message.h"
#include "virp_onode.h"
#include "virp_session.h"

#include <arpa/inet.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int passed, failed;
#define TEST(name) do { printf("  [TEST] %-56s ", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(m)    do { printf("FAIL: %s (line %d)\n", m, __LINE__); failed++; } while (0)
#define ASSERT(c, m) do { if (!(c)) { FAIL(m); return; } } while (0)

extern void virp_driver_mock_init(void);
extern int  virp_driver_mock_exec_attempts_reset(void);

/* Two uids that are not this process's uid and not each other. The values
 * never reach the kernel — the decision function is being driven directly,
 * exactly as test_onode.c drives onode_uid_request_refused(). */
#define UID_A ((uid_t)4242)
#define UID_B ((uid_t)4243)

/* ─────────────────────────────────────────────────────────────────────
 * Part 1 — the decision
 * ───────────────────────────────────────────────────────────────────── */

static onode_state_t u;

static int unit_up(void)
{
    if (onode_init(&u, 0x5E550001, NULL, "/tmp/virp-sowner-unit.sock") != VIRP_OK)
        return -1;
    u.ctx = virp_context_new();
    return u.ctx ? 0 : -1;
}

static void unit_down(void)
{
    virp_context_t *c = u.ctx;
    onode_destroy(&u);
    virp_context_destroy(c);
    unlink("/tmp/virp-sowner-unit.sock");
}

static void test_no_owner_is_permissive(void)
{
    TEST("no owner recorded: every uid is admitted");
    ASSERT(!u.session_owner_valid, "fresh state must record no owner");
    ASSERT(!onode_session_owner_refused_locked(&u, UID_A), "uid A");
    ASSERT(!onode_session_owner_refused_locked(&u, UID_B), "uid B");
    ASSERT(!onode_session_owner_refused_locked(&u, (uid_t)-1), "internal");
    PASS();
}

static void test_owner_admitted_stranger_refused(void)
{
    TEST("owner admitted, a DIFFERENT uid refused");
    /* Claim ownership the way a completed HELLO does, and put the session
     * in a live state so the lapse rule does not clear it. */
    u.ctx->session.state = VIRP_SESSION_ACTIVE;
    u.session_owner_uid = UID_A;
    u.session_owner_valid = true;

    ASSERT(!onode_session_owner_refused_locked(&u, UID_A), "the owner");
    ASSERT(onode_session_owner_refused_locked(&u, UID_B), "a stranger");
    ASSERT(u.session_owner_valid, "a refusal must not clear ownership");
    PASS();
}

static void test_internal_caller_is_not_gated(void)
{
    TEST("(uid_t)-1 internal caller is not gated by ownership");
    u.ctx->session.state = VIRP_SESSION_ACTIVE;
    u.session_owner_uid = UID_A;
    u.session_owner_valid = true;
    /* The watchdog and the health probe have no peer credential. A SOCKET
     * request can never carry -1: onode_uid_request_refused() refuses an
     * unknown identity before the dispatch switch. */
    ASSERT(!onode_session_owner_refused_locked(&u, (uid_t)-1), "internal");
    PASS();
}

static void test_ownership_lapses_with_the_session(void)
{
    TEST("ownership lapses when the session is CLOSED/DISCONNECTED");
    u.ctx->session.state = VIRP_SESSION_ACTIVE;
    u.session_owner_uid = UID_A;
    u.session_owner_valid = true;

    u.ctx->session.state = VIRP_SESSION_CLOSED;
    ASSERT(!onode_session_owner_refused_locked(&u, UID_B),
           "uid B may open a session after uid A closed one");
    ASSERT(!u.session_owner_valid, "the stale record is cleared");

    u.session_owner_uid = UID_A;
    u.session_owner_valid = true;
    u.ctx->session.state = VIRP_SESSION_DISCONNECTED;
    ASSERT(!onode_session_owner_refused_locked(&u, UID_B),
           "a disconnected session is owned by nobody");
    ASSERT(!u.session_owner_valid, "cleared on disconnect too");
    PASS();
}

static void test_mid_handshake_states_stay_owned(void)
{
    TEST("NEGOTIATED / BOUND are still owned (the steal window)");
    /* The window the item exists to close: uid A has HELLO'd but not yet
     * BOUND. If ownership only attached at ACTIVE, uid B could BIND uid
     * A's half-finished handshake. */
    const virp_session_state_t live[] = {
        VIRP_SESSION_NEGOTIATED, VIRP_SESSION_BOUND, VIRP_SESSION_ACTIVE
    };
    for (size_t i = 0; i < sizeof(live) / sizeof(live[0]); i++) {
        u.session_owner_uid = UID_A;
        u.session_owner_valid = true;
        u.ctx->session.state = live[i];
        if (!onode_session_owner_refused_locked(&u, UID_B)) {
            FAIL("a stranger was admitted mid-handshake");
            return;
        }
    }
    PASS();
}

/* ─────────────────────────────────────────────────────────────────────
 * Part 2 — v2 EXECUTE
 * ───────────────────────────────────────────────────────────────────── */

static onode_state_t x;

static int exec_up(void)
{
    if (onode_init(&x, 0x5E550002, NULL, "/tmp/virp-sowner-exec.sock") != VIRP_OK)
        return -1;
    x.ctx = virp_context_new();
    if (!x.ctx) return -1;
    x.evidence_required = false;   /* no chain here; this is the uid gate */
    virp_device_t d;
    memset(&d, 0, sizeof(d));
    snprintf(d.hostname, sizeof(d.hostname), "SOWNER-DEV");
    snprintf(d.host, sizeof(d.host), "10.255.5.5");
    d.port = 22; d.vendor = VIRP_VENDOR_MOCK;
    d.node_id = 0x5E5E5E5E; d.enabled = true;
    return onode_add_device(&x, &d) == VIRP_OK ? 0 : -1;
}

static void exec_down(void)
{
    virp_context_t *c = x.ctx;
    onode_destroy(&x);
    virp_context_destroy(c);
    unlink("/tmp/virp-sowner-exec.sock");
}

static void test_v2_execute_cross_uid_refused(void)
{
    TEST("v2 EXECUTE from a foreign uid: -54, nothing dispatched");
    x.ctx->session.state = VIRP_SESSION_ACTIVE;
    x.ctx->session.session_key_valid = 1;
    x.session_owner_uid = UID_A;
    x.session_owner_valid = true;

    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = 0;
    (void)virp_driver_mock_exec_attempts_reset();
    virp_error_t rc = onode_execute_obs_ex(&x, "SOWNER-DEV", "show version",
                                           2, NULL, UID_B,
                                           buf, sizeof(buf), &len);
    ASSERT(rc == VIRP_ERR_SESSION_FORBIDDEN, "must be SESSION_FORBIDDEN (-54)");
    ASSERT(virp_driver_mock_exec_attempts_reset() == 0,
           "the device must not be touched");
    /* Distinct from -30: the session is perfectly valid, it is just not
     * this caller's. Collapsing the two would send an operator hunting a
     * dead session that is alive and well. */
    ASSERT(rc != VIRP_ERR_SESSION_INVALID, "-54 must not be -30");
    PASS();
}

static void test_v2_execute_owner_is_unchanged(void)
{
    TEST("v2 EXECUTE by the owner: unchanged");
    x.ctx->session.state = VIRP_SESSION_ACTIVE;
    x.ctx->session.session_key_valid = 1;
    x.session_owner_uid = UID_A;
    x.session_owner_valid = true;

    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = 0;
    virp_error_t rc = onode_execute_obs_ex(&x, "SOWNER-DEV", "show version",
                                           2, NULL, UID_A,
                                           buf, sizeof(buf), &len);
    /* The session key here is a test fixture, not a derived one, so the
     * signing step may still refuse — what must NOT happen is a refusal at
     * the OWNERSHIP step. -54 is the only forbidden answer. */
    ASSERT(rc != VIRP_ERR_SESSION_FORBIDDEN, "the owner must not be refused");
    PASS();
}

static void test_v2_execute_unowned_session_is_unchanged(void)
{
    TEST("v2 EXECUTE with no owner recorded: unchanged (pre-branch shape)");
    x.ctx->session.state = VIRP_SESSION_ACTIVE;
    x.ctx->session.session_key_valid = 1;
    x.session_owner_valid = false;

    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = 0;
    virp_error_t rc = onode_execute_obs_ex(&x, "SOWNER-DEV", "show version",
                                           2, NULL, UID_B,
                                           buf, sizeof(buf), &len);
    ASSERT(rc != VIRP_ERR_SESSION_FORBIDDEN,
           "nothing is owned, so nothing is refused");
    PASS();
}

static void test_v1_execute_is_never_gated(void)
{
    TEST("v1 EXECUTE is never gated by session ownership");
    x.ctx->session.state = VIRP_SESSION_ACTIVE;
    x.session_owner_uid = UID_A;
    x.session_owner_valid = true;

    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = 0;
    (void)virp_driver_mock_exec_attempts_reset();
    virp_error_t rc = onode_execute_obs_ex(&x, "SOWNER-DEV", "show version",
                                           1, NULL, UID_B,
                                           buf, sizeof(buf), &len);
    /* A v1 observation is signed with the O-Key and carries no session, so
     * there is no session to misattribute it to. Gating it would be a
     * behaviour change with no security content. */
    ASSERT(rc == VIRP_OK, "v1 must still execute");
    ASSERT(virp_driver_mock_exec_attempts_reset() == 1, "the device acted");
    PASS();
}

/* ─────────────────────────────────────────────────────────────────────
 * Part 3 — the netclaw bridge sequence, end to end, one uid
 * ───────────────────────────────────────────────────────────────────── */

#define BR_SOCKET   "/tmp/virp-sowner-bridge.sock"
#define BR_CHAIN_DB "/tmp/virp-sowner-bridge.db"
#define BR_CHAIN_KEY "/tmp/virp-sowner-bridge.key"

static onode_state_t br;
static pthread_t br_tid;

static void *br_thread(void *a) { (void)a; onode_start(&br); return NULL; }

static void br_files(void)
{
    unlink(BR_CHAIN_DB); unlink(BR_CHAIN_DB "-wal");
    unlink(BR_CHAIN_DB "-shm"); unlink(BR_CHAIN_KEY); unlink(BR_SOCKET);
}

static int br_start(void)
{
    br_files();
    virp_signing_key_t ck;
    if (virp_key_generate(&ck, VIRP_KEY_TYPE_CHAIN) != VIRP_OK) return -1;
    if (virp_key_save_file(&ck, BR_CHAIN_KEY) != VIRP_OK) return -1;
    virp_key_destroy(&ck);

    if (onode_init(&br, 0x5E550003, NULL, BR_SOCKET) != VIRP_OK) return -1;
    br.ctx = virp_context_new();
    if (!br.ctx) return -1;
    br.evidence_required = false;
    virp_device_t d;
    memset(&d, 0, sizeof(d));
    snprintf(d.hostname, sizeof(d.hostname), "BRIDGE-DEV");
    snprintf(d.host, sizeof(d.host), "10.255.6.6");
    d.port = 22; d.vendor = VIRP_VENDOR_MOCK;
    d.node_id = 0x5E5E6666; d.enabled = true;
    if (onode_add_device(&br, &d) != VIRP_OK) return -1;
    if (virp_chain_init(&br.chain, BR_CHAIN_DB, BR_CHAIN_KEY, 0x5E550003,
                        "local") != VIRP_OK) return -1;
    br.chain_enabled = true;
    if (pthread_create(&br_tid, NULL, br_thread, NULL) != 0) return -1;
    for (int i = 0; i < 200; i++) {
        if (access(BR_SOCKET, F_OK) == 0) return 0;
        usleep(20000);
    }
    return -1;
}

static void br_stop(void)
{
    onode_shutdown(&br);
    int poke = socket(AF_UNIX, SOCK_STREAM, 0);
    if (poke >= 0) {
        struct sockaddr_un a;
        memset(&a, 0, sizeof(a));
        a.sun_family = AF_UNIX;
        snprintf(a.sun_path, sizeof(a.sun_path), "%s", BR_SOCKET);
        (void)connect(poke, (struct sockaddr *)&a, sizeof(a));
        close(poke);
    }
    pthread_join(br_tid, NULL);
    onode_destroy(&br);
    virp_context_destroy(br.ctx);
    br.ctx = NULL;
    br_files();
}

/* Framed request/response, same shape as the bridge's own client. */
static ssize_t br_request(const char *json, uint8_t *resp, size_t cap)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", BR_SOCKET);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }
    size_t jl = strlen(json);
    uint32_t fl = htonl((uint32_t)(1 + jl));
    uint8_t ver = VIRP_FRAME_VERSION;
    if (send(fd, &fl, 4, 0) != 4 || send(fd, &ver, 1, 0) != 1 ||
        send(fd, json, jl, 0) != (ssize_t)jl) { close(fd); return -1; }

    uint32_t nrl;
    if (recv(fd, &nrl, 4, MSG_WAITALL) != 4) { close(fd); return -1; }
    uint32_t rl = ntohl(nrl);
    if (rl > cap) { close(fd); return -1; }
    size_t got = 0;
    while (got < rl) {
        ssize_t n = recv(fd, resp + got, rl - got, 0);
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(fd);
    return (ssize_t)got;
}

static int32_t br_err(const uint8_t *r)
{
    uint32_t net; memcpy(&net, r, 4); return (int32_t)ntohl(net);
}

/* Pull "key":"value" out of a JSON response. */
static int br_field(const char *json, const char *key, char *out, size_t cap)
{
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    const char *e = strchr(p, '"');
    if (!e || (size_t)(e - p) >= cap) return -1;
    memcpy(out, p, (size_t)(e - p));
    out[e - p] = '\0';
    return 0;
}

static void test_bridge_sequence_one_uid(void)
{
    TEST("netclaw sequence: hello, bind, execute, chain_append (one uid)");
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    char body[4096];
    char sid[64] = "", cn[64] = "", sn[64] = "";

    /* 1. session_hello */
    ssize_t n = br_request(
        "{\"action\":\"session_hello\",\"client_id\":\"netclaw-bridge\","
        "\"versions\":\"2,1\",\"algorithms\":\"1\","
        "\"client_nonce\":\"a1a2a3a4a5a6a7a8\",\"supported_channels\":1}",
        resp, sizeof(resp));
    ASSERT(n > 4, "hello must return a HELLO_ACK, not a typed error");
    size_t bl = (size_t)n < sizeof(body) - 1 ? (size_t)n : sizeof(body) - 1;
    memcpy(body, resp, bl); body[bl] = '\0';
    ASSERT(br_field(body, "session_id", sid, sizeof(sid)) == 0, "session_id");
    ASSERT(br_field(body, "client_nonce", cn, sizeof(cn)) == 0, "client_nonce");
    ASSERT(br_field(body, "server_nonce", sn, sizeof(sn)) == 0, "server_nonce");

    /* The daemon recorded THIS process's uid as the owner. */
    ASSERT(br.session_owner_valid, "HELLO must claim ownership");
    ASSERT(br.session_owner_uid == getuid(), "owner is the peer uid");

    /* 2. session_bind */
    char json[1024];
    snprintf(json, sizeof(json),
             "{\"action\":\"session_bind\",\"client_id\":\"netclaw-bridge\","
             "\"session_id\":\"%s\",\"client_nonce\":\"%s\","
             "\"server_nonce\":\"%s\"}", sid, cn, sn);
    n = br_request(json, resp, sizeof(resp));
    ASSERT(n > 4, "bind must not be refused");
    bl = (size_t)n < sizeof(body) - 1 ? (size_t)n : sizeof(body) - 1;
    memcpy(body, resp, bl); body[bl] = '\0';
    ASSERT(strstr(body, "\"status\":\"bound\"") != NULL, "bound");

    /* 3. execute (v2, session-bound) */
    n = br_request("{\"action\":\"execute\",\"device\":\"BRIDGE-DEV\","
                   "\"command\":\"show version\",\"obs_version\":2}",
                   resp, sizeof(resp));
    ASSERT(n > 4, "v2 execute must return an observation");
    ASSERT(br_err(resp) != VIRP_ERR_SESSION_FORBIDDEN,
           "the owner must never be refused its own session");

    /* 4. chain_append */
    const char *content = "{\"schema\":\"federated_request/1\","
                          "\"peer\":\"netclaw\"}";
    unsigned char md[32]; unsigned int mdl = 0;
    char hash[65];
    EVP_Digest(content, strlen(content), md, &mdl, EVP_sha256(), NULL);
    for (int i = 0; i < 32; i++) snprintf(hash + i * 2, 3, "%02x", md[i]);
    char esc[256]; size_t o = 0;
    for (const char *p = content; *p && o + 2 < sizeof(esc); p++) {
        if (*p == '"' || *p == '\\') esc[o++] = '\\';
        esc[o++] = *p;
    }
    esc[o] = '\0';
    snprintf(json, sizeof(json),
             "{\"action\":\"chain_append\",\"session_id\":\"fed:sowner\","
             "\"artifact_type\":\"fed_request\","
             "\"artifact_id\":\"sowner-bridge-1\","
             "\"artifact_hash\":\"%s\",\"artifact_content\":\"%s\"}",
             hash, esc);
    n = br_request(json, resp, sizeof(resp));
    ASSERT(n > 0, "chain_append must answer");
    ASSERT(!(n == 4 && br_err(resp) == VIRP_ERR_SESSION_FORBIDDEN),
           "chain_append must not be gated by session ownership");

    /* 5. session_close, by the owner */
    n = br_request("{\"action\":\"session_close\"}", resp, sizeof(resp));
    ASSERT(n > 4, "the owner may close its own session");
    ASSERT(!br.session_owner_valid, "close releases ownership");
    PASS();
}

int main(void)
{
    printf("\n=== VIRP session ownership (SO_PEERCRED binding) ===\n");
    virp_driver_mock_init();

    printf("\n[Decision]\n");
    if (unit_up() != 0) { printf("  SETUP FAIL: unit_up\n"); return 1; }
    test_no_owner_is_permissive();
    test_owner_admitted_stranger_refused();
    test_internal_caller_is_not_gated();
    test_ownership_lapses_with_the_session();
    test_mid_handshake_states_stay_owned();
    unit_down();

    printf("\n[v2 EXECUTE]\n");
    if (exec_up() != 0) { printf("  SETUP FAIL: exec_up\n"); return 1; }
    test_v2_execute_cross_uid_refused();
    test_v2_execute_owner_is_unchanged();
    test_v2_execute_unowned_session_is_unchanged();
    test_v1_execute_is_never_gated();
    exec_down();

    printf("\n[Bridge sequence, one uid, over a real socket]\n");
    if (br_start() != 0) { printf("  SETUP FAIL: br_start\n"); return 1; }
    test_bridge_sequence_one_uid();
    br_stop();

    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
