/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — evidence-required intent/closer binding (Sep 1 review, 1.1-1.2)
 *
 * Crafts chains DIRECTLY through the library append path (which, unlike
 * the socket handler, is allowed to write the daemon-reserved gate_intent
 * / gate_execution / outcome types) and asserts what virp_chain_verify_
 * session() says about each. These are the C half of the parity pinned in
 * tests/test_open_execution_grading.py, and the crafted chains are the
 * fixtures Phase 4 (Docket) reuses.
 *
 * The properties under test (all structural-integrity FAILs, i.e. valid
 * cleared + first_broken set, distinct from an OPEN execution which is
 * reported and never a failure):
 *   - two gate_intent entries citing one approval entry hash  -> FAIL
 *   - two closers citing one gate_intent                      -> FAIL
 *   - a closer citing a hash that is not a gate_intent        -> FAIL
 *   - a closer whose device disagrees with its intent         -> FAIL
 *   - a matched approved-apply intent + outcome               -> VALID, closed
 *   - an intent with no closer                                -> VALID, open
 *
 * No live device, no socket. Private /tmp chain, cleaned each run.
 */
#define _POSIX_C_SOURCE 200809L

#include "virp_chain.h"
#include "virp_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>

static const char *DB  = "/tmp/virp-evbind-chain.db";
static const char *WAL = "/tmp/virp-evbind-chain.db-wal";
static const char *SHM = "/tmp/virp-evbind-chain.db-shm";
static const char *KEY = "/tmp/virp-evbind-chain.key";
static const char *SESSION = "gate-enforce:PVE-LAB";
static const char *APPROVAL_SESSION = "approval:PVE-LAB";

static int tests_run, tests_failed;
#define CHECK(cond, msg) do {                                          \
    if (!(cond)) { printf("    FAIL: %s\n", (msg)); tests_failed++; }   \
} while (0)
#define BEGIN(name) do { printf("  [TEST] %s\n", (name)); tests_run++; } while (0)

static void cleanup(void) { unlink(DB); unlink(WAL); unlink(SHM); unlink(KEY); }

static void sha256_hex(const char *s, char out[65])
{
    unsigned char md[32]; unsigned int n = 0;
    EVP_Digest(s, strlen(s), md, &n, EVP_sha256(), NULL);
    for (int i = 0; i < 32; i++) snprintf(out + i * 2, 3, "%02x", md[i]);
}

/* Append a crafted body under an arbitrary reserved type; return the
 * committed entry's chain_entry_hash via out_hash (may be NULL). */
static int craft(virp_chain_state_t *ch, const char *session,
                 const char *type, const char *id_prefix,
                 const char *body, char out_hash[65])
{
    char ahash[65]; sha256_hex(body, ahash);
    char aid[128]; snprintf(aid, sizeof(aid), "%s-%.16s", id_prefix, ahash);
    virp_chain_entry_t ce;
    if (virp_chain_append_with_artifact(ch, session, type, aid, ahash,
                                        body, &ce) != VIRP_OK)
        return -1;
    if (out_hash) snprintf(out_hash, 65, "%s", ce.chain_entry_hash);
    return 0;
}

static virp_chain_state_t *fresh(void)
{
    cleanup();
    static virp_chain_state_t ch;
    virp_signing_key_t k;
    if (virp_key_generate(&k, VIRP_KEY_TYPE_CHAIN) != VIRP_OK) return NULL;
    if (virp_key_save_file(&k, KEY) != VIRP_OK) return NULL;
    virp_key_destroy(&k);
    if (virp_chain_init(&ch, DB, KEY, 0xDEAD0008, "local") != VIRP_OK)
        return NULL;
    return &ch;
}

static void intent_body(char *buf, size_t cap, const char *approval_hash,
                        const char *device)
{
    snprintf(buf, cap,
        "{\"schema\":\"gate_intent/1\",\"device\":\"%s\",\"driver\":\"mock\","
        "\"command\":\"reload\",\"classified_tier\":\"RED\","
        "\"decision\":\"approved-apply\",\"uid\":null,\"session\":null,"
        "\"proposal_id\":\"p1\",\"approval_entry_hash\":%s%s%s}",
        device,
        approval_hash ? "\"" : "", approval_hash ? approval_hash : "null",
        approval_hash ? "\"" : "");
}

static void exec_body(char *buf, size_t cap, const char *intent_hash,
                      const char *device)
{
    snprintf(buf, cap,
        "{\"schema\":\"gate_execution/1\",\"device\":\"%s\",\"driver\":\"mock\","
        "\"command\":\"reload\",\"decision\":\"auto-execute\",\"uid\":null,"
        "\"session\":null,\"intent_entry_hash\":%s%s%s,\"executed\":true}",
        device,
        intent_hash ? "\"" : "", intent_hash ? intent_hash : "null",
        intent_hash ? "\"" : "");
}

static void outcome_body(char *buf, size_t cap, const char *intent_hash,
                         const char *approval_hash, const char *device)
{
    snprintf(buf, cap,
        "{\"proposal_id\":\"p1\",\"approval_entry_hash\":\"%s\","
        "\"device\":\"%s\",\"command_hash\":\"%s\",\"success\":true,"
        "\"intent_entry_hash\":\"%s\"}",
        approval_hash, device, "c0ffee", intent_hash);
}

/* Verify the given session; report valid + open/closed counters. */
static virp_chain_verify_result_t verify(virp_chain_state_t *ch,
                                         const char *session)
{
    virp_chain_verify_result_t r;
    memset(&r, 0, sizeof(r));
    virp_chain_verify_session(ch, session, &r);
    return r;
}

static void t_open_execution_is_valid(void)
{
    BEGIN("open execution: intent with no closer -> VALID, 1 open");
    virp_chain_state_t *ch = fresh();
    CHECK(ch != NULL, "chain init");
    char body[512]; intent_body(body, sizeof(body), "d0d0", "PVE-LAB");
    CHECK(craft(ch, SESSION, "gate_intent", "gateintent", body, NULL) == 0,
          "append intent");
    virp_chain_verify_result_t r = verify(ch, SESSION);
    CHECK(r.valid, "chain must be VALID (open execution is not a break)");
    CHECK(r.first_broken == -1, "no broken link");
    CHECK(r.executions_open == 1, "one open execution");
    CHECK(r.executions_closed == 0, "none closed");
    virp_chain_destroy(ch);
}

static void t_matched_apply_is_closed(void)
{
    BEGIN("approved apply: intent + matching outcome -> VALID, 1 closed");
    virp_chain_state_t *ch = fresh();
    char ib[512], ob[512], ih[65];
    intent_body(ib, sizeof(ib), "d0d0", "PVE-LAB");
    CHECK(craft(ch, SESSION, "gate_intent", "gateintent", ib, ih) == 0, "intent");
    outcome_body(ob, sizeof(ob), ih, "d0d0", "PVE-LAB");
    CHECK(craft(ch, APPROVAL_SESSION, "outcome", "outcome:p1", ob, NULL) == 0,
          "outcome");
    virp_chain_verify_result_t r = verify(ch, SESSION);
    CHECK(r.valid, "VALID");
    CHECK(r.executions_closed == 1, "one closed (cross-session outcome)");
    CHECK(r.executions_open == 0, "none open");
    virp_chain_destroy(ch);
}

static void t_double_spend_fail(void)
{
    BEGIN("two intents, one approval hash -> FAIL (double-spend)");
    virp_chain_state_t *ch = fresh();
    char b1[512], b2[512];
    intent_body(b1, sizeof(b1), "d0d0", "PVE-LAB");
    intent_body(b2, sizeof(b2), "d0d0", "PVE-LAB");  /* same approval hash */
    /* bodies differ only if something else differs; force distinct ids by
     * appending under different sessions so both commit. */
    CHECK(craft(ch, SESSION, "gate_intent", "gateintent", b1, NULL) == 0, "i1");
    CHECK(craft(ch, "gate-enforce:PVE-LAB-2", "gate_intent", "gateintent2",
                b2, NULL) == 0, "i2");
    virp_chain_verify_result_t r = verify(ch, SESSION);
    CHECK(!r.valid, "must FAIL");
    CHECK(strstr(r.error_detail, "double-spend") != NULL,
          "reason names double-spend");
    virp_chain_destroy(ch);
}

static void t_two_closers_fail(void)
{
    BEGIN("two closers cite one intent -> FAIL");
    virp_chain_state_t *ch = fresh();
    char ib[512], e1[512], e2[512], ih[65];
    intent_body(ib, sizeof(ib), NULL, "PVE-LAB");
    CHECK(craft(ch, SESSION, "gate_intent", "gateintent", ib, ih) == 0, "intent");
    exec_body(e1, sizeof(e1), ih, "PVE-LAB");
    exec_body(e2, sizeof(e2), ih, "OTHER");  /* differ so ids differ */
    CHECK(craft(ch, SESSION, "gate_execution", "gateexec1", e1, NULL) == 0, "c1");
    CHECK(craft(ch, SESSION, "gate_execution", "gateexec2", e2, NULL) == 0, "c2");
    virp_chain_verify_result_t r = verify(ch, SESSION);
    CHECK(!r.valid, "must FAIL");
    CHECK(strstr(r.error_detail, "Two closers") != NULL, "reason names two closers");
    virp_chain_destroy(ch);
}

static void t_closer_wrong_type_fail(void)
{
    BEGIN("closer cites a non-intent hash -> FAIL");
    virp_chain_state_t *ch = fresh();
    /* An observation-typed entry, then a gate_execution citing ITS hash. */
    char oh[65];
    CHECK(craft(ch, SESSION, "observation", "obs:PVE-LAB",
                "{\"schema\":\"observation/1\"}", oh) == 0, "observation");
    char e[512]; exec_body(e, sizeof(e), oh, "PVE-LAB");
    CHECK(craft(ch, SESSION, "gate_execution", "gateexec", e, NULL) == 0, "closer");
    virp_chain_verify_result_t r = verify(ch, SESSION);
    CHECK(!r.valid, "must FAIL");
    CHECK(strstr(r.error_detail, "not a gate_intent") != NULL,
          "reason names wrong type");
    virp_chain_destroy(ch);
}

static void t_binding_mismatch_fail(void)
{
    BEGIN("closer device disagrees with intent -> FAIL");
    virp_chain_state_t *ch = fresh();
    char ib[512], e[512], ih[65];
    intent_body(ib, sizeof(ib), NULL, "PVE-LAB");
    CHECK(craft(ch, SESSION, "gate_intent", "gateintent", ib, ih) == 0, "intent");
    exec_body(e, sizeof(e), ih, "OTHER-DEVICE");  /* wrong device */
    CHECK(craft(ch, SESSION, "gate_execution", "gateexec", e, NULL) == 0, "closer");
    virp_chain_verify_result_t r = verify(ch, SESSION);
    CHECK(!r.valid, "must FAIL");
    CHECK(strstr(r.error_detail, "binding disagrees") != NULL,
          "reason names binding mismatch");
    virp_chain_destroy(ch);
}

int main(void)
{
    printf("\n=== VIRP evidence-required binding (1.1-1.2) ===\n");
    t_open_execution_is_valid();
    t_matched_apply_is_closed();
    t_double_spend_fail();
    t_two_closers_fail();
    t_closer_wrong_type_fail();
    t_binding_mismatch_fail();
    cleanup();
    printf("=== Results: %d tests, %d failed ===\n", tests_run, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
