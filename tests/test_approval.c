/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Approval flow tests (propose → approve → apply)
 *
 * Coverage:
 *   negatives (each asserting its DISTINCT code): expired (-36),
 *     reused (-37), hash mismatch (-38), device mismatch (-39), bad
 *     signature / altered payload / wrong-algorithm (-40), not found
 *     (-41), consumed proposal (-42), unenrolled key (-43), disabled
 *     key (-44), plain block with no approval reference.
 *   positive: library e2e (challenge→submit→apply→OUTCOME linked) and a
 *     CLI e2e through the framed socket with a software approver key.
 *   L1 fix: challenge + submit both refuse a proposal that already has
 *     an OUTCOME (-42).
 *   persistence: a consumed approval stays rejected across a restart.
 *   concurrency: two simultaneous submits for one proposal → exactly one
 *     APPROVAL chain entry.
 *   fail-safe: a registry enrolling no usable key leaves the flow off.
 * Approvals are signed over the padding-free canonical payload and
 * verified through the approver registry (Ed25519 here; ECDSA-P256 KAT
 * lives in test_approver_registry / test_pkcs11_plumbing).
 */

#define _DEFAULT_SOURCE         /* usleep */
#define _POSIX_C_SOURCE 200809L

#include "virp.h"
#include "virp_approval.h"
#include "virp_approver_registry.h"
#include "virp_chain.h"
#include "virp_crypto.h"
#include "virp_federation.h"
#include "virp_message.h"
#include "virp_onode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>   /* chmod — L2 unreadable-store regression */
#include <errno.h>
#include <sqlite3.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { printf("  [TEST] %-52s ", name); } while (0)

#define PASS() \
    do { printf("PASS\n"); tests_passed++; } while (0)

#define FAIL(msg) \
    do { printf("FAIL: %s (line %d)\n", msg, __LINE__); tests_failed++; } while (0)

#define ASSERT(cond, msg) \
    do { if (!(cond)) { FAIL(msg); return; } } while (0)

static const char *DIR       = "/tmp/virp-test-approvals";
static const char *CHAIN_DB  = "/tmp/virp-test-approval-chain.db";
static const char *CHAIN_KEY = "/tmp/virp-test-approval-chain.key";
static const char *REGISTRY  = "/tmp/virp-test-approvers.json";

extern void virp_driver_mock_init(void);

static onode_state_t g;
static virp_fed_keypair_t g_kp;      /* the enrolled Ed25519 approver key */

/* Write an approvers.json enrolling g_kp (Ed25519). `enabled` toggles the
 * entry's enabled flag; `bad` writes a corrupt-SPKI entry instead so the
 * loader skips it (used to prove the flow stays disabled). */
static int write_registry(const char *path, bool enabled, bool bad)
{
    char entry[1024];
    if (bad) {
        snprintf(entry, sizeof(entry),
            "{\"key_id\":\"00000000000000000000000000000000\","
            "\"algorithm\":\"ed25519\",\"public_key\":\"bm90LWEta2V5\","
            "\"operator\":\"nobody\",\"enabled\":true}");
    } else {
        uint8_t spki[44];
        virp_approver_ed25519_spki(g_kp.public_key, spki);
        if (virp_approver_entry_json(spki, sizeof(spki), "test-operator",
                                     enabled, entry, sizeof(entry)) != VIRP_OK)
            return -1;
    }
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "[%s]\n", entry);
    fclose(f);
    return 0;
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void nuke_store(void)
{
    char cmd[512];
    /* test-scoped tmp paths only */
    snprintf(cmd, sizeof(cmd), "rm -rf %s", DIR);
    if (system(cmd) != 0) { /* best-effort */ }
    unlink(CHAIN_DB);
    unlink(REGISTRY);
    unlink(CHAIN_KEY);
}

/* Bring up a socketless onode with two mock devices, chain enabled,
 * approval store configured. Reuses on-disk state left by a previous
 * call (that is the point of the restart test). */
static int onode_up(onode_state_t *st)
{
    if (onode_init(st, 0xA9900001, NULL, "/tmp/virp-test-approval.sock")
            != VIRP_OK)
        return -1;
    st->ctx = virp_context_new();
    if (!st->ctx) return -1;

    virp_device_t dev;
    memset(&dev, 0, sizeof(dev));
    snprintf(dev.hostname, sizeof(dev.hostname), "R-APP");
    snprintf(dev.host, sizeof(dev.host), "10.255.1.1");
    dev.port = 22; dev.vendor = VIRP_VENDOR_MOCK;
    dev.node_id = 0xA0A0A0A1; dev.enabled = true;
    if (onode_add_device(st, &dev) != VIRP_OK) return -1;

    snprintf(dev.hostname, sizeof(dev.hostname), "R-APP2");
    dev.node_id = 0xA0A0A0A2;
    if (onode_add_device(st, &dev) != VIRP_OK) return -1;

    if (virp_chain_init(&st->chain, CHAIN_DB, CHAIN_KEY, st->node_id,
                        "test-org") != VIRP_OK)
        return -1;
    st->chain_enabled = true;

    if (onode_set_approvers(st, DIR, REGISTRY) != VIRP_OK)
        return -1;
    return 0;
}

static void onode_down(onode_state_t *st)
{
    virp_context_t *ctx = st->ctx;
    onode_destroy(st);
    virp_context_destroy(ctx);
}

/* Execute (optionally with an approval reference) and parse the signed
 * response. Returns 0 on success; fills obs_type/tier/payload. */
static int run_cmd(onode_state_t *st, const char *device, const char *cmd,
                   const char *proposal_id,
                   uint8_t *obs_type, uint8_t *tier,
                   char *payload, size_t payload_len)
{
    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = 0;
    if (onode_execute_obs_ex(st, device, cmd, 1, proposal_id,
                             (uid_t)-1,
                             buf, sizeof(buf), &len) != VIRP_OK)
        return -1;
    virp_header_t hdr;
    if (virp_validate_message(buf, len, &st->okey, &hdr) != VIRP_OK)
        return -2;
    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    if (virp_parse_observation(buf + VIRP_HEADER_SIZE, len - VIRP_HEADER_SIZE,
                               &obs, &data, &data_len) != VIRP_OK)
        return -3;
    *obs_type = obs.obs_type;
    *tier = hdr.tier;
    size_t n = data_len < payload_len - 1 ? data_len : payload_len - 1;
    memcpy(payload, data, n);
    payload[n] = '\0';
    return 0;
}

/* Extract "proposal_id=<32hex>" from a rejection payload. */
static int extract_pid(const char *payload, char *pid_out)
{
    const char *p = strstr(payload, "proposal_id=");
    if (!p) return -1;
    p += strlen("proposal_id=");
    if (strspn(p, "0123456789abcdef") < VIRP_APPROVAL_ID_HEX_LEN)
        return -1;
    memcpy(pid_out, p, VIRP_APPROVAL_ID_HEX_LEN);
    pid_out[VIRP_APPROVAL_ID_HEX_LEN] = '\0';
    return 0;
}

/* Block a fresh RED command and return its proposal id. */
static int propose_via_block(onode_state_t *st, const char *device,
                             const char *cmd, char *pid_out)
{
    uint8_t ot, tier;
    char payload[2048];
    if (run_cmd(st, device, cmd, NULL, &ot, &tier, payload,
                sizeof(payload)) != 0)
        return -1;
    if (ot != VIRP_OBS_ERROR) return -2;
    return extract_pid(payload, pid_out);
}

static void keyid_hex(const virp_fed_keypair_t *kp, char out[33])
{
    for (int i = 0; i < VIRP_FED_KEYID_SIZE; i++)
        snprintf(out + i * 2, 3, "%02x", kp->key_id[i]);
}

/* Full library-level approve: challenge -> sign canonical with kp ->
 * submit (daemon writes the APPROVAL chain entry). */
static virp_error_t do_approve_kp(const char *pid, const virp_fed_keypair_t *kp,
                                  virp_approval_rec_t *apr)
{
    virp_approval_challenge_t ch;
    virp_error_t err = virp_approval_challenge(DIR, &g.chain, pid, 0, &ch);
    if (err != VIRP_OK) return err;
    uint8_t sig[VIRP_APPROVER_SIG_SIZE];
    if (virp_fed_sign(kp, ch.canonical, VIRP_APPROVAL_CANON_SIZE, sig)
            != VIRP_OK)
        return VIRP_ERR_CRYPTO;
    char kid[33];
    keyid_hex(kp, kid);
    return virp_approval_submit(DIR, &g.approvers, &g.chain, pid, kid,
                                sig, sizeof(sig), apr);
}

static virp_error_t do_approve(const char *pid, virp_approval_rec_t *apr)
{
    return do_approve_kp(pid, &g_kp, apr);
}

/* Craft an approval record signed by kp over hostile canonical bytes
 * (arbitrary command_hash / device_node_id / approved_at / ttl) and write
 * it directly — bypassing challenge/submit — so apply-side checks can be
 * exercised against a validly-signed-but-hostile approval. */
static virp_error_t craft_record(const char *pid, const virp_fed_keypair_t *kp,
                                 const char *command_hash, const char *device,
                                 uint32_t node_id, uint64_t approved_at_ns,
                                 uint32_t ttl)
{
    uint8_t canon[VIRP_APPROVAL_CANON_SIZE];
    virp_error_t err = virp_approval_build_canonical(pid, command_hash, node_id,
                                                     approved_at_ns, ttl, canon);
    if (err != VIRP_OK) return err;
    uint8_t sig[VIRP_APPROVER_SIG_SIZE];
    if (virp_fed_sign(kp, canon, sizeof(canon), sig) != VIRP_OK)
        return VIRP_ERR_CRYPTO;

    virp_approval_rec_t rec;
    memset(&rec, 0, sizeof(rec));
    snprintf(rec.proposal_id, sizeof(rec.proposal_id), "%s", pid);
    snprintf(rec.command_hash, sizeof(rec.command_hash), "%s", command_hash);
    snprintf(rec.device, sizeof(rec.device), "%s", device);
    rec.device_node_id = node_id;
    rec.approved_at_ns = approved_at_ns;
    rec.ttl_seconds = ttl;
    keyid_hex(kp, rec.approver_key_id);
    return virp_approval_write_record(DIR, &rec, sig, sizeof(sig));
}

/* =========================================================================
 * Tests
 * ========================================================================= */

static char g_pid_e2e[VIRP_APPROVAL_ID_HEX_LEN + 1];   /* used across tests */

static void test_block_files_proposal(void)
{
    TEST("Gate block files PROPOSAL + returns proposal_id");
    uint8_t ot, tier;
    char payload[2048];
    ASSERT(run_cmd(&g, "R-APP", "reload", NULL, &ot, &tier, payload,
                   sizeof(payload)) == 0, "execute failed");
    ASSERT(ot == VIRP_OBS_ERROR, "rejection must be OBS_ERROR");
    ASSERT(tier == VIRP_TIER_RED, "rejection must carry true tier RED");
    ASSERT(strstr(payload, "tier gate blocked") != NULL,
           "existing block message missing");
    ASSERT(extract_pid(payload, g_pid_e2e) == 0,
           "rejection must carry proposal_id");

    /* Proposal record has the required fields */
    virp_proposal_rec_t prop;
    ASSERT(virp_approval_load_proposal(DIR, g_pid_e2e, &prop) == VIRP_OK,
           "proposal not on disk");
    ASSERT(strcmp(prop.device, "R-APP") == 0, "device mismatch");
    ASSERT(prop.device_node_id == 0xA0A0A0A1, "node_id mismatch");
    ASSERT(strcmp(prop.command, "reload") == 0, "command mismatch");
    ASSERT(strlen(prop.command_hash) == 64, "command_hash missing");
    ASSERT(prop.timestamp_ns > 0, "timestamp missing");
    ASSERT(prop.proposer[0] != '\0', "proposer missing");
    ASSERT(prop.chain_entry_hash[0] != '\0', "PROPOSAL chain entry missing");

    /* PROPOSAL chain entry is the latest for the approval session */
    virp_chain_entry_t ce;
    ASSERT(virp_chain_get_last(&g.chain, "approval:R-APP", &ce) == VIRP_OK,
           "no chain entry");
    ASSERT(strcmp(ce.artifact_type, "proposal") == 0, "not a proposal entry");
    PASS();
}

static void test_e2e_propose_approve_apply(void)
{
    TEST("E2E: propose -> approve -> apply -> OUTCOME linked");
    virp_approval_rec_t apr;
    ASSERT(do_approve(g_pid_e2e, &apr) == VIRP_OK, "approve failed");
    ASSERT(apr.ttl_seconds == VIRP_APPROVAL_TTL_SECONDS, "TTL not 300s");
    ASSERT(apr.chain_entry_hash[0] != '\0', "APPROVAL chain entry missing");
    ASSERT(strcmp(apr.operator, "test-operator") == 0,
           "APPROVAL must carry the enrolled operator");

    uint8_t ot, tier;
    char payload[2048];
    ASSERT(run_cmd(&g, "R-APP", "reload", g_pid_e2e, &ot, &tier, payload,
                   sizeof(payload)) == 0, "apply failed");
    /* The mock driver executed the command (it echoes hostname#cmd). */
    ASSERT(strstr(payload, "R-APP#reload") != NULL, "command did not execute");
    ASSERT(strstr(payload, "apply rejected") == NULL, "apply was rejected");

    /* OUTCOME entry present and linked to PROPOSAL + APPROVAL */
    virp_chain_entry_t ce;
    ASSERT(virp_chain_get_last(&g.chain, "approval:R-APP", &ce) == VIRP_OK,
           "no chain entry");
    ASSERT(strcmp(ce.artifact_type, "outcome") == 0, "latest not outcome");
    char want_id[64];
    snprintf(want_id, sizeof(want_id), "outcome:%s", g_pid_e2e);
    ASSERT(strcmp(ce.artifact_id, want_id) == 0, "outcome id mismatch");

    /* The whole approval session chain verifies and holds all three */
    virp_chain_verify_result_t vr;
    ASSERT(virp_chain_verify(&g.chain, "approval:R-APP", 0, ce.sequence, &vr)
               == VIRP_OK, "chain verify errored");
    ASSERT(vr.valid, "approval chain invalid");
    ASSERT(vr.entries_checked >= 3, "expected proposal+approval+outcome");
    PASS();
}

static void test_reused_approval_rejected(void)
{
    TEST("Negative: reused approval -> approval_reused (-37)");
    uint8_t ot, tier;
    char payload[2048];
    ASSERT(run_cmd(&g, "R-APP", "reload", g_pid_e2e, &ot, &tier, payload,
                   sizeof(payload)) == 0, "apply failed");
    ASSERT(ot == VIRP_OBS_ERROR, "second apply must be rejected");
    ASSERT(strstr(payload, "approval_reused") != NULL, "wrong failure mode");
    ASSERT(strstr(payload, "err=-37") != NULL, "wrong error code");
    ASSERT(strstr(payload, "R-APP#") == NULL, "command must not execute");
    PASS();
}

static void test_expired_approval_rejected(void)
{
    TEST("Negative: expired approval -> approval_expired (-36)");
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    ASSERT(propose_via_block(&g, "R-APP", "reload", pid) == 0,
           "propose failed");

    /* Craft a correctly-signed approval whose TTL has already elapsed. */
    virp_proposal_rec_t prop;
    ASSERT(virp_approval_load_proposal(DIR, pid, &prop) == VIRP_OK,
           "proposal missing");
    uint64_t elapsed = now_ns() -
        ((uint64_t)VIRP_APPROVAL_TTL_SECONDS + 100) * 1000000000ULL;
    ASSERT(craft_record(pid, &g_kp, prop.command_hash, prop.device,
                        prop.device_node_id, elapsed,
                        VIRP_APPROVAL_TTL_SECONDS) == VIRP_OK,
           "craft expired record failed");

    uint8_t ot, tier;
    char payload[2048];
    ASSERT(run_cmd(&g, "R-APP", "reload", pid, &ot, &tier, payload,
                   sizeof(payload)) == 0, "apply failed");
    ASSERT(ot == VIRP_OBS_ERROR, "expired apply must be rejected");
    ASSERT(strstr(payload, "approval_expired") != NULL, "wrong failure mode");
    ASSERT(strstr(payload, "err=-36") != NULL, "wrong error code");
    PASS();
}

static void test_hash_mismatch_rejected(void)
{
    TEST("Negative: different command -> approval_hash_mismatch (-38)");
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    ASSERT(propose_via_block(&g, "R-APP", "reload", pid) == 0,
           "propose failed");
    virp_approval_rec_t apr;
    ASSERT(do_approve(pid, &apr) == VIRP_OK, "approve failed");

    /* Apply a DIFFERENT (also RED) command under the same approval. */
    uint8_t ot, tier;
    char payload[2048];
    ASSERT(run_cmd(&g, "R-APP", "erase startup-config", pid, &ot, &tier,
                   payload, sizeof(payload)) == 0, "apply failed");
    ASSERT(ot == VIRP_OBS_ERROR, "must be rejected");
    ASSERT(strstr(payload, "approval_hash_mismatch") != NULL,
           "wrong failure mode");
    ASSERT(strstr(payload, "err=-38") != NULL, "wrong error code");
    PASS();
}

static void test_device_mismatch_rejected(void)
{
    TEST("Negative: different device -> approval_device_mismatch (-39)");
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    ASSERT(propose_via_block(&g, "R-APP", "reload", pid) == 0,
           "propose failed");
    virp_approval_rec_t apr;
    ASSERT(do_approve(pid, &apr) == VIRP_OK, "approve failed");

    uint8_t ot, tier;
    char payload[2048];
    ASSERT(run_cmd(&g, "R-APP2", "reload", pid, &ot, &tier, payload,
                   sizeof(payload)) == 0, "apply failed");
    ASSERT(ot == VIRP_OBS_ERROR, "must be rejected");
    ASSERT(strstr(payload, "approval_device_mismatch") != NULL,
           "wrong failure mode");
    ASSERT(strstr(payload, "err=-39") != NULL, "wrong error code");
    PASS();
}

static void test_unenrolled_key_rejected(void)
{
    TEST("Negative: unenrolled signing key -> approval_key_unenrolled (-43)");
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    ASSERT(propose_via_block(&g, "R-APP", "reload", pid) == 0,
           "propose failed");

    /* A rogue keypair (NOT in the registry) signs an otherwise-perfect
     * approval over correct canonical bytes. Its key_id resolves to
     * nothing enrolled, so the daemon rejects it as unenrolled before
     * ever checking the signature. */
    virp_fed_keypair_t rogue;
    ASSERT(virp_fed_generate(&rogue, 1) == VIRP_OK, "rogue keygen failed");
    virp_proposal_rec_t prop;
    ASSERT(virp_approval_load_proposal(DIR, pid, &prop) == VIRP_OK,
           "proposal missing");
    ASSERT(craft_record(pid, &rogue, prop.command_hash, prop.device,
                        prop.device_node_id, now_ns(),
                        VIRP_APPROVAL_TTL_SECONDS) == VIRP_OK,
           "craft rogue record failed");
    virp_fed_destroy(&rogue);

    uint8_t ot, tier;
    char payload[2048];
    ASSERT(run_cmd(&g, "R-APP", "reload", pid, &ot, &tier, payload,
                   sizeof(payload)) == 0, "apply failed");
    ASSERT(ot == VIRP_OBS_ERROR, "must be rejected");
    ASSERT(strstr(payload, "approval_key_unenrolled") != NULL,
           "wrong failure mode");
    ASSERT(strstr(payload, "err=-43") != NULL, "wrong error code");
    PASS();
}

static void test_no_approval_plain_block(void)
{
    TEST("Negative: no approval at all -> plain block unchanged");
    uint8_t ot, tier;
    char payload[2048];
    ASSERT(run_cmd(&g, "R-APP", "reload", NULL, &ot, &tier, payload,
                   sizeof(payload)) == 0, "execute failed");
    ASSERT(ot == VIRP_OBS_ERROR, "must be blocked");
    ASSERT(tier == VIRP_TIER_RED, "true tier");
    ASSERT(strstr(payload, "tier gate blocked") != NULL,
           "existing rejection changed");
    ASSERT(strstr(payload, "apply rejected") == NULL,
           "must not be an apply rejection");
    ASSERT(strstr(payload, "R-APP#") == NULL, "must not execute");

    /* Referencing a proposal that was never approved is its own,
     * distinct refusal. */
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    ASSERT(extract_pid(payload, pid) == 0, "no proposal id");
    ASSERT(run_cmd(&g, "R-APP", "reload", pid, &ot, &tier, payload,
                   sizeof(payload)) == 0, "apply failed");
    ASSERT(strstr(payload, "approval_not_found") != NULL,
           "unapproved apply must be approval_not_found");
    ASSERT(strstr(payload, "err=-41") != NULL, "wrong error code");
    PASS();
}

static void test_reuse_survives_restart(void)
{
    TEST("Persistence: reuse still rejected after restart");
    /* Fresh consumed approval... */
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    ASSERT(propose_via_block(&g, "R-APP", "reload", pid) == 0,
           "propose failed");
    virp_approval_rec_t apr;
    ASSERT(do_approve(pid, &apr) == VIRP_OK, "approve failed");
    uint8_t ot, tier;
    char payload[2048];
    ASSERT(run_cmd(&g, "R-APP", "reload", pid, &ot, &tier, payload,
                   sizeof(payload)) == 0, "apply failed");
    ASSERT(strstr(payload, "R-APP#reload") != NULL, "first apply must run");

    /* ...then a full daemon restart (new state, same on-disk store). */
    onode_down(&g);
    ASSERT(onode_up(&g) == 0, "restart failed");

    ASSERT(run_cmd(&g, "R-APP", "reload", pid, &ot, &tier, payload,
                   sizeof(payload)) == 0, "apply failed");
    ASSERT(ot == VIRP_OBS_ERROR, "replay after restart must be rejected");
    ASSERT(strstr(payload, "approval_reused") != NULL,
           "wrong failure mode after restart");
    ASSERT(strstr(payload, "err=-37") != NULL, "wrong error code");
    PASS();
}

/* Overwrite the on-disk approval record's stored command_hash with one
 * flipped hex nibble (leaving the signature untouched). Apply rebuilds
 * the canonical bytes from the altered hash, so the signature no longer
 * verifies. Returns 0 on success. */
static int flip_record_command_hash(const char *pid)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/approvals/%s.rec", DIR, pid);
    char buf[4096];
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    char *k = strstr(buf, "\"command_hash\":\"");
    if (!k) return -1;
    k += strlen("\"command_hash\":\"");
    k[0] = (k[0] == 'a') ? 'b' : 'a';   /* flip one hex digit */
    f = fopen(path, "w");
    if (!f) return -1;
    fwrite(buf, 1, strlen(buf), f);
    fclose(f);
    return 0;
}

static void test_disabled_key_rejected(void)
{
    TEST("Negative: disabled enrolled key -> approval_key_disabled (-44)");
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    ASSERT(propose_via_block(&g, "R-APP", "reload", pid) == 0, "propose");
    virp_proposal_rec_t prop;
    ASSERT(virp_approval_load_proposal(DIR, pid, &prop) == VIRP_OK, "load");
    /* Record validly signed by g_kp over correct canonical bytes. */
    ASSERT(craft_record(pid, &g_kp, prop.command_hash, prop.device,
                        prop.device_node_id, now_ns(),
                        VIRP_APPROVAL_TTL_SECONDS) == VIRP_OK, "craft");

    /* Reload the registry with g_kp DISABLED. */
    ASSERT(write_registry(REGISTRY, /*enabled=*/false, false) == 0, "reg");
    ASSERT(onode_set_approvers(&g, DIR, REGISTRY) == VIRP_OK, "reload reg");

    uint8_t ot, tier; char payload[2048];
    ASSERT(run_cmd(&g, "R-APP", "reload", pid, &ot, &tier, payload,
                   sizeof(payload)) == 0, "apply");
    ASSERT(ot == VIRP_OBS_ERROR, "must be rejected");
    ASSERT(strstr(payload, "approval_key_disabled") != NULL, "wrong mode");
    ASSERT(strstr(payload, "err=-44") != NULL, "wrong code");

    /* Restore the enabled registry for later tests. */
    ASSERT(write_registry(REGISTRY, true, false) == 0, "restore reg");
    ASSERT(onode_set_approvers(&g, DIR, REGISTRY) == VIRP_OK, "restore reload");
    PASS();
}

static void test_altered_payload_rejected(void)
{
    TEST("Negative: altered command_hash -> approval_bad_signature (-40)");
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    ASSERT(propose_via_block(&g, "R-APP", "reload", pid) == 0, "propose");
    virp_approval_rec_t apr;
    ASSERT(do_approve(pid, &apr) == VIRP_OK, "approve");
    /* Tamper the stored command_hash after signing. */
    ASSERT(flip_record_command_hash(pid) == 0, "flip");

    uint8_t ot, tier; char payload[2048];
    ASSERT(run_cmd(&g, "R-APP", "reload", pid, &ot, &tier, payload,
                   sizeof(payload)) == 0, "apply");
    ASSERT(ot == VIRP_OBS_ERROR, "must be rejected");
    ASSERT(strstr(payload, "approval_bad_signature") != NULL, "wrong mode");
    ASSERT(strstr(payload, "err=-40") != NULL, "wrong code");
    PASS();
}

static void test_challenge_and_submit_consumed_refused(void)
{
    TEST("L1: challenge + submit for a consumed proposal -> -42");
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    ASSERT(propose_via_block(&g, "R-APP", "reload", pid) == 0, "propose");
    virp_approval_rec_t apr;
    ASSERT(do_approve(pid, &apr) == VIRP_OK, "approve");
    uint8_t ot, tier; char payload[2048];
    ASSERT(run_cmd(&g, "R-APP", "reload", pid, &ot, &tier, payload,
                   sizeof(payload)) == 0, "apply");
    ASSERT(strstr(payload, "R-APP#reload") != NULL, "first apply ran");

    /* An OUTCOME now exists. Re-challenge and re-submit must both refuse
     * with approval_proposal_consumed (-42) — the L1 fix. */
    virp_approval_challenge_t ch;
    ASSERT(virp_approval_challenge(DIR, &g.chain, pid, 0, &ch)
               == VIRP_ERR_APPROVAL_CONSUMED, "re-challenge must be -42");

    uint8_t sig[VIRP_APPROVER_SIG_SIZE];
    char kid[33];
    keyid_hex(&g_kp, kid);
    /* Any signature bytes: the consumed check precedes verification. */
    memset(sig, 0x11, sizeof(sig));
    ASSERT(virp_approval_submit(DIR, &g.approvers, &g.chain, pid, kid,
                                sig, sizeof(sig), &apr)
               == VIRP_ERR_APPROVAL_CONSUMED, "re-submit must be -42");
    PASS();
}

static void test_wrong_algorithm_rejected(void)
{
    TEST("Negative: wrong-algorithm sig for enrolled key -> -40");
    /* Enroll BOTH g_kp (ed25519) and the mock's ECDSA-P256 key, then
     * write a record whose key_id is the ECDSA key but whose signature is
     * an Ed25519 signature. The daemon dispatches ECDSA verify on Ed25519
     * bytes -> bad signature. */
    static const char MOCK_SPKI[] =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUlaSetRmRWfyHZV0CjHUP09tdnES"
        "vruJo7n5ZnZ8Wov7B1OMrkI0pzOLn8WDLTown1WsdvcEi1BYbbJACMgUNg==";
    /* Compute the ECDSA key_id + build a 2-key registry. */
    char ed[1024], ec[1024];
    uint8_t ed_spki[44];
    virp_approver_ed25519_spki(g_kp.public_key, ed_spki);
    ASSERT(virp_approver_entry_json(ed_spki, sizeof(ed_spki), "op", true,
                                    ed, sizeof(ed)) == VIRP_OK, "ed entry");
    /* Decode the mock SPKI base64 to DER for entry_json. */
    uint8_t der[256];
    static const char A[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t bl = strlen(MOCK_SPKI), o = 0;
    for (size_t i = 0; i < bl; i += 4) {
        int v[4], pad = 0;
        for (int j = 0; j < 4; j++) {
            char cc = MOCK_SPKI[i + j];
            if (cc == '=') { v[j] = 0; pad++; }
            else { const char *q = strchr(A, cc); v[j] = q ? (int)(q - A) : 0; }
        }
        uint32_t acc = ((uint32_t)v[0] << 18) | ((uint32_t)v[1] << 12) |
                       ((uint32_t)v[2] << 6) | (uint32_t)v[3];
        if (pad < 3) der[o++] = (acc >> 16) & 0xff;
        if (pad < 2) der[o++] = (acc >> 8) & 0xff;
        if (pad < 1) der[o++] = acc & 0xff;
    }
    ASSERT(virp_approver_entry_json(der, o, "mock", true, ec, sizeof(ec))
               == VIRP_OK, "ec entry");
    FILE *f = fopen(REGISTRY, "w");
    ASSERT(f != NULL, "reg open");
    fprintf(f, "[%s,%s]\n", ed, ec);
    fclose(f);
    ASSERT(onode_set_approvers(&g, DIR, REGISTRY) == VIRP_OK, "reload 2-key");

    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    ASSERT(propose_via_block(&g, "R-APP", "reload", pid) == 0, "propose");
    virp_proposal_rec_t prop;
    ASSERT(virp_approval_load_proposal(DIR, pid, &prop) == VIRP_OK, "load");

    /* Ed25519 signature over the correct canonical bytes... */
    uint8_t canon[VIRP_APPROVAL_CANON_SIZE];
    uint64_t at = now_ns();
    ASSERT(virp_approval_build_canonical(pid, prop.command_hash,
               prop.device_node_id, at, VIRP_APPROVAL_TTL_SECONDS, canon)
               == VIRP_OK, "canon");
    uint8_t sig[VIRP_APPROVER_SIG_SIZE];
    ASSERT(virp_fed_sign(&g_kp, canon, sizeof(canon), sig) == VIRP_OK, "sign");
    /* ...but written under the ECDSA key's key_id. */
    virp_approver_alg_t alg;
    uint8_t raw[65]; size_t rawlen;
    (void)alg; (void)raw; (void)rawlen;
    virp_approval_rec_t rec;
    memset(&rec, 0, sizeof(rec));
    snprintf(rec.proposal_id, sizeof(rec.proposal_id), "%s", pid);
    snprintf(rec.command_hash, sizeof(rec.command_hash), "%s", prop.command_hash);
    snprintf(rec.device, sizeof(rec.device), "%s", prop.device);
    rec.device_node_id = prop.device_node_id;
    rec.approved_at_ns = at;
    rec.ttl_seconds = VIRP_APPROVAL_TTL_SECONDS;
    /* ECDSA key's key_id (derive via a throwaway registry lookup). */
    {
        virp_approver_registry_t r2;
        char one[1024];
        virp_approver_entry_json(der, o, "mock", true, one, sizeof(one));
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "/tmp/virp-test-wrongalg.json");
        FILE *g2 = fopen(tmp, "w"); fprintf(g2, "[%s]\n", one); fclose(g2);
        virp_approver_registry_load(&r2, tmp);
        snprintf(rec.approver_key_id, sizeof(rec.approver_key_id), "%s",
                 r2.entries[0].key_id);
        unlink(tmp);
    }
    ASSERT(virp_approval_write_record(DIR, &rec, sig, sizeof(sig)) == VIRP_OK,
           "write record");

    uint8_t ot, tier; char payload[2048];
    ASSERT(run_cmd(&g, "R-APP", "reload", pid, &ot, &tier, payload,
                   sizeof(payload)) == 0, "apply");
    ASSERT(ot == VIRP_OBS_ERROR, "must be rejected");
    ASSERT(strstr(payload, "approval_bad_signature") != NULL, "wrong mode");
    ASSERT(strstr(payload, "err=-40") != NULL, "wrong code");

    /* Restore the single-key enabled registry. */
    ASSERT(write_registry(REGISTRY, true, false) == 0, "restore");
    ASSERT(onode_set_approvers(&g, DIR, REGISTRY) == VIRP_OK, "restore reload");
    PASS();
}

/* Concurrency: two simultaneous SUBMITs for one proposal must yield
 * exactly ONE APPROVAL chain entry. */
struct submit_arg { char pid[33]; uint8_t sig[VIRP_APPROVER_SIG_SIZE];
                    char kid[33]; virp_error_t rc; virp_approval_rec_t apr; };
static void *submit_thread(void *a)
{
    struct submit_arg *s = a;
    s->rc = virp_approval_submit(DIR, &g.approvers, &g.chain, s->pid,
                                 s->kid, s->sig, VIRP_APPROVER_SIG_SIZE,
                                 &s->apr);
    return NULL;
}

static void test_concurrent_submit_one_entry(void)
{
    TEST("Concurrency: two submits for one proposal -> one chain entry");
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    ASSERT(propose_via_block(&g, "R-APP", "reload", pid) == 0, "propose");
    virp_approval_challenge_t ch;
    ASSERT(virp_approval_challenge(DIR, &g.chain, pid, 0, &ch) == VIRP_OK,
           "challenge");

    struct submit_arg a1, a2;
    memset(&a1, 0, sizeof(a1)); memset(&a2, 0, sizeof(a2));
    snprintf(a1.pid, sizeof(a1.pid), "%s", pid);
    snprintf(a2.pid, sizeof(a2.pid), "%s", pid);
    keyid_hex(&g_kp, a1.kid); keyid_hex(&g_kp, a2.kid);
    ASSERT(virp_fed_sign(&g_kp, ch.canonical, VIRP_APPROVAL_CANON_SIZE,
                         a1.sig) == VIRP_OK, "sign1");
    memcpy(a2.sig, a1.sig, sizeof(a2.sig));

    pthread_t t1, t2;
    pthread_create(&t1, NULL, submit_thread, &a1);
    pthread_create(&t2, NULL, submit_thread, &a2);
    pthread_join(t1, NULL); pthread_join(t2, NULL);
    /* Success-class both, but distinguishable: exactly one submission
     * created the record (VIRP_OK), the other found it already there. */
    ASSERT((a1.rc == VIRP_OK) + (a2.rc == VIRP_OK) == 1,
           "exactly one winner");
    ASSERT((a1.rc == VIRP_APPROVAL_ALREADY_EXISTS) +
           (a2.rc == VIRP_APPROVAL_ALREADY_EXISTS) == 1,
           "exactly one already-exists");

    /* EXACTLY one APPROVAL chain entry for this proposal — count directly. */
    char aid[64];
    snprintf(aid, sizeof(aid), "approval:%s", pid);
    sqlite3 *db = NULL;
    ASSERT(sqlite3_open_v2(CHAIN_DB, &db, SQLITE_OPEN_READONLY, NULL)
               == SQLITE_OK, "open chain ro");
    sqlite3_stmt *st = NULL;
    ASSERT(sqlite3_prepare_v2(db,
               "SELECT COUNT(*) FROM chain_entries WHERE artifact_id = ?",
               -1, &st, NULL) == SQLITE_OK, "prepare");
    sqlite3_bind_text(st, 1, aid, -1, SQLITE_TRANSIENT);
    ASSERT(sqlite3_step(st) == SQLITE_ROW, "step");
    int count = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    sqlite3_close(db);
    ASSERT(count == 1, "must be exactly one APPROVAL entry");
    PASS();
}

/* Attribution race: two DIFFERENT enrolled approvers submit for one
 * proposal concurrently. Exactly one identity becomes the approver of
 * record; the loser must be told so (VIRP_APPROVAL_ALREADY_EXISTS) and
 * must receive the WINNER's identity in *out — never its own. Before
 * the fix the loser got VIRP_OK with its own key/operator in *out while
 * the winner's approval was canonical on disk. */
static virp_fed_keypair_t g_kp2;     /* second enrolled approver */

static int write_registry_two(const char *path)
{
    char e1[1024], e2[1024];
    uint8_t spki[44];
    virp_approver_ed25519_spki(g_kp.public_key, spki);
    if (virp_approver_entry_json(spki, sizeof(spki), "operator-one",
                                 true, e1, sizeof(e1)) != VIRP_OK)
        return -1;
    virp_approver_ed25519_spki(g_kp2.public_key, spki);
    if (virp_approver_entry_json(spki, sizeof(spki), "operator-two",
                                 true, e2, sizeof(e2)) != VIRP_OK)
        return -1;
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "[%s,\n%s]\n", e1, e2);
    fclose(f);
    return 0;
}

static void test_concurrent_submit_attribution_two_approvers(void)
{
    TEST("Concurrency: race loser gets winner's identity + already-exists");
    ASSERT(virp_fed_generate(&g_kp2, 1) == VIRP_OK, "keygen2");
    ASSERT(write_registry_two(REGISTRY) == 0, "two-key registry");
    ASSERT(onode_set_approvers(&g, DIR, REGISTRY) == VIRP_OK, "reload reg");

    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    ASSERT(propose_via_block(&g, "R-APP", "reload", pid) == 0, "propose");
    virp_approval_challenge_t ch;
    ASSERT(virp_approval_challenge(DIR, &g.chain, pid, 0, &ch) == VIRP_OK,
           "challenge");

    /* Both approvers sign the same canonical bytes with their OWN keys —
     * two independently valid submissions with distinct identities. */
    struct submit_arg a1, a2;
    memset(&a1, 0, sizeof(a1)); memset(&a2, 0, sizeof(a2));
    snprintf(a1.pid, sizeof(a1.pid), "%s", pid);
    snprintf(a2.pid, sizeof(a2.pid), "%s", pid);
    keyid_hex(&g_kp, a1.kid); keyid_hex(&g_kp2, a2.kid);
    ASSERT(virp_fed_sign(&g_kp, ch.canonical, VIRP_APPROVAL_CANON_SIZE,
                         a1.sig) == VIRP_OK, "sign1");
    ASSERT(virp_fed_sign(&g_kp2, ch.canonical, VIRP_APPROVAL_CANON_SIZE,
                         a2.sig) == VIRP_OK, "sign2");

    pthread_t t1, t2;
    pthread_create(&t1, NULL, submit_thread, &a1);
    pthread_create(&t2, NULL, submit_thread, &a2);
    pthread_join(t1, NULL); pthread_join(t2, NULL);

    ASSERT((a1.rc == VIRP_OK) + (a2.rc == VIRP_OK) == 1,
           "exactly one winner");
    ASSERT((a1.rc == VIRP_APPROVAL_ALREADY_EXISTS) +
           (a2.rc == VIRP_APPROVAL_ALREADY_EXISTS) == 1,
           "loser told already-exists, not plain OK");

    struct submit_arg *win = (a1.rc == VIRP_OK) ? &a1 : &a2;
    struct submit_arg *lose = (a1.rc == VIRP_OK) ? &a2 : &a1;

    /* The winner's *out is its own identity... */
    ASSERT(strcmp(win->apr.approver_key_id, win->kid) == 0,
           "winner sees itself as approver");
    /* ...and the loser's *out is ALSO the winner's identity — the
     * approver of record — not the loser's own. */
    ASSERT(strcmp(lose->apr.approver_key_id, win->kid) == 0,
           "loser must see the approver of record");
    ASSERT(strcmp(lose->apr.approver_key_id, lose->kid) != 0,
           "loser must NOT see itself");
    ASSERT(strcmp(lose->apr.operator, win->apr.operator) == 0,
           "operator is the winner's");
    ASSERT(lose->apr.approved_at_ns == win->apr.approved_at_ns,
           "timestamp is the record's");
    ASSERT(strcmp(lose->apr.chain_entry_hash, win->apr.chain_entry_hash) == 0,
           "chain hash is the record's");

    /* What is persisted attributes the winner: the on-disk record (via
     * the same loader the apply path uses) and the single chain entry. */
    virp_approval_rec_t disk;
    ASSERT(virp_approval_verify_consume(DIR, &g.approvers, pid, "R-APP",
                                        0xA0A0A0A1, "reload", NULL,
                                        0 /* now */, &disk) == VIRP_OK,
           "persisted record verifies and consumes once");
    ASSERT(strcmp(disk.approver_key_id, win->kid) == 0,
           "persisted approver is the winner");
    ASSERT(strcmp(disk.operator, win->apr.operator) == 0,
           "persisted operator is the winner's");

    char aid[64];
    snprintf(aid, sizeof(aid), "approval:%s", pid);
    sqlite3 *db = NULL;
    ASSERT(sqlite3_open_v2(CHAIN_DB, &db, SQLITE_OPEN_READONLY, NULL)
               == SQLITE_OK, "open chain ro");
    sqlite3_stmt *st = NULL;
    ASSERT(sqlite3_prepare_v2(db,
               "SELECT COUNT(*) FROM chain_entries WHERE artifact_id = ?",
               -1, &st, NULL) == SQLITE_OK, "prepare");
    sqlite3_bind_text(st, 1, aid, -1, SQLITE_TRANSIENT);
    ASSERT(sqlite3_step(st) == SQLITE_ROW, "step");
    int count = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    sqlite3_close(db);
    ASSERT(count == 1, "still exactly one APPROVAL entry");

    /* Restore the single-key registry for the tests that follow. */
    ASSERT(write_registry(REGISTRY, true, false) == 0, "restore registry");
    ASSERT(onode_set_approvers(&g, DIR, REGISTRY) == VIRP_OK,
           "restore reload");
    PASS();
}

/* =========================================================================
 * Evidence-required consumption invariant (Sep 1 review, Task 5 / 1.1)
 *
 * "An approval is consumed iff a committed gate_intent entry names its
 * proposal id and approval entry hash. A refused intent consumes nothing.
 * The chain is the authority; the consumed list is a cache." These tests
 * drive the in-process apply path with the chain forced read-only at the
 * moment of the intent append, and with the consumed.list cache emptied
 * out from under the daemon, to show the chain — not the cache — decides.
 * ========================================================================= */

/* Force every chain write to fail (PRAGMA query_only) / restore it. */
static void ev_chain_ro(onode_state_t *st, int on)
{
    pthread_mutex_lock(&st->chain.lock);
    sqlite3_exec(st->chain.db, on ? "PRAGMA query_only=ON"
                                  : "PRAGMA query_only=OFF",
                 NULL, NULL, NULL);
    pthread_mutex_unlock(&st->chain.lock);
}

/* Count committed gate_intent entries citing this approval entry hash, by
 * reading the chain db the way the daemon's own guard does. */
static int ev_intents_for_approval(const char *approval_hash)
{
    int n = 0;
    if (virp_chain_count_intents_for_approval(&g.chain, approval_hash, &n)
            != VIRP_OK)
        return -1;
    return n;
}

/* Is proposal_id present in consumed.list? */
static int ev_in_consumed_list(const char *pid)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/consumed.list", DIR);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[128];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';
        if (strcmp(line, pid) == 0) { found = 1; break; }
    }
    fclose(f);
    return found;
}

/* (a) Forced intent-append failure on an approved apply refuses, consumes
 * nothing, and a later apply (chain restored) executes EXACTLY once with
 * one intent and one closer. */
static void test_evidence_intent_fail_leaves_approval_consumable(void)
{
    TEST("1.1(a): intent-append failure refuses, approval still consumable");
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    ASSERT(propose_via_block(&g, "R-APP", "reload", pid) == 0, "propose");
    virp_approval_rec_t apr;
    ASSERT(do_approve(pid, &apr) == VIRP_OK, "approve");
    ASSERT(apr.chain_entry_hash[0] != '\0', "approval entry hash");

    uint8_t ot, tier;
    char payload[2048];

    /* Intent append fails: refuse, nothing consumed, no intent committed. */
    ev_chain_ro(&g, 1);
    ASSERT(run_cmd(&g, "R-APP", "reload", pid, &ot, &tier, payload,
                   sizeof(payload)) == 0, "apply call");
    ev_chain_ro(&g, 0);
    ASSERT(ot == VIRP_OBS_ERROR, "must be refused");
    ASSERT(strstr(payload, "evidence-unavailable") != NULL,
           "must cite evidence-unavailable");
    ASSERT(strstr(payload, "R-APP#") == NULL, "must not execute");
    ASSERT(ev_intents_for_approval(apr.chain_entry_hash) == 0,
           "no intent may be committed on a refused apply");
    ASSERT(ev_in_consumed_list(pid) == 0, "approval must NOT be consumed");

    /* Chain restored: the same approval applies, executes once, one intent
     * and one closer (outcome). */
    ASSERT(run_cmd(&g, "R-APP", "reload", pid, &ot, &tier, payload,
                   sizeof(payload)) == 0, "second apply call");
    ASSERT(strstr(payload, "R-APP#reload") != NULL, "must execute now");
    ASSERT(strstr(payload, "apply rejected") == NULL, "not rejected");
    ASSERT(ev_intents_for_approval(apr.chain_entry_hash) == 1,
           "exactly one intent for the approval");
    ASSERT(ev_in_consumed_list(pid) == 1, "approval now consumed");

    virp_chain_entry_t ce;
    char want_id[64];
    snprintf(want_id, sizeof(want_id), "outcome:%s", pid);
    ASSERT(virp_chain_get_last(&g.chain, "approval:R-APP", &ce) == VIRP_OK,
           "outcome present");
    ASSERT(strcmp(ce.artifact_id, want_id) == 0, "outcome closes this apply");
    PASS();
}

/* (b) Consumed list emptied but the chain holds an intent for the
 * approval: apply refused. The chain is the authority. */
static void test_evidence_chain_beats_emptied_cache(void)
{
    TEST("1.1(b): emptied consumed.list, chain intent still refuses replay");
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    ASSERT(propose_via_block(&g, "R-APP", "reload", pid) == 0, "propose");
    virp_approval_rec_t apr;
    ASSERT(do_approve(pid, &apr) == VIRP_OK, "approve");

    uint8_t ot, tier;
    char payload[2048];
    ASSERT(run_cmd(&g, "R-APP", "reload", pid, &ot, &tier, payload,
                   sizeof(payload)) == 0, "first apply");
    ASSERT(strstr(payload, "R-APP#reload") != NULL, "first apply ran");
    ASSERT(ev_intents_for_approval(apr.chain_entry_hash) == 1, "one intent");

    /* Blow away the cache the daemon relies on for the fast path. */
    char path[512];
    snprintf(path, sizeof(path), "%s/consumed.list", DIR);
    ASSERT(unlink(path) == 0 || errno == ENOENT, "empty consumed.list");
    ASSERT(ev_in_consumed_list(pid) == 0, "cache is empty");

    /* Replay must still be refused — from the chain, not the cache. */
    ASSERT(run_cmd(&g, "R-APP", "reload", pid, &ot, &tier, payload,
                   sizeof(payload)) == 0, "replay apply");
    ASSERT(ot == VIRP_OBS_ERROR, "replay refused");
    ASSERT(strstr(payload, "R-APP#") == NULL, "replay must not execute");
    ASSERT(ev_intents_for_approval(apr.chain_entry_hash) == 1,
           "still exactly one intent (no second)");
    PASS();
}

/* (c) Two applies on one approval with the chain read-only: nothing
 * executes, no intent, approval unconsumed. (Serialized stand-in for the
 * concurrent race — the per-device exec_mutex serializes real threads to
 * exactly this, and the invariant is what matters.) */
static void test_evidence_readonly_double_apply_executes_nothing(void)
{
    TEST("1.1(c): two applies, chain read-only -> nothing runs, unconsumed");
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    ASSERT(propose_via_block(&g, "R-APP", "reload", pid) == 0, "propose");
    virp_approval_rec_t apr;
    ASSERT(do_approve(pid, &apr) == VIRP_OK, "approve");

    uint8_t ot, tier;
    char payload[2048];
    ev_chain_ro(&g, 1);
    for (int i = 0; i < 2; i++) {
        ASSERT(run_cmd(&g, "R-APP", "reload", pid, &ot, &tier, payload,
                       sizeof(payload)) == 0, "apply call");
        ASSERT(ot == VIRP_OBS_ERROR, "refused under read-only chain");
        ASSERT(strstr(payload, "R-APP#") == NULL, "nothing executes");
    }
    ev_chain_ro(&g, 0);
    ASSERT(ev_intents_for_approval(apr.chain_entry_hash) == 0, "no intent");
    ASSERT(ev_in_consumed_list(pid) == 0, "approval unconsumed");

    /* And the approval is still good: one real apply now executes once. */
    ASSERT(run_cmd(&g, "R-APP", "reload", pid, &ot, &tier, payload,
                   sizeof(payload)) == 0, "recovery apply");
    ASSERT(strstr(payload, "R-APP#reload") != NULL, "executes after recovery");
    ASSERT(ev_intents_for_approval(apr.chain_entry_hash) == 1, "one intent");
    PASS();
}

/* 1.5 — the daemon records its posture on the chain at startup, so an
 * auditor can bound the window in which unrecorded execution was allowed
 * from the chain alone. onode_start (serve_thread) ran with the chain
 * enabled, so a node_config entry must be present and carry the posture. */
static void test_node_config_recorded_at_startup(void)
{
    TEST("1.5: node_config posture entry recorded at startup");
    char session[64];
    snprintf(session, sizeof(session), "node-config:%08X", g.node_id);
    virp_chain_entry_t ce;
    ASSERT(virp_chain_get_last(&g.chain, session, &ce) == VIRP_OK,
           "node_config entry present");
    ASSERT(strcmp(ce.artifact_type, "node_config") == 0, "type is node_config");

    /* Read the body back and confirm it carries the posture fields. */
    sqlite3 *db = NULL;
    ASSERT(sqlite3_open_v2(CHAIN_DB, &db, SQLITE_OPEN_READONLY, NULL)
               == SQLITE_OK, "open chain ro");
    sqlite3_stmt *st = NULL;
    ASSERT(sqlite3_prepare_v2(db,
        "SELECT a.artifact_content FROM chain_entries c "
        "JOIN artifacts a ON a.artifact_id=c.artifact_id "
        "               AND a.artifact_hash=c.artifact_hash "
        "WHERE c.artifact_type='node_config' ORDER BY c.id DESC LIMIT 1",
        -1, &st, NULL) == SQLITE_OK, "prepare");
    ASSERT(sqlite3_step(st) == SQLITE_ROW, "row");
    const char *body = (const char *)sqlite3_column_text(st, 0);
    ASSERT(body != NULL, "body present");
    ASSERT(strstr(body, "\"schema\":\"node_config/1\"") != NULL, "schema");
    ASSERT(strstr(body, "\"evidence_required\":") != NULL, "evidence_required");
    ASSERT(strstr(body, "\"gate_max_tier\":") != NULL, "gate_max_tier");
    ASSERT(strstr(body, "\"build_id\":") != NULL, "build_id");
    /* v0.2.1 Fix 2. Asserting only that the FIELD EXISTS is what let
     * v0.2.0 ship node_config entries reading build_id="unknown" for the
     * whole deploy window: the key was there, the provenance was not.
     * The recorded id must be the real one this binary was built from. */
    ASSERT(strstr(body, "\"build_id\":\"unknown\"") == NULL,
           "build_id is not \"unknown\" (the v0.2.0 defect)");
    {
        char want[128];
        snprintf(want, sizeof(want), "\"build_id\":\"%s\"", virp_build_id());
        ASSERT(strstr(body, want) != NULL,
               "build_id equals this binary's linked build id");
    }
    sqlite3_finalize(st);
    sqlite3_close(db);
    PASS();
}

/* Apply thread for the item-1 concurrency test. */
struct apply_arg { char pid[33]; const char *device; const char *cmd;
                   int rc; uint8_t ot; int executed; };
static void *apply_thread(void *a)
{
    struct apply_arg *x = a;
    uint8_t tier; char payload[2048];
    x->rc = run_cmd(&g, x->device, x->cmd, x->pid, &x->ot, &tier,
                    payload, sizeof(payload));
    x->executed = (strstr(payload, "#") != NULL &&
                   strstr(payload, "R-") != NULL &&
                   strstr(payload, "apply rejected") == NULL &&
                   strstr(payload, "ERROR") == NULL);
    return NULL;
}

/* item 1 — two concurrent applies of ONE approval to ONE device execute
 * exactly once. The per-device exec_mutex serializes them and the loser's
 * apply-time chain guard (now atomic with the intent append under
 * consume_lock) finds the winner's committed intent and refuses reused.
 * Exactly one intent, exactly one outcome. */
static void test_evidence_concurrent_apply_executes_once(void)
{
    TEST("1.1(item1): two concurrent applies, one approval -> exactly once");
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    ASSERT(propose_via_block(&g, "R-APP", "reload", pid) == 0, "propose");
    virp_approval_rec_t apr;
    ASSERT(do_approve(pid, &apr) == VIRP_OK, "approve");

    struct apply_arg a1, a2;
    memset(&a1, 0, sizeof(a1)); memset(&a2, 0, sizeof(a2));
    snprintf(a1.pid, sizeof(a1.pid), "%s", pid);
    snprintf(a2.pid, sizeof(a2.pid), "%s", pid);
    a1.device = a2.device = "R-APP";
    a1.cmd = a2.cmd = "reload";

    pthread_t t1, t2;
    pthread_create(&t1, NULL, apply_thread, &a1);
    pthread_create(&t2, NULL, apply_thread, &a2);
    pthread_join(t1, NULL); pthread_join(t2, NULL);

    ASSERT(a1.executed + a2.executed == 1, "exactly one execution");
    ASSERT(ev_intents_for_approval(apr.chain_entry_hash) == 1,
           "exactly one intent for the approval");

    /* The loser saw a reused refusal (from the chain guard), not a crash. */
    struct apply_arg *lose = a1.executed ? &a2 : &a1;
    ASSERT(lose->ot == VIRP_OBS_ERROR, "loser refused with an ERROR obs");
    PASS();
}

/* item 2 — an approval valid at verify but expired by the time connect
 * returns is refused at the re-check, consuming nothing. A per-connect
 * delay makes the TTL lapse deterministically during a fresh connect. */
static void test_evidence_ttl_rechecked_after_connect(void)
{
    TEST("1.1(item2): TTL re-checked after connect -> expired, unconsumed");
    /* A fresh device with no cached connection, so this apply must connect
     * (and hit the delay). */
    virp_device_t dev;
    memset(&dev, 0, sizeof(dev));
    snprintf(dev.hostname, sizeof(dev.hostname), "R-TTL");
    snprintf(dev.host, sizeof(dev.host), "10.255.9.9");
    dev.port = 22; dev.vendor = VIRP_VENDOR_MOCK;
    dev.node_id = 0xA0A0A0AA; dev.enabled = true;
    ASSERT(onode_add_device(&g, &dev) == VIRP_OK, "add R-TTL");

    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    ASSERT(propose_via_block(&g, "R-TTL", "reload", pid) == 0, "propose");
    virp_proposal_rec_t prop;
    ASSERT(virp_approval_load_proposal(DIR, pid, &prop) == VIRP_OK, "prop");

    /* ttl=1s, approved 800ms ago -> ~200ms remaining at verify (passes),
     * then a 500ms connect delay pushes the re-check past expiry. */
    uint64_t approved_at = now_ns() - 800ULL * 1000000ULL;
    ASSERT(craft_record(pid, &g_kp, prop.command_hash, prop.device,
                        prop.device_node_id, approved_at, 1) == VIRP_OK,
           "craft near-expiry approval");

    virp_driver_mock_set_connect_delay(500);
    uint8_t ot, tier; char payload[2048];
    int rc = run_cmd(&g, "R-TTL", "reload", pid, &ot, &tier, payload,
                     sizeof(payload));
    virp_driver_mock_set_connect_delay(0);
    ASSERT(rc == 0, "apply call");

    ASSERT(ot == VIRP_OBS_ERROR, "must be refused");
    ASSERT(strstr(payload, "approval_expired") != NULL, "expired at re-check");
    ASSERT(strstr(payload, "R-TTL#") == NULL, "nothing executed");
    ASSERT(ev_in_consumed_list(pid) == 0, "approval unconsumed");
    PASS();
}

/* item 3 — a consumed.list cache write that fails AFTER the intent has
 * committed must NOT refuse and must NOT stop execution: the intent is the
 * authority. The next apply of the same approval is refused via the chain
 * guard, proving the cache miss did not lose single-use. */
static void test_evidence_cache_failure_after_intent_still_executes(void)
{
    TEST("1.1(item3): cache write fails after intent -> executes, replay blocked");
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    ASSERT(propose_via_block(&g, "R-APP", "reload", pid) == 0, "propose");
    virp_approval_rec_t apr;
    ASSERT(do_approve(pid, &apr) == VIRP_OK, "approve");

    /* Make the approval dir unwritable so the consumed.list temp-create in
     * commit_consume fails, while the record stays readable for verify. */
    ASSERT(chmod(DIR, 0500) == 0, "chmod dir read-only");
    uint8_t ot, tier; char payload[2048];
    int rc = run_cmd(&g, "R-APP", "reload", pid, &ot, &tier, payload,
                     sizeof(payload));
    ASSERT(chmod(DIR, 0700) == 0, "restore dir");
    ASSERT(rc == 0, "apply call");

    /* Executed despite the cache-write failure. */
    ASSERT(strstr(payload, "R-APP#reload") != NULL, "executed");
    ASSERT(strstr(payload, "apply rejected") == NULL, "not rejected");
    ASSERT(ev_intents_for_approval(apr.chain_entry_hash) == 1, "one intent");
    ASSERT(ev_in_consumed_list(pid) == 0, "cache write did fail");

    /* Replay refused from the chain, not the (empty) cache. */
    ASSERT(run_cmd(&g, "R-APP", "reload", pid, &ot, &tier, payload,
                   sizeof(payload)) == 0, "replay apply");
    ASSERT(ot == VIRP_OBS_ERROR, "replay refused");
    ASSERT(strstr(payload, "R-APP#") == NULL, "replay must not execute");
    ASSERT(ev_intents_for_approval(apr.chain_entry_hash) == 1, "still one intent");
    PASS();
}

/* =========================================================================
 * CLI tests — `virp exec` and `virp chain tail` against the served
 * daemon. The CLI is a client: everything goes through the framed
 * socket and the same tier gate as any other submission.
 * ========================================================================= */

#include <pthread.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <arpa/inet.h>   /* htonl/ntohl */

#define CLI_BIN "./build/virp"

static void *serve_thread(void *arg)
{
    onode_start((onode_state_t *)arg);
    return NULL;
}

/* Run a CLI command, capture combined output and exit status. */
static int run_cli(const char *cmdline, char *out, size_t out_len)
{
    char full[1024];
    snprintf(full, sizeof(full), "%s 2>&1", cmdline);
    FILE *p = popen(full, "r");
    if (!p) return -1;
    size_t got = fread(out, 1, out_len - 1, p);
    out[got] = '\0';
    int status = pclose(p);
    if (status == -1 || !WIFEXITED(status)) return -1;
    return WEXITSTATUS(status);
}

static void test_cli_exec_green_executes(void)
{
    TEST("CLI: virp exec GREEN read executes");
    char out[8192], cmd[512];
    snprintf(cmd, sizeof(cmd),
             CLI_BIN " exec R-APP \"show version\" --socket %s --no-verify",
             g.socket_path);
    int rc = run_cli(cmd, out, sizeof(out));
    ASSERT(rc == 0, "exit code should be 0 (executed)");
    ASSERT(strstr(out, "trust_tier=GREEN") != NULL, "tier resolution missing");
    ASSERT(strstr(out, "gate_decision=allowed") != NULL, "gate decision missing");
    ASSERT(strstr(out, "R-APP#show version") != NULL, "device output missing");
    PASS();
}

/*
 * The operator CLI must VERIFY, not just print (2026-07-30). `virp exec`
 * used to print the response unverified and tell the reader to run
 * `virp-tool inspect` separately, which made the one client a human
 * drives by hand the weakest verifier in the fleet while the autopilot
 * verified everything. Asserted both ways: the harness O-Key verifies,
 * and an unrelated key is a hard failure — a bad signature must never
 * exit 0 with the payload printed as fact.
 */
static void test_cli_exec_verifies_signature(void)
{
    TEST("CLI: virp exec verifies the observation signature");
    char out[8192], cmd[768];

    /* The harness signs with the in-memory g.okey; write it out so the
     * CLI can verify against the same key the daemon used. */
    const char *good = "/tmp/virp-approval-test-okey.bin";
    const char *bad  = "/tmp/virp-approval-test-okey-wrong.bin";
    ASSERT(virp_key_save_file(&g.okey, good) == VIRP_OK, "save harness okey");

    virp_signing_key_t other;
    ASSERT(virp_key_generate(&other, VIRP_KEY_TYPE_OKEY) == VIRP_OK,
           "generate unrelated okey");
    ASSERT(virp_key_save_file(&other, bad) == VIRP_OK, "save unrelated okey");
    virp_key_destroy(&other);

    /* Correct key: executes AND reports the signature as valid. */
    snprintf(cmd, sizeof(cmd),
             CLI_BIN " exec R-APP \"show version\" --socket %s --okey %s",
             g.socket_path, good);
    int rc = run_cli(cmd, out, sizeof(out));
    ASSERT(rc == 0, "correct key: exit 0");
    ASSERT(strstr(out, "signature=VALID") != NULL,
           "correct key: signature must be reported VALID");

    /* Wrong key: must FAIL, and must say the payload is not evidence. */
    snprintf(cmd, sizeof(cmd),
             CLI_BIN " exec R-APP \"show version\" --socket %s --okey %s",
             g.socket_path, bad);
    rc = run_cli(cmd, out, sizeof(out));
    ASSERT(rc == 1, "wrong key: must exit non-zero, not 0");
    ASSERT(strstr(out, "INVALID") != NULL,
           "wrong key: must announce INVALID");
    ASSERT(strstr(out, "NOT evidence") != NULL,
           "wrong key: must refuse to present the payload as evidence");

    /* Explicit opt-out still works and says so rather than implying a check. */
    snprintf(cmd, sizeof(cmd),
             CLI_BIN " exec R-APP \"show version\" --socket %s --no-verify",
             g.socket_path);
    rc = run_cli(cmd, out, sizeof(out));
    ASSERT(rc == 0, "--no-verify: exit 0");
    ASSERT(strstr(out, "signature=SKIPPED") != NULL,
           "--no-verify must report SKIPPED, never VALID");

    unlink(good);
    unlink(bad);
    PASS();
}

static void test_cli_exec_red_rejected_with_proposal(void)
{
    TEST("CLI: virp exec RED returns rejection + proposal_id");
    char out[8192], cmd[512];
    snprintf(cmd, sizeof(cmd),
             CLI_BIN " exec R-APP \"reload\" --socket %s --no-verify", g.socket_path);
    int rc = run_cli(cmd, out, sizeof(out));
    ASSERT(rc == 2, "exit code should be 2 (signed rejection)");
    ASSERT(strstr(out, "trust_tier=RED") != NULL, "tier resolution missing");
    ASSERT(strstr(out, "gate_decision=blocked") != NULL, "gate decision missing");
    ASSERT(strstr(out, "signed rejection") != NULL, "rejection label missing");
    ASSERT(strstr(out, "tier gate blocked") != NULL,
           "rejection payload missing");
    /* proposal_id surfaced on its own line, 32 hex */
    const char *p = strstr(out, "\nproposal_id=");
    ASSERT(p != NULL, "standalone proposal_id line missing");
    p += strlen("\nproposal_id=");
    ASSERT(strspn(p, "0123456789abcdef") == VIRP_APPROVAL_ID_HEX_LEN,
           "proposal_id not 32 hex");
    ASSERT(strstr(out, "R-APP#reload") == NULL, "command must not execute");
    PASS();
}

static void test_cli_chain_tail_format(void)
{
    TEST("CLI: virp chain tail shows linked entries, oldest first");
    /*
     * WINDOW (2026-08-12): -n was 50 with a 16 KiB buffer, which fit the
     * suite's chain only while the daemon chained refusals and nothing
     * else. Now that GREEN auto-executions are chained too (gate_execution
     * — see gate_emit_execution in src/virp_onode.c), the suite's own
     * `virp exec` calls put enough entries after the e2e proposal to push
     * it out of a 50-row tail, and this test failed on a missing proposal
     * that was present and correctly linked all along.
     *
     * Fixed by asking for the whole chain (-n 1000, the CLI maximum)
     * rather than by picking a new number that today's entry count
     * happens to clear: the assertion is about linkage and ordering, and
     * it should never again fail because the ledger records more. The
     * buffer is sized for 1000 rows at ~120 bytes each with headroom —
     * run_cli truncates silently at out_len, so a short buffer would
     * reintroduce exactly this failure in a harder-to-read form.
     */
    static char out[262144];
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             CLI_BIN " chain tail -n 1000 --db %s", CHAIN_DB);
    int rc = run_cli(cmd, out, sizeof(out));
    ASSERT(rc == 0, "exit code should be 0");
    /* Column header */
    ASSERT(strstr(out, "SESSION") != NULL && strstr(out, "TYPE") != NULL &&
           strstr(out, "ARTIFACT_ID") != NULL &&
           strstr(out, "ENTRY_HASH") != NULL &&
           strstr(out, "PREV_HASH") != NULL, "column header missing");
    /* The e2e flow left proposal, approval, and outcome entries; tail
     * must show all three artifact kinds under the approval session. */
    char want[64];
    snprintf(want, sizeof(want), "proposal:%s", g_pid_e2e);
    const char *prop = strstr(out, want);
    ASSERT(prop != NULL, "proposal entry missing");
    snprintf(want, sizeof(want), "approval:%s", g_pid_e2e);
    const char *appr = strstr(out, want);
    ASSERT(appr != NULL, "approval entry missing");
    snprintf(want, sizeof(want), "outcome:%s", g_pid_e2e);
    const char *outc = strstr(out, want);
    ASSERT(outc != NULL, "outcome entry missing");
    /* Oldest-first: PROPOSAL before APPROVAL before OUTCOME. */
    ASSERT(prop < appr && appr < outc, "entries not in chain order");
    PASS();
}

/* Full positive e2e THROUGH THE CLI + framed socket + daemon, using the
 * SINGLE secret-key file `keygen approval` writes (the exact real-world
 * path): propose -> `virp approve --key <prefix>.key` -> `virp apply`. */
static void test_cli_approve_apply_e2e(void)
{
    TEST("CLI e2e: keygen -> approve --key <secret.key> -> apply executes");
    /* Save g_kp's secret to the 64-byte `.key` file the CLI loads.
     * (virp_fed_save writes exactly what `keygen approval` writes; the
     * dedicated keygen-subprocess load is covered by the next test.) */
    const char *pub = "/tmp/virp-test-cli.pub", *sk = "/tmp/virp-test-cli.key";
    /* virp_fed_save is O_EXCL (never overwrites) — clear any file left by
     * a prior run before saving. */
    unlink(pub); unlink(sk);
    ASSERT(virp_fed_save(&g_kp, pub, sk) == VIRP_OK, "save key");

    /* 1. Block a fresh RED command via the CLI to file a proposal.
     * ("reload" is RED for the mock classifier; "configure" is YELLOW.) */
    char out[8192], cmd[1024];
    snprintf(cmd, sizeof(cmd),
             CLI_BIN " exec R-APP \"reload\" --socket %s --no-verify", g.socket_path);
    ASSERT(run_cli(cmd, out, sizeof(out)) == 2, "exec must be a rejection");
    const char *p = strstr(out, "\nproposal_id=");
    ASSERT(p != NULL, "no proposal_id");
    p += strlen("\nproposal_id=");
    char pid[33]; memcpy(pid, p, 32); pid[32] = '\0';

    /* 2. Approve via the CLI with ONLY the secret key file (--key), the
     * way an operator invokes it. The daemon writes the APPROVAL entry. */
    snprintf(cmd, sizeof(cmd),
             CLI_BIN " approve %s --socket %s --key %s",
             pid, g.socket_path, sk);
    ASSERT(run_cli(cmd, out, sizeof(out)) == 0, "approve failed");
    ASSERT(strstr(out, "APPROVED") != NULL, "no APPROVED banner");

    /* 3. Apply via the CLI — the command executes. */
    snprintf(cmd, sizeof(cmd),
             CLI_BIN " apply %s --dir %s --socket %s --no-verify", pid, DIR, g.socket_path);
    int rc = run_cli(cmd, out, sizeof(out));
    ASSERT(rc == 0, "apply should execute (exit 0)");
    ASSERT(strstr(out, "R-APP#reload") != NULL, "command did not execute");

    /* Chain shows the daemon-written APPROVAL with operator. */
    char tail[16384];
    snprintf(cmd, sizeof(cmd), CLI_BIN " chain tail -n 60 --db %s", CHAIN_DB);
    ASSERT(run_cli(cmd, tail, sizeof(tail)) == 0, "chain tail");
    char want[64];
    snprintf(want, sizeof(want), "approval:%s", pid);
    ASSERT(strstr(tail, want) != NULL, "APPROVAL entry missing");
    unlink(pub); unlink(sk);
    PASS();
}

/* =========================================================================
 * Review B #1 — `virp approve` reconstructs before it signs.
 *
 * A hostile / MITM'd O-Node hands the operator a challenge whose
 * human-readable summary shows one command_hash while the canonical
 * bytes to be signed commit to ANOTHER. A blind signer signs the
 * attacker's bytes and hands back a real approver signature for a
 * command the operator never saw. The fixed client re-derives the
 * proposal_id and command_hash embedded in the canonical and refuses
 * when they do not match the display — BEFORE any signing, and so
 * without ever sending a submit.
 * ========================================================================= */

struct hostile_srv {
    char sock_path[108];
    virp_signing_key_t okey;
    char pid[33];
    char canon_hex[2 * VIRP_APPROVAL_CANON_SIZE + 1];
    char disp_chash[65];        /* what the summary DISPLAYS (benign) */
    int  submit_seen;           /* set iff the client came back to submit */
    int  ready;                 /* listening socket is bound + listening */
};

static int read_n(int fd, void *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (uint8_t *)buf + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

/* Drain one framed request ([4B len][1B ver][json]); contents ignored. */
static void drain_one_request(int fd)
{
    uint8_t hdr[4];
    if (read_n(fd, hdr, 4) != 0) return;
    uint32_t len = ntohl(*(uint32_t *)hdr);
    if (len == 0 || len > VIRP_MAX_MESSAGE_SIZE) return;
    uint8_t *tmp = malloc(len);
    if (!tmp) return;
    (void)read_n(fd, tmp, len);
    free(tmp);
}

static void *hostile_serve_thread(void *arg)
{
    struct hostile_srv *s = arg;
    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lfd < 0) return NULL;
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof(a.sun_path), "%s", s->sock_path);
    unlink(s->sock_path);
    if (bind(lfd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(lfd, 4) != 0) {
        close(lfd);
        return NULL;
    }
    __atomic_store_n(&s->ready, 1, __ATOMIC_RELEASE);

    /* Connection 1: the approval_challenge fetch. Answer with the
     * inconsistent challenge and close. */
    int c1 = accept(lfd, NULL, NULL);
    if (c1 >= 0) {
        drain_one_request(c1);

        char json[1024];
        snprintf(json, sizeof(json),
                 "{\"proposal_id\":\"%s\",\"canonical\":\"%s\","
                 "\"device\":\"core-sw-1\",\"command\":\"show version\","
                 "\"command_hash\":\"%s\",\"tier\":\"YELLOW\","
                 "\"device_node_id\":5,\"approved_at_ns\":1750000000000000000,"
                 "\"ttl_seconds\":300}",
                 s->pid, s->canon_hex, s->disp_chash);

        uint8_t obuf[VIRP_MAX_MESSAGE_SIZE];
        size_t olen = 0;
        if (virp_build_observation(obuf, sizeof(obuf), &olen, 1, 1,
                                   VIRP_OBS_APPROVAL_CHALLENGE, VIRP_SCOPE_LOCAL,
                                   (const uint8_t *)json, (uint16_t)strlen(json),
                                   &s->okey) == VIRP_OK) {
            uint32_t belen = htonl((uint32_t)olen);
            (void)!write(c1, &belen, 4);
            (void)!write(c1, obuf, olen);
        }
        close(c1);
    }

    /* If the client is buggy it now opens a SECOND connection to submit.
     * A correct client refuses after the challenge and never comes back.
     * Poll briefly; any second connection is the failure signal. */
    struct pollfd pfd = { .fd = lfd, .events = POLLIN };
    if (poll(&pfd, 1, 2000) > 0 && (pfd.revents & POLLIN)) {
        int c2 = accept(lfd, NULL, NULL);
        if (c2 >= 0) {
            __atomic_store_n(&s->submit_seen, 1, __ATOMIC_RELEASE);
            drain_one_request(c2);
            close(c2);
        }
    }
    close(lfd);
    unlink(s->sock_path);
    return NULL;
}

static void test_cli_approve_refuses_inconsistent_canonical(void)
{
    TEST("CLI: approve refuses a challenge whose canonical != display");

    struct hostile_srv s;
    memset(&s, 0, sizeof(s));
    snprintf(s.sock_path, sizeof(s.sock_path), "/tmp/virp-test-hostile.sock");

    /* O-Key to sign the (well-formed) challenge observation. The approve
     * client does not HMAC-verify the challenge, so any O-Key serves. */
    ASSERT(virp_key_generate(&s.okey, VIRP_KEY_TYPE_OKEY) == VIRP_OK,
           "gen okey");

    /* 32-hex proposal id the client will pass on the command line. */
    snprintf(s.pid, sizeof(s.pid), "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1");

    /* The canonical commits to H_evil; the summary DISPLAYS H_benign. */
    char evil[65], benign[65];
    for (int i = 0; i < 64; i++) { evil[i] = 'b'; benign[i] = 'a'; }
    evil[64] = benign[64] = '\0';
    snprintf(s.disp_chash, sizeof(s.disp_chash), "%s", benign);

    uint8_t canon[VIRP_APPROVAL_CANON_SIZE];
    ASSERT(virp_approval_build_canonical(s.pid, evil, 5, 1750000000000000000ULL,
                                         300, canon) == VIRP_OK,
           "build evil canonical");
    for (size_t i = 0; i < sizeof(canon); i++)
        snprintf(s.canon_hex + i * 2, 3, "%02x", canon[i]);

    /* A loadable approver key file for --key (else the client fails at
     * load, before the challenge, for the wrong reason). */
    const char *sk = "/tmp/virp-test-hostile.key",
               *pk = "/tmp/virp-test-hostile.pub";
    unlink(sk); unlink(pk);
    ASSERT(virp_fed_save(&g_kp, pk, sk) == VIRP_OK, "save approver key");

    pthread_t srv;
    ASSERT(pthread_create(&srv, NULL, hostile_serve_thread, &s) == 0,
           "spawn hostile daemon");
    /* Wait for the listener to be up before the client connects. */
    for (int i = 0; i < 200 && !__atomic_load_n(&s.ready, __ATOMIC_ACQUIRE); i++)
        usleep(5000);

    char out[8192], cmd[512];
    snprintf(cmd, sizeof(cmd), CLI_BIN " approve %s --socket %s --key %s",
             s.pid, s.sock_path, sk);
    int rc = run_cli(cmd, out, sizeof(out));

    pthread_join(srv, NULL);
    virp_key_destroy(&s.okey);
    unlink(sk); unlink(pk);

    ASSERT(rc == 1, "client must refuse (exit 1), not sign");
    ASSERT(strstr(out, "REFUSING to sign") != NULL, "no refusal message");
    ASSERT(strstr(out, "APPROVED") == NULL, "must not report APPROVED");
    ASSERT(__atomic_load_n(&s.submit_seen, __ATOMIC_ACQUIRE) == 0,
           "client sent a submit for bytes it should have refused");
    PASS();
}

/* Regression for the two-file loader bug: the secret key file that
 * `virp-tool keygen approval` actually writes must load directly via
 * `virp approve --key <prefix>.key`. Run keygen as a subprocess, then
 * approve — the key is not enrolled, so submit is rejected -43, which
 * PROVES the key LOADED and SIGNED (we got past sign_software to submit),
 * rather than failing at key load. */
static void test_cli_keygen_key_loads(void)
{
    TEST("Regression: keygen `.key` loads via `virp approve --key`");
    const char *prefix = "/tmp/virp-test-kg";
    char pubf[64], keyf[64];
    snprintf(pubf, sizeof(pubf), "%s.pub", prefix);
    snprintf(keyf, sizeof(keyf), "%s.key", prefix);
    unlink(pubf); unlink(keyf);

    char out[8192], cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "./build/virp-tool keygen approval %s", prefix);
    ASSERT(run_cli(cmd, out, sizeof(out)) == 0, "keygen failed");

    /* File a proposal so the challenge succeeds. */
    snprintf(cmd, sizeof(cmd),
             CLI_BIN " exec R-APP \"reload\" --socket %s --no-verify", g.socket_path);
    ASSERT(run_cli(cmd, out, sizeof(out)) == 2, "exec block");
    const char *p = strstr(out, "\nproposal_id=");
    ASSERT(p != NULL, "no proposal_id");
    p += strlen("\nproposal_id=");
    char pid[33]; memcpy(pid, p, 32); pid[32] = '\0';

    /* Approve with the single keygen secret file. The key is NOT enrolled,
     * so the daemon rejects the SUBMIT as unenrolled (-43) — but only the
     * signer having loaded and signed gets us that far. */
    snprintf(cmd, sizeof(cmd),
             CLI_BIN " approve %s --socket %s --key %s", pid, g.socket_path,
             keyf);
    int rc = run_cli(cmd, out, sizeof(out));
    ASSERT(strstr(out, "cannot load") == NULL, "key load must NOT fail");
    ASSERT(strstr(out, "-43") != NULL || strstr(out, "unenrolled") != NULL,
           "expected unenrolled submit rejection (key loaded + signed)");
    ASSERT(rc == 2, "submit rejection exit code");
    unlink(pubf); unlink(keyf);
    PASS();
}

/* Each key-load failure cause must produce its OWN message (this is the
 * bug that burned an hour: one string covered five causes). */
static void test_cli_approve_key_diagnostics(void)
{
    TEST("Loader diagnostics: not-found and public-key give distinct msgs");
    /* Need a live proposal so the loader is reached (it runs post-challenge). */
    char out[8192], cmd[1024];
    snprintf(cmd, sizeof(cmd),
             CLI_BIN " exec R-APP \"reload\" --socket %s --no-verify", g.socket_path);
    ASSERT(run_cli(cmd, out, sizeof(out)) == 2, "exec block");
    const char *p = strstr(out, "\nproposal_id=");
    ASSERT(p != NULL, "no proposal_id");
    p += strlen("\nproposal_id=");
    char pid[33]; memcpy(pid, p, 32); pid[32] = '\0';

    /* (a) not found */
    snprintf(cmd, sizeof(cmd),
             CLI_BIN " approve %s --socket %s --key /tmp/virp-nope.key",
             pid, g.socket_path);
    ASSERT(run_cli(cmd, out, sizeof(out)) != 0, "must fail");
    ASSERT(strstr(out, "not found") != NULL, "no not-found message");

    /* (b) a 32-byte PUBLIC key passed where the secret is wanted */
    const char *pub = "/tmp/virp-test-diag.pub", *sk = "/tmp/virp-test-diag.key";
    unlink(pub); unlink(sk);   /* O_EXCL save: clear any prior-run file */
    ASSERT(virp_fed_save(&g_kp, pub, sk) == VIRP_OK, "save");
    snprintf(cmd, sizeof(cmd),
             CLI_BIN " approve %s --socket %s --key %s", pid, g.socket_path, pub);
    ASSERT(run_cli(cmd, out, sizeof(out)) != 0, "must fail");
    ASSERT(strstr(out, "PUBLIC key") != NULL, "no public-key message");
    unlink(pub); unlink(sk);
    PASS();
}

static void test_registry_zero_keys_disables_flow(void)
{
    TEST("Key separation: registry with no usable key disables flow");
    /* The registry only ever carries public SPKI — there is no secret to
     * point the daemon at. A registry whose sole entry is unusable (bad
     * SPKI) enrolls zero keys, and the flow must stay DISABLED (fail
     * safe) rather than accept anything. */
    ASSERT(write_registry(REGISTRY, true, /*bad=*/true) == 0,
           "write bad registry");
    onode_state_t tmp;
    ASSERT(onode_init(&tmp, 0xA9900002, NULL,
                      "/tmp/virp-test-approval2.sock") == VIRP_OK,
           "init failed");
    ASSERT(onode_set_approvers(&tmp, DIR, REGISTRY)
               == VIRP_ERR_KEY_NOT_LOADED, "empty registry must not enable");
    ASSERT(!tmp.approvers_loaded, "flow must stay disabled");
    onode_destroy(&tmp);
    /* Restore the good registry for any later use. */
    ASSERT(write_registry(REGISTRY, true, false) == 0, "restore registry");
    PASS();
}

/* =========================================================================
 * Main
 * ========================================================================= */

/* L2 (2026-08-18): challenge_load()/approval_load_raw() collapsed EVERY
 * read failure (EACCES, EIO, ...) into APPROVAL_NOT_FOUND — a store that
 * exists but cannot be read read as "no such approval". Now ENOENT stays
 * NOT_FOUND and any other open failure is STORE_UNREADABLE (-52), matching
 * the hardened proposal loader. Drives the apply-path loader
 * (approval_load_raw via verify_consume) with an unreadable record. */
static void test_unreadable_store_is_minus52_not_notfound(void)
{
    TEST("L2: unreadable approval record -> store_unreadable (-52), not not-found");
    if (geteuid() == 0) {
        /* root bypasses chmod 000, so the EACCES path cannot be forced. */
        PASS();
        return;
    }

    /* The fix is in the record LOADER (approval_load_raw), which fails on
     * open before any parse — so a record whose bytes are arbitrary but
     * whose FILE is unreadable is enough. Create one directly. */
    const char *pid = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
    char adir[512], rec_path[600];
    snprintf(adir, sizeof(adir), "%s/approvals", DIR);
    mkdir(adir, 0700);   /* ensure the subdir exists (ignore EEXIST) */
    snprintf(rec_path, sizeof(rec_path), "%s/%s.rec", adir, pid);
    FILE *rf = fopen(rec_path, "w");
    ASSERT(rf != NULL, "could not create test approval record");
    fputs("approval-record-bytes\n", rf);
    fclose(rf);

    virp_approval_rec_t out;
    /* Unreadable record: EACCES on open -> STORE_UNREADABLE, not NOT_FOUND. */
    ASSERT(chmod(rec_path, 0000) == 0, "chmod 000 failed");
    virp_error_t e = virp_approval_verify_consume(DIR, &g.approvers, pid,
                        "R-APP", 0xA0A0A0A1, "reload", NULL, 0, &out);
    chmod(rec_path, 0644);   /* restore before asserting, for teardown */
    unlink(rec_path);
    ASSERT(e == VIRP_ERR_APPROVAL_STORE_UNREADABLE,
           "an unreadable record must be -52 store_unreadable, not not-found");

    /* Control: a genuinely MISSING record (ENOENT) stays NOT_FOUND. */
    e = virp_approval_verify_consume(DIR, &g.approvers,
                        "6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b",
                        "R-APP", 0xA0A0A0A1, "reload", NULL, 0, &out);
    ASSERT(e == VIRP_ERR_APPROVAL_NOT_FOUND,
           "a missing record must stay NOT_FOUND (ENOENT)");
    PASS();
}

int main(void)
{
    printf("\n=== VIRP Approval Flow (propose -> approve -> apply) Tests ===\n");

    virp_driver_mock_init();
    if (virp_fed_init() != VIRP_OK) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    nuke_store();

    /* Chain key + dedicated approval keypair (distinct from the O-Key
     * by construction: Ed25519 keypair vs 32-byte HMAC secret). */
    virp_signing_key_t ck;
    virp_key_generate(&ck, VIRP_KEY_TYPE_CHAIN);
    virp_key_save_file(&ck, CHAIN_KEY);
    virp_key_destroy(&ck);

    if (virp_fed_generate(&g_kp, 1) != VIRP_OK) {
        fprintf(stderr, "approval keygen failed\n");
        return 1;
    }
    /* Enroll the Ed25519 approver key in the registry the daemon reads. */
    if (write_registry(REGISTRY, /*enabled=*/true, /*bad=*/false) != 0) {
        fprintf(stderr, "registry write failed\n");
        return 1;
    }

    if (onode_up(&g) != 0) {
        fprintf(stderr, "onode setup failed\n");
        return 1;
    }

    test_block_files_proposal();
    test_e2e_propose_approve_apply();
    test_reused_approval_rejected();
    test_expired_approval_rejected();
    test_hash_mismatch_rejected();
    test_device_mismatch_rejected();
    test_unenrolled_key_rejected();
    test_disabled_key_rejected();
    test_altered_payload_rejected();
    test_challenge_and_submit_consumed_refused();
    test_wrong_algorithm_rejected();
    test_no_approval_plain_block();
    test_unreadable_store_is_minus52_not_notfound();
    test_reuse_survives_restart();
    test_concurrent_submit_one_entry();
    test_concurrent_submit_attribution_two_approvers();
    test_evidence_intent_fail_leaves_approval_consumable();
    test_evidence_chain_beats_emptied_cache();
    test_evidence_readonly_double_apply_executes_nothing();
    test_evidence_concurrent_apply_executes_once();
    test_evidence_ttl_rechecked_after_connect();
    test_evidence_cache_failure_after_intent_still_executes();

    /* Serve the daemon socket for the CLI client tests. */
    pthread_t srv;
    pthread_create(&srv, NULL, serve_thread, &g);
    usleep(200000);
    test_cli_exec_green_executes();
    test_cli_exec_verifies_signature();
    test_cli_exec_red_rejected_with_proposal();
    test_cli_approve_apply_e2e();
    test_cli_approve_refuses_inconsistent_canonical();
    test_cli_keygen_key_loads();
    test_cli_approve_key_diagnostics();
    test_cli_chain_tail_format();
    test_node_config_recorded_at_startup();
    onode_shutdown(&g);
    pthread_join(srv, NULL);

    test_registry_zero_keys_disables_flow();

    onode_down(&g);
    virp_fed_destroy(&g_kp);
    nuke_store();

    printf("\n=== Results: %d passed, %d failed ===\n",
           tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
