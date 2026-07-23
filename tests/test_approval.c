/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Approval flow tests (propose → approve → apply)
 *
 * Required coverage (Task 3):
 *   negative: expired / reused / hash mismatch / device mismatch /
 *             wrong key / no approval at all — each asserting its
 *             DISTINCT error code in the signed rejection
 *   positive: propose → approve → apply → OUTCOME chain entry present
 *             and linked
 *   persistence: a consumed approval stays consumed across a daemon
 *             restart (fresh onode state, same approval store)
 * Plus: the daemon must refuse to load the approval SECRET key as its
 *       verification key (approver/observer key separation).
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

/* =========================================================================
 * CLI tests — `virp exec` and `virp chain tail` against the served
 * daemon. The CLI is a client: everything goes through the framed
 * socket and the same tier gate as any other submission.
 * ========================================================================= */

#include <pthread.h>
#include <sys/wait.h>

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
             CLI_BIN " exec R-APP \"show version\" --socket %s",
             g.socket_path);
    int rc = run_cli(cmd, out, sizeof(out));
    ASSERT(rc == 0, "exit code should be 0 (executed)");
    ASSERT(strstr(out, "trust_tier=GREEN") != NULL, "tier resolution missing");
    ASSERT(strstr(out, "gate_decision=allowed") != NULL, "gate decision missing");
    ASSERT(strstr(out, "R-APP#show version") != NULL, "device output missing");
    PASS();
}

static void test_cli_exec_red_rejected_with_proposal(void)
{
    TEST("CLI: virp exec RED returns rejection + proposal_id");
    char out[8192], cmd[512];
    snprintf(cmd, sizeof(cmd),
             CLI_BIN " exec R-APP \"reload\" --socket %s", g.socket_path);
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
    char out[16384], cmd[512];
    snprintf(cmd, sizeof(cmd),
             CLI_BIN " chain tail -n 50 --db %s", CHAIN_DB);
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
    test_no_approval_plain_block();
    test_reuse_survives_restart();

    /* Serve the daemon socket for the CLI client tests. */
    pthread_t srv;
    pthread_create(&srv, NULL, serve_thread, &g);
    usleep(200000);
    test_cli_exec_green_executes();
    test_cli_exec_red_rejected_with_proposal();
    test_cli_chain_tail_format();
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
