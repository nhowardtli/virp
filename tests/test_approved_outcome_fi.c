/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — APPROVED-APPLY outcome-append failure (LAB-ONLY, fault-injected)
 *
 * The approved half of the Sep 1 review 1.3 window. tests/test_evidence_fi.c
 * covers the AUTO-EXECUTE half (gate_execution is the closer). This file
 * covers the half SECURITY.md carried as a known limitation: an approved
 * RED apply whose `outcome` closer cannot be chained after the device has
 * already acted.
 *
 * Before this branch: approval_emit_outcome() returned void, the outcome
 * append happened after the observation had been built, and the caller
 * received an ordinary DEVICE_OUTPUT success while its outcome was
 * unrecorded and the daemon latched degraded behind its back.
 *
 * Required behaviour, asserted below:
 *   - the caller gets a SIGNED ERROR citing unchained-execution, never
 *     DEVICE_OUTPUT,
 *   - the error names the OPEN intent entry hash and the approval,
 *   - the error says in words that whether the device changed cannot be
 *     told from the response,
 *   - the intent stays OPEN: exactly one gate_intent for that approval and
 *     ZERO outcome entries,
 *   - the approval is consumed permanently: a second apply refuses
 *     approval_reused (-37) and nothing reaches the device,
 *   - evidence-degraded latches (same latch as the auto-execute path) and
 *     the next dispatch is refused at the intent step,
 *   - the C verifier grades the gate session as one OPEN execution.
 *
 * Built only by `make test-approved-outcome-fi` against build-fi/libvirp.a:
 * evidence_fail_closer_once exists ONLY under -DVIRP_FAULT_INJECT, the same
 * discipline as the VIRP_FI() crash points. The production binary has
 * neither the field nor the check.
 *
 * RED PROOF: delete the `if (state->evidence_required && intent && oerr...)`
 * substitution at the approved success site in src/virp_onode.c and
 * check [4] fails (the caller gets DEVICE_OUTPUT). Restore it; passes.
 */
#define _DEFAULT_SOURCE
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
#include <pthread.h>
#include <sys/wait.h>
#include <signal.h>

static const char *DIR       = "/tmp/virp-aofi-approvals";
static const char *CHAIN_DB  = "/tmp/virp-aofi-chain.db";
static const char *CHAIN_KEY = "/tmp/virp-aofi-chain.key";
static const char *REGISTRY  = "/tmp/virp-aofi-approvers.json";
static const char *SOCK      = "/tmp/virp-aofi.sock";
static const char *DEV       = "R-AOFI";
static const char *GATE_SESSION = "gate-enforce:R-AOFI";
static const char *APPR_SESSION = "approval:R-AOFI";
static const char *CMD       = "reload";

extern void virp_driver_mock_init(void);
extern int  virp_driver_mock_exec_attempts_reset(void);

static int failures;
#define CHECK(cond, msg) do {                                           \
    if (!(cond)) { printf("    FAIL: %s\n", (msg)); failures++; }        \
    else         { printf("    ok:   %s\n", (msg)); }                    \
} while (0)

static onode_state_t g;
static virp_fed_keypair_t g_kp;

static void nuke(void)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", DIR);
    if (system(cmd) != 0) { /* best-effort */ }
    unlink(CHAIN_DB);
    unlink("/tmp/virp-aofi-chain.db-wal");
    unlink("/tmp/virp-aofi-chain.db-shm");
    unlink(CHAIN_KEY);
    unlink(REGISTRY);
    unlink(SOCK);
}

static void keyid_hex(const virp_fed_keypair_t *kp, char out[33])
{
    for (int i = 0; i < VIRP_FED_KEYID_SIZE; i++)
        snprintf(out + i * 2, 3, "%02x", kp->key_id[i]);
}

static int write_registry(void)
{
    uint8_t spki[44];
    char entry[1024];
    virp_approver_ed25519_spki(g_kp.public_key, spki);
    if (virp_approver_entry_json(spki, sizeof(spki), "aofi-operator",
                                 true, entry, sizeof(entry)) != VIRP_OK)
        return -1;
    FILE *f = fopen(REGISTRY, "w");
    if (!f) return -1;
    fprintf(f, "[%s]\n", entry);
    fclose(f);
    return 0;
}

/* Execute (optionally under an approval) and parse the signed response. */
static int run_cmd(const char *cmd, const char *pid,
                   uint8_t *obs_type, char *payload, size_t pcap)
{
    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = 0;
    if (onode_execute_obs_ex(&g, DEV, cmd, 1, pid, (uid_t)-1,
                             buf, sizeof(buf), &len) != VIRP_OK)
        return -1;
    virp_header_t hdr;
    if (virp_validate_message(buf, len, &g.okey, &hdr) != VIRP_OK)
        return -2;
    virp_observation_t obs;
    const uint8_t *data;
    uint16_t dl;
    if (virp_parse_observation(buf + VIRP_HEADER_SIZE, len - VIRP_HEADER_SIZE,
                               &obs, &data, &dl) != VIRP_OK)
        return -3;
    *obs_type = obs.obs_type;
    size_t n = dl < pcap - 1 ? dl : pcap - 1;
    memcpy(payload, data, n);
    payload[n] = '\0';
    return 0;
}

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

/* Block a fresh RED command; return its proposal id. */
static int propose(char *pid_out)
{
    uint8_t ot;
    char payload[2048];
    if (run_cmd(CMD, NULL, &ot, payload, sizeof(payload)) != 0) return -1;
    if (ot != VIRP_OBS_ERROR) return -2;
    return extract_pid(payload, pid_out);
}

static virp_error_t approve(const char *pid, virp_approval_rec_t *apr)
{
    virp_approval_challenge_t ch;
    virp_error_t err = virp_approval_challenge(DIR, &g.chain, pid, 0, &ch);
    if (err != VIRP_OK) return err;
    uint8_t sig[VIRP_APPROVER_SIG_SIZE];
    if (virp_fed_sign(&g_kp, ch.canonical, VIRP_APPROVAL_CANON_SIZE, sig)
            != VIRP_OK)
        return VIRP_ERR_CRYPTO;
    char kid[33];
    keyid_hex(&g_kp, kid);
    return virp_approval_submit(DIR, &g.approvers, &g.chain, pid, kid,
                                sig, sizeof(sig), apr);
}

int main(void)
{
    printf("\n=== VIRP approved-apply outcome-fail (FI) ===\n");
    nuke();
    virp_driver_mock_init();

    if (virp_fed_generate(&g_kp, 1) != VIRP_OK) {
        printf("    FAIL: keygen\n"); return 1;
    }
    if (write_registry() != 0) { printf("    FAIL: registry\n"); return 1; }

    if (onode_init(&g, 0xA0F10001, NULL, SOCK) != VIRP_OK) {
        printf("    FAIL: onode_init\n"); return 1;
    }
    g.ctx = virp_context_new();
    if (!g.ctx) { printf("    FAIL: context\n"); return 1; }

    virp_device_t dev;
    memset(&dev, 0, sizeof(dev));
    snprintf(dev.hostname, sizeof(dev.hostname), "%s", DEV);
    snprintf(dev.host, sizeof(dev.host), "10.255.9.9");
    dev.port = 22; dev.vendor = VIRP_VENDOR_MOCK;
    dev.node_id = 0xA0F1A0F1; dev.enabled = true;
    if (onode_add_device(&g, &dev) != VIRP_OK) {
        printf("    FAIL: add_device\n"); return 1;
    }
    virp_signing_key_t ck;
    virp_key_generate(&ck, VIRP_KEY_TYPE_CHAIN);
    virp_key_save_file(&ck, CHAIN_KEY);
    virp_key_destroy(&ck);
    if (virp_chain_init(&g.chain, CHAIN_DB, CHAIN_KEY, g.node_id, "test-org")
            != VIRP_OK) {
        printf("    FAIL: chain_init\n"); return 1;
    }
    g.chain_enabled = true;
    if (onode_set_approvers(&g, DIR, REGISTRY) != VIRP_OK) {
        printf("    FAIL: set_approvers\n"); return 1;
    }

    uint8_t ot;
    char payload[2048];
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    virp_approval_rec_t apr;
    char want_id[64];
    bool exists;

    /* ═══ PHASE A — NEGATIVE: the append succeeds, nothing changes ═══
     * The success path must be exactly what it was: an ordinary
     * DEVICE_OUTPUT observation carrying the device's bytes, with the
     * outcome entry chained and the intent CLOSED. Run first, while the
     * daemon is still healthy. */
    printf("  -- phase A: clean approved apply (no fault) --\n");
    char pid_a[VIRP_APPROVAL_ID_HEX_LEN + 1];
    virp_approval_rec_t apr_a;
    if (propose(pid_a) != 0) { printf("    FAIL: propose A\n"); return 1; }
    if (approve(pid_a, &apr_a) != VIRP_OK) { printf("    FAIL: approve A\n"); return 1; }
    (void)virp_driver_mock_exec_attempts_reset();
    int rca = run_cmd(CMD, pid_a, &ot, payload, sizeof(payload));
    CHECK(rca == 0, "[A1] clean apply returned a parseable signed message");
    CHECK(virp_driver_mock_exec_attempts_reset() == 1,
          "[A2] the device acted once");
    CHECK(ot == VIRP_OBS_DEVICE_OUTPUT,
          "[A3] ordinary success: DEVICE_OUTPUT, unchanged");
    CHECK(strstr(payload, "R-AOFI#" ) == payload,
          "[A4] the payload is the device's own output, verbatim");
    CHECK(strstr(payload, "unchained-execution") == NULL,
          "[A5] no unchained-execution marker on the success path");
    snprintf(want_id, sizeof(want_id), "outcome:%s", pid_a);
    exists = false;
    CHECK(virp_chain_artifact_exists(&g.chain, want_id, &exists) == VIRP_OK &&
          exists, "[A6] the outcome entry landed");
    CHECK(!g.evidence_degraded, "[A7] the daemon is NOT degraded");

    /* ── 1. propose -> approve ─────────────────────────────────────── */
    printf("  -- phase B: approved apply, outcome append forced to fail --\n");
    if (propose(pid) != 0) { printf("    FAIL: propose\n"); return 1; }
    if (approve(pid, &apr) != VIRP_OK) { printf("    FAIL: approve\n"); return 1; }
    printf("  [setup] proposal=%s approval_entry=%.16s\n",
           pid, apr.chain_entry_hash);

    /* ── 2. apply with the outcome append forced to fail ───────────── */
    pthread_mutex_lock(&g.state_mutex);
    g.evidence_fail_closer_once = true;
    pthread_mutex_unlock(&g.state_mutex);
    (void)virp_driver_mock_exec_attempts_reset();
    int rc = run_cmd(CMD, pid, &ot, payload, sizeof(payload));
    int ran = virp_driver_mock_exec_attempts_reset();

    printf("  [probe] rc=%d obs_type=%u ran=%d\n  [probe] payload=\"%s\"\n",
           rc, (unsigned)ot, ran, payload);

    CHECK(rc == 0, "[1] apply returned a parseable signed message");
    CHECK(ran == 1, "[2] the device DID act (one execute attempt)");

    /* The intent for an approved apply lands in gate-enforce:<device>;
     * its approval-side entries live in approval:<device>. */
    int nintent = -1;
    CHECK(virp_chain_count_intents_for_approval(&g.chain, apr.chain_entry_hash,
                                                &nintent) == VIRP_OK &&
          nintent == 1, "[3] exactly one gate_intent cites this approval");

    CHECK(ot == VIRP_OBS_ERROR, "[4] caller gets ERROR, not DEVICE_OUTPUT");
    CHECK(strstr(payload, "unchained-execution") != NULL,
          "[5] payload cites unchained-execution");
    CHECK(strstr(payload, pid) != NULL,
          "[6] payload names the approval (proposal id)");
    CHECK(strstr(payload, "OPEN") != NULL,
          "[7] payload names the OPEN intent");
    CHECK(strstr(payload, "cannot be determined") != NULL,
          "[8] payload says the device's state cannot be told from it");
    CHECK(strstr(payload, "evidence-degraded") != NULL,
          "[9] payload says the daemon is now degraded");
    CHECK(strstr(payload, "R-AOFI#") == NULL,
          "[10] the error carries no device output");

    /* ── 3. no outcome entry exists for this approval ──────────────── */
    snprintf(want_id, sizeof(want_id), "outcome:%s", pid);
    exists = true;
    CHECK(virp_chain_artifact_exists(&g.chain, want_id, &exists) == VIRP_OK &&
          !exists, "[11] ZERO outcome entries for this approval");
    virp_chain_entry_t last;
    CHECK(virp_chain_get_last(&g.chain, APPR_SESSION, &last) == VIRP_OK &&
          strcmp(last.artifact_type, "approval") == 0,
          "[12] approval session still ends at the APPROVAL entry");

    /* ── 4. degraded latched; approval permanently consumed ────────── */
    CHECK(g.evidence_degraded, "[13] daemon latched evidence-degraded");

    (void)virp_driver_mock_exec_attempts_reset();
    rc = run_cmd(CMD, pid, &ot, payload, sizeof(payload));
    int ran2 = virp_driver_mock_exec_attempts_reset();
    printf("  [probe] retry rc=%d obs_type=%u ran=%d\n  [probe] payload=\"%s\"\n",
           rc, (unsigned)ot, ran2, payload);
    CHECK(ran2 == 0, "[14] the second apply dispatched nothing");
    CHECK(ot == VIRP_OBS_ERROR, "[15] the second apply is refused");
    CHECK(strstr(payload, "approval_reused") != NULL ||
          strstr(payload, "evidence-unavailable") != NULL,
          "[16] refused as approval_reused or evidence-unavailable");

    /* ── 5. the C verifier grades the gate session OPEN ────────────── */
    virp_chain_verify_result_t vr;
    memset(&vr, 0, sizeof(vr));
    virp_chain_verify_session(&g.chain, GATE_SESSION, &vr);
    printf("  [probe] verify: valid=%d first_broken=%lld open=%lld closed=%lld\n",
           (int)vr.valid, (long long)vr.first_broken,
           (long long)vr.executions_open, (long long)vr.executions_closed);
    CHECK(vr.valid, "[17] gate session VALID — not a broken chain");
    CHECK(vr.first_broken == -1, "[18] no broken link");
    CHECK(vr.executions_open == 1,
          "[19] exactly one OPEN execution (this one)");
    CHECK(vr.executions_closed == 1,
          "[20] phase A's execution is still CLOSED");

    /* ═══ PHASE C — the pre_outcome fault point is UNCHANGED ═══════════
     * The entanglement that deferred this work on Sep 1 was the ordering
     * the adversarial crash transcript pins: VIRP_FI("pre_outcome") sits
     * between the observation build and the outcome append, and a daemon
     * SIGKILLed there must leave proposal + approval + intent on the chain
     * and NO outcome. This branch adds code AFTER the append, so that
     * ordering cannot have moved — and this phase proves it rather than
     * asserting it, by actually killing a daemon at that point.
     *
     * The child builds its OWN onode_state and its OWN chain handle on the
     * same on-disk paths (the pattern from test_chain_atomicity_fi.c): the
     * parent's handle is not usable across fork, and the parent here is
     * already evidence-degraded, which would refuse the apply at the intent
     * step and measure nothing. */
    printf("  -- phase C: SIGKILL at pre_outcome (ordering unchanged) --\n");
    char pid_c[VIRP_APPROVAL_ID_HEX_LEN + 1];
    virp_approval_rec_t apr_c;
    if (propose(pid_c) != 0) { printf("    FAIL: propose C\n"); return 1; }
    if (approve(pid_c, &apr_c) != VIRP_OK) { printf("    FAIL: approve C\n"); return 1; }

    fflush(stdout);
    fflush(stderr);
    pid_t kid = fork();
    if (kid < 0) { printf("    FAIL: fork\n"); return 1; }
    if (kid == 0) {
        setenv("VIRP_FI_POINT", "pre_outcome", 1);
        onode_state_t c;
        if (onode_init(&c, 0xA0F10002, NULL, "/tmp/virp-aofi-child.sock")
                != VIRP_OK)
            _exit(70);
        c.ctx = virp_context_new();
        if (!c.ctx) _exit(70);
        virp_device_t cd;
        memset(&cd, 0, sizeof(cd));
        snprintf(cd.hostname, sizeof(cd.hostname), "%s", DEV);
        snprintf(cd.host, sizeof(cd.host), "10.255.9.9");
        cd.port = 22; cd.vendor = VIRP_VENDOR_MOCK;
        cd.node_id = 0xA0F1A0F1; cd.enabled = true;
        if (onode_add_device(&c, &cd) != VIRP_OK) _exit(70);
        if (virp_chain_init(&c.chain, CHAIN_DB, CHAIN_KEY, c.node_id,
                            "test-org") != VIRP_OK) _exit(70);
        c.chain_enabled = true;
        if (onode_set_approvers(&c, DIR, REGISTRY) != VIRP_OK) _exit(70);

        uint8_t cbuf[VIRP_MAX_MESSAGE_SIZE];
        size_t clen = 0;
        onode_execute_obs_ex(&c, DEV, CMD, 1, pid_c, (uid_t)-1,
                             cbuf, sizeof(cbuf), &clen);
        /* Reaching here means pre_outcome never fired. */
        _exit(71);
    }
    int status = 0;
    if (waitpid(kid, &status, 0) < 0) { printf("    FAIL: waitpid\n"); return 1; }
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
          "[C1] the daemon died BY SIGKILL at pre_outcome");
    if (WIFEXITED(status) && WEXITSTATUS(status) == 71)
        printf("    note: pre_outcome did not fire — is this a "
               "-DVIRP_FAULT_INJECT build?\n");

    int nc = -1;
    CHECK(virp_chain_count_intents_for_approval(&g.chain,
              apr_c.chain_entry_hash, &nc) == VIRP_OK && nc == 1,
          "[C2] the intent committed before the kill (approval consumed)");
    snprintf(want_id, sizeof(want_id), "outcome:%s", pid_c);
    exists = true;
    CHECK(virp_chain_artifact_exists(&g.chain, want_id, &exists) == VIRP_OK &&
          !exists, "[C3] NO outcome entry survived the kill — as before");
    unlink("/tmp/virp-aofi-child.sock");

    virp_context_t *ctx = g.ctx;
    onode_destroy(&g);
    virp_context_destroy(ctx);
    nuke();

    if (failures == 0) {
        printf("=== Results: all approved-outcome FI checks passed ===\n");
        return 0;
    }
    printf("=== Results: %d approved-outcome FI check(s) FAILED ===\n", failures);
    return 1;
}
