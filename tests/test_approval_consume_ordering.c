/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — defect D: an approval is spent only when the device was reachable
 *
 * Observed 2026-09-05, production. `virp apply` committed the consuming
 * intent and the apply then failed; a retry returned approval_reused
 * (err=-37). A failed apply had consumed the approval and NO device
 * execution ever happened. The human had to re-approve a RED command
 * that had never run.
 *
 * Mechanism. get_connection() returns the CACHED connection with no
 * liveness check — "assume connected until a write fails". SW-3850's
 * vty had idled out (exec-timeout 10) between the approve and the
 * apply, so:
 *
 *     get_connection()  -> non-NULL, but the channel is dead
 *     gate_emit_intent()-> COMMITTED = the approval is now spent
 *     drv->execute()    -> transport failure, nothing dispatched
 *
 * The consume ordering was already careful about the store, the driver
 * and a NULL connection — all of those refuse before the intent commit.
 * The gap is the one the brief names: the session must be "live enough
 * to attempt the write" BEFORE the approval is spent.
 *
 * Asserted below:
 *   [1] an apply against a dead session is REFUSED,
 *   [2] the driver is never dispatched,
 *   [3] NO gate_intent is committed for that approval,
 *   [4] the approval is UNCONSUMED and the SAME proposal applies
 *       successfully once the session recovers,
 *   [5] a healthy apply still consumes exactly once (no weakening),
 *   [6] re-applying a spent approval still refuses approval_reused,
 *   [7] a DEVICE-LEVEL rejection — the command reached the device and
 *       the device said no — DOES consume. See the log: this is the
 *       question flagged for Nate's confirmation.
 *
 * RED PROOF: delete the liveness gate in src/virp_onode.c (the
 * `approved && drv->health_check` block before the consume) and checks
 * [1]-[4] fail exactly as production did.
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

static const char *DIR       = "/tmp/virp-dord-approvals";
static const char *CHAIN_DB  = "/tmp/virp-dord-chain.db";
static const char *CHAIN_KEY = "/tmp/virp-dord-chain.key";
static const char *REGISTRY  = "/tmp/virp-dord-approvers.json";
static const char *SOCK      = "/tmp/virp-dord.sock";
static const char *DEV       = "R-DORD";
static const char *CMD       = "reload";

extern void virp_driver_mock_set_dead_session(bool on);
extern void virp_driver_mock_set_output(const char *text);

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
    unlink("/tmp/virp-dord-chain.db-wal");
    unlink("/tmp/virp-dord-chain.db-shm");
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
    if (virp_approver_entry_json(spki, sizeof(spki), "dord-operator",
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
    printf("\n=== VIRP defect D: consume only when the device is reachable ===\n");
    nuke();
    virp_driver_mock_init();

    if (virp_fed_generate(&g_kp, 1) != VIRP_OK) {
        printf("    FAIL: keygen\n"); return 1;
    }
    if (write_registry() != 0) { printf("    FAIL: registry\n"); return 1; }

    if (onode_init(&g, 0xD00D0001, NULL, SOCK) != VIRP_OK) {
        printf("    FAIL: onode_init\n"); return 1;
    }
    g.ctx = virp_context_new();
    if (!g.ctx) { printf("    FAIL: context\n"); return 1; }

    virp_device_t dev;
    memset(&dev, 0, sizeof(dev));
    snprintf(dev.hostname, sizeof(dev.hostname), "%s", DEV);
    snprintf(dev.host, sizeof(dev.host), "10.255.9.10");
    dev.port = 22; dev.vendor = VIRP_VENDOR_MOCK;
    dev.node_id = 0xD0D1D0D1; dev.enabled = true;
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
    char want_id[64];
    bool exists;

    /* ═══ PHASE 1 — THE DEFECT ════════════════════════════════════════
     * Propose, approve, then let the device session die before the
     * apply — exactly tonight's gap between approve and apply. */
    printf("\n  -- phase 1: apply against a session the device closed --\n");
    char pid1[VIRP_APPROVAL_ID_HEX_LEN + 1];
    virp_approval_rec_t apr1;
    if (propose(pid1) != 0) { printf("    FAIL: propose 1\n"); return 1; }
    if (approve(pid1, &apr1) != VIRP_OK) { printf("    FAIL: approve 1\n"); return 1; }

    virp_driver_mock_set_dead_session(true);
    (void)virp_driver_mock_exec_attempts_reset();
    int rc1 = run_cmd(CMD, pid1, &ot, payload, sizeof(payload));

    CHECK(rc1 == 0 && ot == VIRP_OBS_ERROR,
          "[1] an apply against a dead session is REFUSED (signed ERROR)");
    CHECK(virp_driver_mock_exec_attempts_reset() == 0,
          "[2] the driver was never dispatched");
    /* The chain is the authority on consumption: an approval is spent iff
     * a committed gate_intent cites its entry hash. */
    int intents = -1;
    CHECK(virp_chain_count_intents_for_approval(&g.chain,
              apr1.chain_entry_hash, &intents) == VIRP_OK && intents == 0,
          "[3] NO gate_intent cites the approval — nothing consumed it");

    /* The session comes back (a reconnect, or the watchdog). The SAME
     * approval must still work: the human approved this command once and
     * it never ran. */
    virp_driver_mock_set_dead_session(false);
    (void)virp_driver_mock_exec_attempts_reset();
    int rc1b = run_cmd(CMD, pid1, &ot, payload, sizeof(payload));
    CHECK(rc1b == 0 && ot == VIRP_OBS_DEVICE_OUTPUT,
          "[4] the SAME approval applies once the session recovers "
          "(it was never spent)");
    CHECK(virp_driver_mock_exec_attempts_reset() == 1,
          "[4b] and the device acted exactly once");

    /* ═══ PHASE 2 — NO WEAKENING ══════════════════════════════════════ */
    printf("\n  -- phase 2: a spent approval is still spent --\n");
    snprintf(want_id, sizeof(want_id), "outcome:%s", pid1);
    exists = false;
    CHECK(virp_chain_artifact_exists(&g.chain, want_id, &exists) == VIRP_OK &&
          exists, "[5] the successful apply chained its outcome");

    (void)virp_driver_mock_exec_attempts_reset();
    int rc2 = run_cmd(CMD, pid1, &ot, payload, sizeof(payload));
    CHECK(rc2 == 0 && ot == VIRP_OBS_ERROR &&
          strstr(payload, "approval_reused") != NULL,
          "[6] re-applying a spent approval still refuses approval_reused");
    CHECK(virp_driver_mock_exec_attempts_reset() == 0,
          "[6b] and nothing reached the device");

    /* ═══ PHASE 3 — THE DEVICE-LEVEL REJECTION QUESTION ═══════════════
     * The command REACHED the device and the device rejected it. Per
     * the brief's lean: a real execution attempt that reached the device
     * consumes the approval; a failure before the device does not.
     * Encoded here as the expectation, FLAGGED for Nate's confirmation. */
    printf("\n  -- phase 3: a device-level rejection consumes (confirm?) --\n");
    char pid3[VIRP_APPROVAL_ID_HEX_LEN + 1];
    virp_approval_rec_t apr3;
    if (propose(pid3) != 0) { printf("    FAIL: propose 3\n"); return 1; }
    if (approve(pid3, &apr3) != VIRP_OK) { printf("    FAIL: approve 3\n"); return 1; }

    /* The device ANSWERS, and its answer is a rejection. This is what a
     * real IOS invalid command looks like: the read completes normally,
     * on the prompt, and the body is the device's own refusal text. It
     * is emphatically NOT a pre-dispatch refusal — the bytes went out
     * and the device processed them. That is the distinction phase 3
     * exists to pin. */
    virp_driver_mock_set_output("% Invalid input detected at '^' marker.");
    (void)virp_driver_mock_exec_attempts_reset();
    int rc3 = run_cmd(CMD, pid3, &ot, payload, sizeof(payload));
    (void)rc3;
    CHECK(virp_driver_mock_exec_attempts_reset() == 1,
          "[7a] the command DID reach the device");
    virp_driver_mock_set_output(NULL);

    (void)virp_driver_mock_exec_attempts_reset();
    int rc3b = run_cmd(CMD, pid3, &ot, payload, sizeof(payload));
    CHECK(rc3b == 0 && ot == VIRP_OBS_ERROR &&
          strstr(payload, "approval_reused") != NULL,
          "[7b] a device-level rejection CONSUMED the approval "
          "(re-apply refuses) - NATE: confirm this is the intent");
    CHECK(virp_driver_mock_exec_attempts_reset() == 0,
          "[7c] and the re-apply reached nothing");

    if (failures == 0) {
        printf("\n=== Results: all defect-D consume-ordering checks passed ===\n\n");
        return 0;
    }
    printf("\n=== Results: %d defect-D check(s) FAILED ===\n\n", failures);
    return 1;
}
