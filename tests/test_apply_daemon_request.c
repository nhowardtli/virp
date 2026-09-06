/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — store split: apply is a daemon request, not a directory read
 *
 * Observed 2026-09-05 (and previously 2026-08-19). `virp approve` reaches
 * the approval store through the daemon socket and succeeds as uid 1000;
 * `virp apply` read /var/lib/virp/approvals off disk and failed for any
 * uid that cannot read the daemon's private store. Hence `sudo -u virp`,
 * and hence half of why defect D bit: the operator retried apply under a
 * different uid against an approval the first attempt had already spent.
 *
 * The client read the store for exactly ONE reason: to learn `device` and
 * `command` so it could put them in an `execute` request. Every security
 * decision was already daemon-side. So the daemon now fills both from its
 * OWN store when an apply names only a proposal — which also stops the
 * daemon reading those two fields from the client at all.
 *
 * Asserted below:
 *   [1] an apply naming ONLY a proposal_id executes the approved command
 *       on the approved device, with no device/command from the caller,
 *   [2] the approval is consumed exactly once by that path,
 *   [3] a proposal id that does not exist is NOT_FOUND (-41),
 *   [4] a store directory absent on this host is STORE_ABSENT (-56) —
 *       distinct from [3], which is the conflation the operator hit,
 *   [5] the gate is not weakened: a proposal-only apply still refuses
 *       when the approval is already spent.
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

static const char *DIR       = "/tmp/virp-apdr-approvals";
static const char *CHAIN_DB  = "/tmp/virp-apdr-chain.db";
static const char *CHAIN_KEY = "/tmp/virp-apdr-chain.key";
static const char *REGISTRY  = "/tmp/virp-apdr-approvers.json";
static const char *SOCK      = "/tmp/virp-apdr.sock";
static const char *DEV       = "R-APDR";
static const char *CMD       = "reload";

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
    unlink("/tmp/virp-apdr-chain.db-wal");
    unlink("/tmp/virp-apdr-chain.db-shm");
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
    if (virp_approver_entry_json(spki, sizeof(spki), "apdr-operator",
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
    printf("\n=== VIRP store split: apply as a daemon request ===\n");
    nuke();
    virp_driver_mock_init();

    if (virp_fed_generate(&g_kp, 1) != VIRP_OK) {
        printf("    FAIL: keygen\n"); return 1;
    }
    if (write_registry() != 0) { printf("    FAIL: registry\n"); return 1; }
    if (onode_init(&g, 0xA9D40001, NULL, SOCK) != VIRP_OK) {
        printf("    FAIL: onode_init\n"); return 1;
    }
    g.ctx = virp_context_new();
    if (!g.ctx) { printf("    FAIL: context\n"); return 1; }

    virp_device_t dev;
    memset(&dev, 0, sizeof(dev));
    snprintf(dev.hostname, sizeof(dev.hostname), "%s", DEV);
    snprintf(dev.host, sizeof(dev.host), "10.255.9.11");
    dev.port = 22; dev.vendor = VIRP_VENDOR_MOCK;
    dev.node_id = 0xA9D4A9D4; dev.enabled = true;
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

    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = 0;
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    virp_approval_rec_t apr;

    /* ── propose + approve, exactly as tonight ─────────────────────── */
    if (propose(pid) != 0)  { printf("    FAIL: propose\n"); return 1; }
    if (approve(pid, &apr) != VIRP_OK) { printf("    FAIL: approve\n"); return 1; }

    /* ═══ [1][2] apply naming ONLY the proposal ═══════════════════════
     * No device. No command. The daemon must find both in its own store. */
    printf("\n  -- apply with proposal_id alone --\n");
    (void)virp_driver_mock_exec_attempts_reset();
    virp_error_t e1 = onode_apply_obs(&g, pid, 1, (uid_t)-1,
                                      buf, sizeof(buf), &len);
    CHECK(e1 == VIRP_OK && len > 0,
          "[1] a proposal-only apply is accepted by the daemon");

    virp_header_t hdr;
    virp_observation_t obs;
    const uint8_t *data; uint16_t dl;
    uint8_t ot = 0;
    if (e1 == VIRP_OK &&
        virp_validate_message(buf, len, &g.okey, &hdr) == VIRP_OK &&
        virp_parse_observation(buf + VIRP_HEADER_SIZE, len - VIRP_HEADER_SIZE,
                               &obs, &data, &dl) == VIRP_OK)
        ot = obs.obs_type;
    CHECK(ot == VIRP_OBS_DEVICE_OUTPUT,
          "[1b] and it ran the approved command on the approved device");
    CHECK(virp_driver_mock_exec_attempts_reset() == 1,
          "[2] the device acted exactly once");

    /* ═══ [5] the gate is not weakened ════════════════════════════════ */
    printf("\n  -- the same approval, applied twice --\n");
    (void)virp_driver_mock_exec_attempts_reset();
    len = 0;
    virp_error_t e5 = onode_apply_obs(&g, pid, 1, (uid_t)-1,
                                      buf, sizeof(buf), &len);
    ot = 0;
    if (e5 == VIRP_OK &&
        virp_validate_message(buf, len, &g.okey, &hdr) == VIRP_OK &&
        virp_parse_observation(buf + VIRP_HEADER_SIZE, len - VIRP_HEADER_SIZE,
                               &obs, &data, &dl) == VIRP_OK)
        ot = obs.obs_type;
    CHECK(ot == VIRP_OBS_ERROR,
          "[5] a spent approval is still refused on the proposal-only path");
    CHECK(virp_driver_mock_exec_attempts_reset() == 0,
          "[5b] and nothing reached the device");

    /* ═══ [3][4] the three causes read differently ════════════════════ */
    printf("\n  -- error causes stay distinct --\n");
    len = 0;
    virp_error_t e3 = onode_apply_obs(&g,
                          "deadbeefdeadbeefdeadbeefdeadbeef", 1, (uid_t)-1,
                          buf, sizeof(buf), &len);
    CHECK(e3 == VIRP_ERR_APPROVAL_NOT_FOUND,
          "[3] an unknown proposal in a real store is NOT_FOUND (-41)");

    char saved[VIRP_APPROVAL_DIR_MAX];
    snprintf(saved, sizeof(saved), "%s", g.approval_dir);
    snprintf(g.approval_dir, sizeof(g.approval_dir),
             "/tmp/virp-no-such-store-apdr");
    len = 0;
    virp_error_t e4 = onode_apply_obs(&g, pid, 1, (uid_t)-1,
                                      buf, sizeof(buf), &len);
    snprintf(g.approval_dir, sizeof(g.approval_dir), "%s", saved);
    CHECK(e4 == VIRP_ERR_APPROVAL_STORE_ABSENT,
          "[4] a store absent on this host is STORE_ABSENT (-56)");
    CHECK(e3 != e4,
          "[4b] and the two do NOT share a code — the conflation the "
          "operator hit tonight");

    if (failures == 0) {
        printf("\n=== Results: all store-split checks passed ===\n\n");
        return 0;
    }
    printf("\n=== Results: %d store-split check(s) FAILED ===\n\n", failures);
    return 1;
}
