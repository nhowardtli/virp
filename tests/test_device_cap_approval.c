/*
 * Per-device tier cap vs. the approval path.
 *
 * A device "max_tier" is a ceiling on UNAPPROVED execution, exactly like
 * the node-wide and per-uid ceilings. This suite pins both halves on a
 * device capped at GREEN under a YELLOW node:
 *
 *   - a YELLOW command the node would otherwise auto-execute is refused
 *     and files a proposal (nothing is dispatched), and
 *   - an enrolled approver's signature over that proposal admits it, once.
 *
 * Without the second half a cap would be a hard wall that turned every
 * write on the protected device into a config edit plus a restart; without
 * the first it would protect nothing. The helpers are the ones
 * tests/test_approval_consume_ordering.c uses.
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

static const char *DIR       = "/tmp/virp-devcap-approvals";
static const char *CHAIN_DB  = "/tmp/virp-devcap-chain.db";
static const char *CHAIN_KEY = "/tmp/virp-devcap-chain.key";
static const char *REGISTRY  = "/tmp/virp-devcap-approvers.json";
static const char *SOCK      = "/tmp/virp-devcap.sock";
static const char *DEV       = "SW-CAPPED";
static const char *CMD       = "clear counters";   /* YELLOW on the mock */

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
    unlink("/tmp/virp-devcap-chain.db-wal");
    unlink("/tmp/virp-devcap-chain.db-shm");
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
    if (virp_approver_entry_json(spki, sizeof(spki), "devcap-operator",
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

/* Block a fresh over-cap command; return its proposal id. */
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
    printf("\n=== VIRP per-device tier cap: refusal, proposal, approval ===\n");
    nuke();
    virp_driver_mock_init();

    if (virp_fed_generate(&g_kp, 1) != VIRP_OK) {
        printf("    FAIL: keygen\n"); return 1;
    }
    if (write_registry() != 0) { printf("    FAIL: registry\n"); return 1; }

    if (onode_init(&g, 0xD00D0002, NULL, SOCK) != VIRP_OK) {
        printf("    FAIL: onode_init\n"); return 1;
    }
    g.ctx = virp_context_new();
    if (!g.ctx) { printf("    FAIL: context\n"); return 1; }
    /* compiled-in defaults: ENFORCE, node-wide max_tier=YELLOW */

    virp_device_t dev;
    memset(&dev, 0, sizeof(dev));
    snprintf(dev.hostname, sizeof(dev.hostname), "%s", DEV);
    snprintf(dev.host, sizeof(dev.host), "10.255.9.11");
    dev.port = 22; dev.vendor = VIRP_VENDOR_MOCK;
    dev.node_id = 0xD0D1D0D2; dev.enabled = true;
    dev.max_tier = VIRP_TIER_GREEN;
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

    /* 1. Unapproved: the node-wide YELLOW ceiling would run this. The cap
     *    refuses it, names GREEN as the ceiling, and dispatches nothing. */
    (void)virp_driver_mock_exec_attempts_reset();
    int rc = run_cmd(CMD, NULL, &ot, payload, sizeof(payload));
    CHECK(rc == 0 && ot == VIRP_OBS_ERROR,
          "[1] YELLOW on a GREEN-capped device is REFUSED (signed ERROR)");
    CHECK(strstr(payload, "max=GREEN") != NULL,
          "[1b] the refusal names the device cap as the ceiling");
    CHECK(virp_driver_mock_exec_attempts_reset() == 0,
          "[1c] the driver was never dispatched");

    /* 2. The refusal filed a proposal an approver can sign. */
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    virp_approval_rec_t apr;
    CHECK(propose(pid) == 0, "[2] the refusal carries a proposal id");
    CHECK(approve(pid, &apr) == VIRP_OK,
          "[2b] an enrolled approver can approve it");

    /* 3. The approval admits the command above the cap, exactly once. */
    (void)virp_driver_mock_exec_attempts_reset();
    rc = run_cmd(CMD, pid, &ot, payload, sizeof(payload));
    CHECK(rc == 0 && ot == VIRP_OBS_DEVICE_OUTPUT,
          "[3] the approved command executes on the capped device");
    CHECK(virp_driver_mock_exec_attempts_reset() == 1,
          "[3b] and the device acted exactly once");

    /* 4. The approval is spent: replaying it does not run the command. */
    (void)virp_driver_mock_exec_attempts_reset();
    rc = run_cmd(CMD, pid, &ot, payload, sizeof(payload));
    CHECK(rc == 0 && ot == VIRP_OBS_ERROR,
          "[4] replaying the spent approval is REFUSED");
    CHECK(virp_driver_mock_exec_attempts_reset() == 0,
          "[4b] and nothing is dispatched");

    /* 5. BLACK is unapprovable on a capped device as anywhere else. */
    (void)virp_driver_mock_exec_attempts_reset();
    rc = run_cmd("selfdestruct", NULL, &ot, payload, sizeof(payload));
    CHECK(rc == 0 && ot == VIRP_OBS_ERROR &&
          strstr(payload, "proposal_id=") == NULL,
          "[5] BLACK is refused with no proposal to approve");
    CHECK(virp_driver_mock_exec_attempts_reset() == 0,
          "[5b] and nothing is dispatched");

    onode_destroy(&g);
    virp_context_destroy(g.ctx);
    nuke();

    printf("\n  %s (%d failure%s)\n\n", failures ? "FAILED" : "PASSED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
