/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — regressions for the O-Node security review (security/onode-review-1)
 *
 * One test function per finding ID, named t_<ID>_<what>, so the PR's
 * findings table can cite a test by name and `test_onode_review <name>`
 * can run it alone. Every one of these FAILS against the tree as it stood
 * before its fix; REVIEW-NOTES.md records how each was shown to.
 *
 * The daemon source is included rather than linked, the same way
 * tests/test_security_handlers.c does it: most of what the review found
 * lives in static functions (parse_request, fed_outcome_citation, the gate
 * helpers), and a test that can only reach them through a socket ends up
 * testing the socket.
 *
 * No network I/O and no real device: the mock driver stands in for the far
 * end, and every fixture lives under one mkdtemp() directory that is
 * removed on exit, so this suite cannot collide with another suite's fixed
 * /tmp paths or with a second copy of itself.
 */
#include "../src/virp_onode.c"

#include "virp_federation.h"
#include <assert.h>
#include <fcntl.h>
#include <sys/wait.h>

extern void virp_driver_mock_init(void);
extern int  virp_driver_mock_exec_attempts_reset(void);

static int failures;
#define CHECK(cond, msg) do {                                           \
    if (!(cond)) { printf("    FAIL: %s\n", (msg)); failures++; }        \
    else         { printf("    ok:   %s\n", (msg)); }                    \
} while (0)

/* =========================================================================
 * Fixture: a daemon state with one mock device, a chain and an enrolled
 * approver — everything the approval path needs, nothing listening.
 * ========================================================================= */

static char g_root[64];              /* mkdtemp root for the whole run */

typedef struct {
    onode_state_t       st;
    virp_fed_keypair_t  kp;
    char                dir[160];    /* approval store */
    char                db[160];
    char                key[160];
    char                reg[160];
    bool                up;
} fx_t;

/* onode_state_t is several hundred KB; keep fixtures off the stack. */
static fx_t g_fx;

#define FX_DEV "R-REV"

static void fx_keyid_hex(const virp_fed_keypair_t *kp, char out[33])
{
    for (int i = 0; i < VIRP_FED_KEYID_SIZE; i++)
        snprintf(out + i * 2, 3, "%02x", kp->key_id[i]);
}

static bool fx_init(fx_t *fx, const char *name)
{
    memset(fx, 0, sizeof(*fx));
    char base[128];
    snprintf(base, sizeof(base), "%s/%s", g_root, name);
    if (mkdir(base, 0700) != 0) return false;
    snprintf(fx->dir, sizeof(fx->dir), "%s/approvals", base);
    snprintf(fx->db,  sizeof(fx->db),  "%s/chain.db", base);
    snprintf(fx->key, sizeof(fx->key), "%s/chain.key", base);
    snprintf(fx->reg, sizeof(fx->reg), "%s/approvers.json", base);
    char sock[160];
    snprintf(sock, sizeof(sock), "%s/onode.sock", base);

    if (virp_fed_generate(&fx->kp, 1) != VIRP_OK) return false;
    uint8_t spki[44];
    char entry[1024];
    virp_approver_ed25519_spki(fx->kp.public_key, spki);
    if (virp_approver_entry_json(spki, sizeof(spki), "review-operator",
                                 true, entry, sizeof(entry)) != VIRP_OK)
        return false;
    FILE *f = fopen(fx->reg, "w");
    if (!f) return false;
    fprintf(f, "[%s]\n", entry);
    fclose(f);

    if (onode_init(&fx->st, 0x5EC00001, NULL, sock) != VIRP_OK) return false;
    fx->st.ctx = virp_context_new();
    if (!fx->st.ctx) return false;

    virp_device_t dev;
    memset(&dev, 0, sizeof(dev));
    snprintf(dev.hostname, sizeof(dev.hostname), "%s", FX_DEV);
    snprintf(dev.host, sizeof(dev.host), "10.255.7.10");
    dev.port = 22; dev.vendor = VIRP_VENDOR_MOCK;
    dev.node_id = 0x5EC0D0D1; dev.enabled = true;
    if (onode_add_device(&fx->st, &dev) != VIRP_OK) return false;

    virp_signing_key_t ck;
    if (virp_key_generate(&ck, VIRP_KEY_TYPE_CHAIN) != VIRP_OK) return false;
    virp_key_save_file(&ck, fx->key);
    virp_key_destroy(&ck);
    if (virp_chain_init(&fx->st.chain, fx->db, fx->key, fx->st.node_id,
                        "review-org") != VIRP_OK)
        return false;
    fx->st.chain_enabled = true;
    if (onode_set_approvers(&fx->st, fx->dir, fx->reg) != VIRP_OK)
        return false;
    fx->up = true;
    return true;
}

static void fx_destroy(fx_t *fx)
{
    if (!fx->up) return;
    virp_context_t *ctx = fx->st.ctx;
    onode_destroy(&fx->st);
    virp_context_destroy(ctx);
    fx->up = false;
}

/* Execute through the real gate and unpack the signed v1 response. */
static int fx_run(fx_t *fx, const char *device, const char *cmd,
                  const char *pid, uid_t uid,
                  uint8_t *obs_type, char *payload, size_t pcap)
{
    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = 0;
    if (onode_execute_obs_ex(&fx->st, device, cmd, 1, pid, uid,
                             buf, sizeof(buf), &len) != VIRP_OK)
        return -1;
    virp_header_t hdr;
    if (virp_validate_message(buf, len, &fx->st.okey, &hdr) != VIRP_OK)
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

static int fx_extract_pid(const char *payload, char *pid_out)
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

/* Block a RED command and return the proposal the refusal filed. */
static int fx_propose(fx_t *fx, const char *cmd, char *pid_out)
{
    uint8_t ot;
    char payload[2048];
    if (fx_run(fx, FX_DEV, cmd, NULL, (uid_t)-1, &ot, payload,
               sizeof(payload)) != 0)
        return -1;
    if (ot != VIRP_OBS_ERROR) return -2;
    return fx_extract_pid(payload, pid_out);
}

static virp_error_t fx_approve(fx_t *fx, const char *pid,
                               virp_approval_rec_t *apr)
{
    virp_approval_challenge_t ch;
    virp_error_t err = virp_approval_challenge(fx->dir, &fx->st.chain, pid,
                                               0, &ch);
    if (err != VIRP_OK) return err;
    uint8_t sig[VIRP_APPROVER_SIG_SIZE];
    if (virp_fed_sign(&fx->kp, ch.canonical, VIRP_APPROVAL_CANON_SIZE, sig)
            != VIRP_OK)
        return VIRP_ERR_CRYPTO;
    char kid[33];
    fx_keyid_hex(&fx->kp, kid);
    return virp_approval_submit(fx->dir, &fx->st.approvers, &fx->st.chain,
                                pid, kid, sig, sizeof(sig), apr);
}

/* =========================================================================
 * H1 — approved-apply replay guard
 *
 * The approval record on disk is three lines: the signed body, the
 * signature, and the APPROVAL chain entry hash. Only the first is covered
 * by the approver's signature. These tests play the party who can write
 * the approval store but holds no approver key.
 * ========================================================================= */

/* Rewrite line 3 of an approval record, leaving body and signature
 * byte-identical — so the record still verifies. */
static bool h1_rewrite_hash_line(const fx_t *fx, const char *pid,
                                 const char *new_line3)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/approvals/%s.rec", fx->dir, pid);
    char buf[8192];
    FILE *f = fopen(path, "r");
    if (!f) return false;
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    char *l2 = strchr(buf, '\n');
    if (!l2) return false;
    char *l3 = strchr(l2 + 1, '\n');
    if (!l3) return false;
    l3[1] = '\0';                      /* keep "body\nsig\n" */
    f = fopen(path, "w");
    if (!f) return false;
    fprintf(f, "%s%s\n", buf, new_line3);
    fclose(f);
    return true;
}

static void h1_forget_consumed(const fx_t *fx)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/consumed.list", fx->dir);
    unlink(path);
}

/* propose + approve + one successful apply; leaves pid spent. */
static bool h1_spend(fx_t *fx, char *pid)
{
    uint8_t ot;
    char payload[2048];
    virp_approval_rec_t apr;
    if (fx_propose(fx, "reload", pid) != 0) return false;
    if (fx_approve(fx, pid, &apr) != VIRP_OK) return false;
    (void)virp_driver_mock_exec_attempts_reset();
    if (fx_run(fx, FX_DEV, "reload", pid, (uid_t)-1, &ot, payload,
               sizeof(payload)) != 0)
        return false;
    return virp_driver_mock_exec_attempts_reset() == 1;
}

static void t_H1_blanked_hash_replay(void)
{
    printf("\n  H1: spent approval, record hash line BLANKED, cache deleted\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "h1-blank")) { CHECK(false, "fixture"); return; }
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    CHECK(h1_spend(fx, pid), "first apply executes exactly once");

    CHECK(h1_rewrite_hash_line(fx, pid, ""), "hash line blanked");
    h1_forget_consumed(fx);

    uint8_t ot = 0;
    char payload[2048] = "";
    (void)virp_driver_mock_exec_attempts_reset();
    int rc = fx_run(fx, FX_DEV, "reload", pid, (uid_t)-1, &ot, payload,
                    sizeof(payload));
    CHECK(rc == 0 && ot == VIRP_OBS_ERROR,
          "replay with a blanked hash line is REFUSED (signed ERROR)");
    CHECK(virp_driver_mock_exec_attempts_reset() == 0,
          "and nothing reached the device");
    int n = -1;
    CHECK(virp_chain_count_intents_for_proposal(&fx->st.chain, pid, &n)
              == VIRP_OK && n == 1,
          "exactly ONE gate_intent names the proposal — no second consume");
    fx_destroy(fx);
}

static void t_H1_altered_hash_replay(void)
{
    printf("\n  H1: spent approval, record hash line ALTERED, cache deleted\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "h1-alter")) { CHECK(false, "fixture"); return; }
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    CHECK(h1_spend(fx, pid), "first apply executes exactly once");

    char other[65];
    memset(other, 'a', 64); other[64] = '\0';
    CHECK(h1_rewrite_hash_line(fx, pid, other), "hash line altered");
    h1_forget_consumed(fx);

    uint8_t ot = 0;
    char payload[2048] = "";
    (void)virp_driver_mock_exec_attempts_reset();
    int rc = fx_run(fx, FX_DEV, "reload", pid, (uid_t)-1, &ot, payload,
                    sizeof(payload));
    CHECK(rc == 0 && ot == VIRP_OBS_ERROR,
          "replay with an altered hash line is REFUSED (signed ERROR)");
    CHECK(virp_driver_mock_exec_attempts_reset() == 0,
          "and nothing reached the device");
    int n = -1;
    CHECK(virp_chain_count_intents_for_proposal(&fx->st.chain, pid, &n)
              == VIRP_OK && n == 1,
          "exactly ONE gate_intent names the proposal — no second consume");
    fx_destroy(fx);
}

static void t_H1_second_apply_inside_ttl(void)
{
    printf("\n  H1: second apply inside the TTL, cache intact\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "h1-ttl")) { CHECK(false, "fixture"); return; }
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    CHECK(h1_spend(fx, pid), "first apply executes exactly once");

    /* Untampered: the pre-existing guard already refused this. Pinned so
     * the rewrite did not trade one hole for another. */
    uint8_t ot = 0;
    char payload[2048] = "";
    (void)virp_driver_mock_exec_attempts_reset();
    int rc = fx_run(fx, FX_DEV, "reload", pid, (uid_t)-1, &ot, payload,
                    sizeof(payload));
    CHECK(rc == 0 && ot == VIRP_OBS_ERROR &&
          strstr(payload, "approval_reused") != NULL,
          "an untampered second apply refuses approval_reused");
    CHECK(virp_driver_mock_exec_attempts_reset() == 0,
          "and nothing reached the device");

    /* Hash line blanked, consumed.list still naming the proposal. The old
     * guard skipped itself on the empty field, committed a second intent,
     * got REUSED back from the cache write — and logged it and executed. */
    CHECK(h1_rewrite_hash_line(fx, pid, "-"), "hash line blanked ('-')");
    ot = 0; payload[0] = '\0';
    (void)virp_driver_mock_exec_attempts_reset();
    rc = fx_run(fx, FX_DEV, "reload", pid, (uid_t)-1, &ot, payload,
                sizeof(payload));
    CHECK(rc == 0 && ot == VIRP_OBS_ERROR &&
          strstr(payload, "approval_reused") != NULL,
          "REUSED from the consumed list is a refusal, not a log line");
    CHECK(virp_driver_mock_exec_attempts_reset() == 0,
          "and nothing reached the device");
    int n = -1;
    CHECK(virp_chain_count_intents_for_proposal(&fx->st.chain, pid, &n)
              == VIRP_OK && n == 1,
          "exactly ONE gate_intent names the proposal — no second consume");
    fx_destroy(fx);
}

static void t_H1_unspent_record_must_match_chain(void)
{
    printf("\n  H1: an UNSPENT approval whose hash line does not match the chain\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "h1-first")) { CHECK(false, "fixture"); return; }
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    virp_approval_rec_t apr;
    CHECK(fx_propose(fx, "reload", pid) == 0, "proposal filed");
    CHECK(fx_approve(fx, pid, &apr) == VIRP_OK, "approval submitted");

    CHECK(h1_rewrite_hash_line(fx, pid, ""), "hash line blanked before any apply");
    uint8_t ot = 0;
    char payload[2048] = "";
    (void)virp_driver_mock_exec_attempts_reset();
    int rc = fx_run(fx, FX_DEV, "reload", pid, (uid_t)-1, &ot, payload,
                    sizeof(payload));
    CHECK(rc == 0 && ot == VIRP_OBS_ERROR,
          "an empty record hash refuses instead of skipping the guard");
    CHECK(virp_driver_mock_exec_attempts_reset() == 0,
          "nothing reached the device");
    int n = -1;
    CHECK(virp_chain_count_intents_for_proposal(&fx->st.chain, pid, &n)
              == VIRP_OK && n == 0,
          "the refusal committed no intent, so it consumed nothing");

    /* Put the true hash back: the approval was never spent and applies. */
    CHECK(h1_rewrite_hash_line(fx, pid, apr.chain_entry_hash),
          "true hash line restored");
    ot = 0;
    (void)virp_driver_mock_exec_attempts_reset();
    rc = fx_run(fx, FX_DEV, "reload", pid, (uid_t)-1, &ot, payload,
                sizeof(payload));
    CHECK(rc == 0 && virp_driver_mock_exec_attempts_reset() == 1,
          "the intact approval still applies exactly once");
    fx_destroy(fx);
}

/* =========================================================================
 * H2 — fed_outcome "executed" must be unambiguous
 *
 * An error-backed outcome may not claim execution. Each body below cites
 * error_sha256 and smuggles an execution claim past a reader that takes
 * the first "executed" member, or that only recognises the literal true.
 * ========================================================================= */

#define H2_HASH "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

static void t_H2_executed_must_be_single_boolean(void)
{
    printf("\n  H2: fed_outcome 'executed' is at most once and a JSON boolean\n");
    static const struct { const char *body; const char *what; } REFUSED[] = {
        { "{\"error_sha256\":\"" H2_HASH "\",\"executed\":false,"
          "\"executed\":true}",
          "duplicate executed (false then true) is refused" },
        { "{\"executed\":true,\"error_sha256\":\"" H2_HASH "\","
          "\"executed\":false}",
          "duplicate executed (true then false) is refused" },
        { "{\"error_sha256\":\"" H2_HASH "\",\"executed\":1}",
          "executed:1 is refused" },
        { "{\"error_sha256\":\"" H2_HASH "\",\"executed\":\"true\"}",
          "executed:\"true\" is refused" },
        { "{\"error_sha256\":\"" H2_HASH "\",\"executed\":null}",
          "executed:null is refused" },
        { "{\"observation_sha256\":\"" H2_HASH "\",\"executed\":\"yes\"}",
          "a mistyped executed is refused on an observation-backed outcome too" },
    };
    for (size_t i = 0; i < sizeof(REFUSED) / sizeof(REFUSED[0]); i++) {
        char cited[65] = "";
        bool claims = true;
        fed_cite_kind_t k = fed_outcome_citation(REFUSED[i].body, cited,
                                                 &claims);
        CHECK(k == FED_CITE_NONE && !claims, REFUSED[i].what);
    }

    /* The well-formed shapes are untouched. */
    char cited[65];
    bool claims = true;
    CHECK(fed_outcome_citation("{\"error_sha256\":\"" H2_HASH "\","
                               "\"executed\":false}", cited, &claims)
              == FED_CITE_ERROR && !claims && strcmp(cited, H2_HASH) == 0,
          "error-backed, executed:false is still an error citation");
    claims = true;
    CHECK(fed_outcome_citation("{\"error_sha256\":\"" H2_HASH "\"}",
                               cited, &claims) == FED_CITE_ERROR && !claims,
          "error-backed with no executed member claims nothing");
    claims = false;
    CHECK(fed_outcome_citation("{\"error_sha256\":\"" H2_HASH "\","
                               "\"executed\":true}", cited, &claims)
              == FED_CITE_ERROR && claims,
          "a single boolean true is still reported as a claim (GATE 4 refuses it)");
    claims = false;
    CHECK(fed_outcome_citation("{\"observation_sha256\":\"" H2_HASH "\","
                               "\"executed\":true,"
                               "\"detail\":{\"executed\":\"nested\"}}",
                               cited, &claims)
              == FED_CITE_OBSERVATION && claims,
          "a nested executed is not the root claim and does not count");
}

/* =========================================================================
 * H3 — tier consistency
 *
 * The route-table default (unmapped -> RED) is pinned across all five CLI
 * drivers by tests/test_driver_route_defaults.c, which needs the driver
 * objects. What can be pinned here, without them, is the ceiling
 * contract the corrected comments now state: a per-uid row is GREEN,
 * YELLOW or RED, decides in both directions, and a refused update leaves
 * the table exactly as it was.
 * ========================================================================= */

static void t_H3_uid_ceiling_contract(void)
{
    printf("\n  H3: per-uid ceilings — authoritative, never BLACK, atomic update\n");
    static onode_state_t st;
    CHECK(onode_init(&st, 1, NULL, "/tmp/virp-review-unused.sock") == VIRP_OK,
          "state initialised");
    st.gate_max_tier = VIRP_TIER_YELLOW;

    const uid_t uids[2] = { 4101, 4102 };
    const virp_trust_tier_t ok[2] = { VIRP_TIER_GREEN, VIRP_TIER_RED };
    CHECK(onode_set_uid_ceilings(&st, uids, ok, 2) == VIRP_OK,
          "GREEN and RED rows install");
    CHECK(onode_effective_max_tier(&st, 4101) == VIRP_TIER_GREEN &&
          strcmp(onode_ceiling_source(&st, 4101), "per-uid") == 0,
          "a TIGHTER row decides, and is recorded as per-uid");
    CHECK(onode_effective_max_tier(&st, 4102) == VIRP_TIER_RED &&
          strcmp(onode_ceiling_source(&st, 4102), "per-uid") == 0,
          "a LOOSER row decides too, and is recorded as per-uid");
    CHECK(onode_effective_max_tier(&st, 4199) == VIRP_TIER_YELLOW &&
          strcmp(onode_ceiling_source(&st, 4199), "node-wide") == 0,
          "a uid with no row gets the node-wide ceiling");
    CHECK(onode_effective_max_tier(&st, (uid_t)-1) == VIRP_TIER_YELLOW,
          "the internal caller gets the node-wide ceiling");

    /* A refused update must not have moved anything: row 0 is valid and
     * LOOSER than what is installed, row 1 is the retired BLACK. */
    const virp_trust_tier_t bad[2] = { VIRP_TIER_RED, VIRP_TIER_BLACK };
    CHECK(onode_set_uid_ceilings(&st, uids, bad, 2) == VIRP_ERR_INVALID_TYPE,
          "a BLACK ceiling is rejected");
    CHECK(onode_effective_max_tier(&st, 4101) == VIRP_TIER_GREEN,
          "and the rejected call did not loosen the row before it");
    const virp_trust_tier_t unc[1] = { VIRP_TIER_UNCLASSIFIED };
    CHECK(onode_set_uid_ceilings(&st, uids, unc, 1) == VIRP_ERR_INVALID_TYPE,
          "an UNCLASSIFIED ceiling is rejected");
    CHECK(st.uid_ceiling_count == 2 &&
          onode_effective_max_tier(&st, 4102) == VIRP_TIER_RED,
          "the installed table is unchanged");

    /* BLACK is outside the order: no ceiling admits it. */
    CHECK(gate_tier_blocks(VIRP_TIER_BLACK, VIRP_TIER_RED) &&
          gate_tier_blocks(VIRP_TIER_UNCLASSIFIED, VIRP_TIER_RED),
          "BLACK and UNCLASSIFIED block under the highest ceiling");
    CHECK(!gate_tier_blocks(VIRP_TIER_YELLOW, VIRP_TIER_YELLOW) &&
          gate_tier_blocks(VIRP_TIER_YELLOW, VIRP_TIER_GREEN) &&
          gate_tier_blocks(VIRP_TIER_RED, VIRP_TIER_YELLOW),
          "YELLOW runs unapproved at a YELLOW ceiling, needs approval under GREEN; RED needs it under YELLOW");
    onode_destroy(&st);
}

/* =========================================================================
 * Runner
 * ========================================================================= */

static const struct { const char *name; void (*fn)(void); } TESTS[] = {
    { "t_H1_blanked_hash_replay",             t_H1_blanked_hash_replay },
    { "t_H1_altered_hash_replay",             t_H1_altered_hash_replay },
    { "t_H1_second_apply_inside_ttl",         t_H1_second_apply_inside_ttl },
    { "t_H1_unspent_record_must_match_chain", t_H1_unspent_record_must_match_chain },
    { "t_H2_executed_must_be_single_boolean", t_H2_executed_must_be_single_boolean },
    { "t_H3_uid_ceiling_contract",            t_H3_uid_ceiling_contract },
};

static void rm_rf_root(void)
{
    if (!g_root[0]) return;
    pid_t pid = fork();
    if (pid == 0) {
        execlp("rm", "rm", "-rf", "--", g_root, (char *)NULL);
        _exit(127);
    }
    if (pid > 0) { int st; (void)waitpid(pid, &st, 0); }
}

int main(int argc, char **argv)
{
    /* The approver registry loader refuses a group- or world-writable
     * file, so the fixtures must not inherit a permissive umask. */
    umask(077);
    snprintf(g_root, sizeof(g_root), "/tmp/virp-onode-review-XXXXXX");
    if (!mkdtemp(g_root)) { perror("mkdtemp"); return 1; }
    atexit(rm_rf_root);
    virp_driver_mock_init();

    printf("\n=== VIRP O-Node security review regressions ===\n");
    int ran = 0;
    for (size_t i = 0; i < sizeof(TESTS) / sizeof(TESTS[0]); i++) {
        bool want = (argc < 2);
        for (int a = 1; a < argc && !want; a++)
            want = strcmp(argv[a], TESTS[i].name) == 0;
        if (!want) continue;
        TESTS[i].fn();
        ran++;
    }
    if (ran == 0) {
        printf("no test matched\n");
        return 1;
    }
    if (failures == 0) {
        printf("\n=== Results: %d review regression(s) ran, all passed ===\n\n", ran);
        return 0;
    }
    printf("\n=== Results: %d check(s) FAILED ===\n\n", failures);
    return 1;
}
