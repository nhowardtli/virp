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
 * H4 — owner-policy mode still consults the driver's classifier
 *
 * A second driver, registered for the PROXMOX vendor (not compiled into
 * this build), whose classifier is a small switchable table and whose
 * execute() has NO backstop of its own — so if the gate admits something
 * it should not, the dispatch counter says so directly instead of a
 * driver belt masking it. The owner policy's closed grammar recognises
 * `uptime`, `hostname` and `uname -sr` as system.read (GREEN) and
 * `reboot` as host.reboot (RED) for this vendor.
 * ========================================================================= */

struct virp_conn { int unused; };

static int  h4_dispatches;
static bool h4_uname_is_black;       /* a table change between propose and approve */

static virp_conn_t *h4_connect(const virp_device_t *d)
{ (void)d; return calloc(1, sizeof(virp_conn_t)); }
static void h4_disconnect(virp_conn_t *c) { free(c); }
static virp_error_t h4_health(virp_conn_t *c) { (void)c; return VIRP_OK; }

static virp_trust_tier_t h4_classify(const char *cmd)
{
    if (!strcmp(cmd, "uptime"))   return VIRP_TIER_GREEN;
    if (!strcmp(cmd, "hostname")) return VIRP_TIER_BLACK;   /* policy: GREEN */
    if (!strcmp(cmd, "uname -sr"))
        return h4_uname_is_black ? VIRP_TIER_BLACK : VIRP_TIER_RED;
    if (!strcmp(cmd, "reboot"))   return VIRP_TIER_BLACK;   /* typed reboot */
    return VIRP_TIER_UNCLASSIFIED;
}

static virp_error_t h4_execute(virp_conn_t *c, const char *cmd,
                               virp_exec_result_t *r)
{
    (void)c; (void)cmd;
    h4_dispatches++;
    memset(r, 0, sizeof(*r));
    strcpy(r->output, "h4 fixture output");
    r->output_len = strlen(r->output);
    r->success = true;
    r->exit_code_trusted = true;
    r->disposition = VIRP_DISPOSITION_EXECUTED_CONFIRMED;
    return VIRP_OK;
}

#define H4_DEV    "L-POL"
#define H4_DEV_ID 0x21ULL

static sqlite3 *h4_journal(void)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK) return NULL;
    FILE *f = fopen("deploy/policy-schema.sql", "r");
    if (!f) { sqlite3_close(db); return NULL; }
    char schema[8192];
    size_t n = fread(schema, 1, sizeof(schema) - 1, f);
    fclose(f);
    schema[n] = '\0';
    if (sqlite3_exec(db, schema, NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return NULL;
    }
    return db;
}

static virp_policy_t *h4_policy(sqlite3 *db, const char *profile)
{
    char text[2048];
    snprintf(text, sizeof(text),
        "{\"version\":1,\"max_calls\":100,\"max_disruptive\":10,"
        "\"max_inflight\":1,\"protected\":[],"
        "\"principals\":[{\"uid\":%u,\"profile\":\"%s\","
        "\"expires\":4102444800,\"rules\":["
        "{\"device_id\":\"%016llx\",\"host\":\"127.0.0.1\",\"port\":22,"
        "\"vendor\":%d,\"operation\":\"host.reboot\",\"resource\":\"host\"},"
        "{\"device_id\":\"%016llx\",\"host\":\"127.0.0.1\",\"port\":22,"
        "\"vendor\":%d,\"operation\":\"system.read\",\"resource\":\"host\"}]}]}",
        (unsigned)getuid(), profile,
        (unsigned long long)H4_DEV_ID, (int)VIRP_VENDOR_PROXMOX,
        (unsigned long long)H4_DEV_ID, (int)VIRP_VENDOR_PROXMOX);
    return virp_policy_parse(text, db);
}

/* fx + the policy fixture device + an owner policy at `profile`. */
static bool h4_init(fx_t *fx, const char *name, sqlite3 **db,
                    const char *profile)
{
    static bool registered;
    if (!registered) {
        static const virp_driver_t drv = {
            .name = "review-h4", .vendor = VIRP_VENDOR_PROXMOX,
            .connect = h4_connect, .disconnect = h4_disconnect,
            .execute = h4_execute, .health_check = h4_health,
            .route_command = h4_classify,
        };
        /* Fails only if a real driver already owns the vendor, i.e. this
         * suite was built with LINUX=1 — it is a plain-build suite. */
        if (virp_driver_register(&drv) != VIRP_OK) return false;
        registered = true;
    }
    if (!fx_init(fx, name)) return false;
    virp_device_t d;
    memset(&d, 0, sizeof(d));
    snprintf(d.hostname, sizeof(d.hostname), "%s", H4_DEV);
    snprintf(d.host, sizeof(d.host), "127.0.0.1");
    d.port = 22; d.vendor = VIRP_VENDOR_PROXMOX;
    d.node_id = 0x21212121; d.device_id = H4_DEV_ID; d.enabled = true;
    if (onode_add_device(&fx->st, &d) != VIRP_OK) return false;
    *db = h4_journal();
    if (!*db) return false;
    fx->st.policy = h4_policy(*db, profile);
    h4_dispatches = 0;
    h4_uname_is_black = false;
    return fx->st.policy != NULL;
}

static void h4_set_profile(fx_t *fx, sqlite3 *db, const char *profile)
{
    virp_policy_close(fx->st.policy);
    fx->st.policy = h4_policy(db, profile);
}

static void t_H4_policy_mode_consults_driver(void)
{
    printf("\n  H4: policy mode gates at the stricter of policy and driver\n");
    fx_t *fx = &g_fx;
    sqlite3 *db = NULL;
    if (!h4_init(fx, "h4-gate", &db, "autonomous")) {
        CHECK(false, "fixture (needs a plain build, without LINUX=1)");
        return;
    }
    uid_t me = getuid();
    uint8_t ot = 0;
    char payload[2048] = "";

    CHECK(fx_run(fx, H4_DEV, "uptime", NULL, me, &ot, payload,
                 sizeof(payload)) == 0 &&
          ot == VIRP_OBS_DEVICE_OUTPUT && h4_dispatches == 1,
          "policy GREEN + driver GREEN executes");

    /* The policy grammar calls `hostname` a read. The driver calls it
     * BLACK. It is not the typed reboot, so BLACK stands. */
    ot = 0;
    CHECK(fx_run(fx, H4_DEV, "hostname", NULL, me, &ot, payload,
                 sizeof(payload)) == 0 && ot == VIRP_OBS_ERROR,
          "a policy-permitted command the driver calls BLACK is REFUSED");
    CHECK(h4_dispatches == 1, "and never dispatched");
    CHECK(strstr(payload, "tier=BLACK") != NULL &&
          strstr(payload, "proposal_id=") == NULL,
          "refused AS BLACK: no proposal, no escalation path");

    /* The one BLACK the policy can express. */
    ot = 0;
    CHECK(fx_run(fx, H4_DEV, "reboot", NULL, me, &ot, payload,
                 sizeof(payload)) == 0 &&
          ot == VIRP_OBS_DEVICE_OUTPUT && h4_dispatches == 2,
          "driver-BLACK reboot still runs as the policy's typed reboot");

    /* Policy says read (GREEN); driver says RED. Under an observe
     * profile the ceiling is GREEN, so the stricter tier must block. */
    h4_set_profile(fx, db, "observe");
    ot = 0;
    CHECK(fx_run(fx, H4_DEV, "uname -sr", NULL, me, &ot, payload,
                 sizeof(payload)) == 0 && ot == VIRP_OBS_ERROR &&
          strstr(payload, "tier=RED max=GREEN") != NULL,
          "driver RED over policy GREEN is gated as RED and blocked");
    CHECK(h4_dispatches == 2, "and never dispatched");

    /* A driver with no opinion is not a driver that agrees. */
    h4_set_profile(fx, db, "autonomous");
    ot = 0;
    CHECK(fx_run(fx, H4_DEV, "systemctl reboot", NULL, me, &ot, payload,
                 sizeof(payload)) == 0 && ot == VIRP_OBS_ERROR &&
          h4_dispatches == 2,
          "a driver-UNCLASSIFIED command is blocked under policy mode");

    fx_destroy(fx);
    sqlite3_close(db);
}

static void t_H4_challenge_consults_driver(void)
{
    printf("\n  H4: approval challenge reflects the driver's table under policy\n");
    fx_t *fx = &g_fx;
    sqlite3 *db = NULL;
    if (!h4_init(fx, "h4-chal", &db, "observe")) {
        CHECK(false, "fixture (needs a plain build, without LINUX=1)");
        return;
    }
    uid_t me = getuid();
    uint8_t ot = 0;
    char payload[2048] = "";
    uint8_t out[VIRP_MAX_MESSAGE_SIZE];
    size_t out_len = 0;

    /* RED now -> blocked under the GREEN ceiling -> a proposal is filed. */
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    CHECK(fx_run(fx, H4_DEV, "uname -sr", NULL, me, &ot, payload,
                 sizeof(payload)) == 0 && ot == VIRP_OBS_ERROR &&
          fx_extract_pid(payload, pid) == 0,
          "a RED-by-driver command files a proposal");
    CHECK(onode_approval_challenge(&fx->st, pid, out, sizeof(out), &out_len)
              == VIRP_OK,
          "while the driver calls it RED the proposal is challengeable");

    /* The driver's table changes before the human signs. */
    h4_uname_is_black = true;
    CHECK(onode_approval_challenge(&fx->st, pid, out, sizeof(out), &out_len)
              == VIRP_ERR_TIER_VIOLATION,
          "once the driver calls it BLACK the challenge is refused");
    h4_uname_is_black = false;

    fx_destroy(fx);
    sqlite3_close(db);
}

/* =========================================================================
 * M1 — the request the daemon parses is the request that was sent
 *
 * Driven through onode_parse_request_fuzz(), the exported (bytes, length)
 * entry the socket path's parser sits behind, and through the batch
 * parser with an explicit length.
 * ========================================================================= */

static bool m1_parse(const char *bytes, size_t n)
{
    return onode_parse_request_fuzz((const uint8_t *)bytes, n);
}
#define M1_STR(s) (s), strlen(s)
/* For literals with an embedded NUL, where strlen would stop early. */
#define M1_LIT(s) (s), (sizeof(s) - 1)

static void t_M1_whole_buffer_exact_length_no_duplicate_keys(void)
{
    printf("\n  M1: whole buffer, exact length, no duplicate root keys\n");

    CHECK(m1_parse(M1_STR("{\"action\":\"heartbeat\"}")),
          "a plain request parses");
    CHECK(m1_parse(M1_STR("{\"action\":\"heartbeat\"} \n\t ")),
          "trailing whitespace is still fine");

    CHECK(!m1_parse(M1_STR("{\"action\":\"heartbeat\"}"
                           "{\"action\":\"shutdown\"}")),
          "a second object after the first is refused");
    CHECK(!m1_parse(M1_STR("{\"action\":\"heartbeat\"} x")),
          "trailing garbage is refused");
    CHECK(!m1_parse(M1_STR("{\"action\":\"heartbeat\"},")),
          "a trailing comma is refused");

    CHECK(!m1_parse(M1_LIT("{\"action\":\"heartbeat\"}\0"
                           "{\"action\":\"shutdown\"}")),
          "a raw NUL inside the declared length is refused");
    CHECK(!m1_parse(M1_LIT("{\"action\":\"heartbeat\"}\0")),
          "a payload one NUL longer than its text is refused");

    CHECK(!m1_parse(M1_STR("{\"action\":\"heartbeat\","
                           "\"action\":\"shutdown\"}")),
          "a duplicate action key is refused");
    CHECK(!m1_parse(M1_STR("{\"action\":\"execute\",\"device\":\"R1\","
                           "\"command\":\"show version\","
                           "\"command\":\"reload\"}")),
          "a duplicate command key is refused");
    CHECK(!m1_parse(M1_STR("{\"action\":\"execute\",\"device\":\"R1\","
                           "\"command\":\"show version\","
                           "\"note\":1,\"note\":2}")),
          "a duplicate of a key the daemon does not even read is refused");
    CHECK(m1_parse(M1_STR("{\"action\":\"execute\",\"device\":\"R1\","
                          "\"command\":\"show version\","
                          "\"meta\":{\"a\":1,\"a\":2}}")),
          "only ROOT keys are policed here (nested objects are not ours to read)");

    /* More root members than the wire vocabulary could ever need. */
    char many[4096];
    size_t off = (size_t)snprintf(many, sizeof(many), "{\"action\":\"heartbeat\"");
    for (int i = 0; i < ONODE_MAX_ROOT_KEYS; i++)
        off += (size_t)snprintf(many + off, sizeof(many) - off,
                                ",\"k%d\":%d", i, i);
    snprintf(many + off, sizeof(many) - off, "}");
    CHECK(!m1_parse(M1_STR(many)),
          "a root object with more members than the cap is refused");

    /* The batch parser is a second, independent parse of the same frame. */
    static batch_thread_arg_t args[ONODE_MAX_BATCH];
    const char *ok = "{\"action\":\"batch_execute\",\"commands\":"
                     "[{\"device\":\"R1\",\"command\":\"show version\"}]}";
    CHECK(parse_batch_commands(ok, strlen(ok), args, ONODE_MAX_BATCH) == 1,
          "a plain batch parses");
    const char *trail = "{\"commands\":[{\"device\":\"R1\","
                        "\"command\":\"show version\"}]}"
                        "{\"commands\":[]}";
    CHECK(parse_batch_commands(trail, strlen(trail), args, ONODE_MAX_BATCH) == 0,
          "batch: a second object after the first is refused");
    const char *dupc = "{\"commands\":[{\"device\":\"R1\","
                       "\"command\":\"show version\"}],"
                       "\"commands\":[{\"device\":\"R1\","
                       "\"command\":\"reload\"}]}";
    CHECK(parse_batch_commands(dupc, strlen(dupc), args, ONODE_MAX_BATCH) == 0,
          "batch: a duplicate commands key is refused");
    const char *dupi = "{\"commands\":[{\"device\":\"R1\","
                       "\"command\":\"show version\","
                       "\"command\":\"reload\"}]}";
    CHECK(parse_batch_commands(dupi, strlen(dupi), args, ONODE_MAX_BATCH) == 0,
          "batch: a duplicate key inside an item is refused");
    static const char nul[] = "{\"commands\":[{\"device\":\"R1\","
                              "\"command\":\"show version\"}]}\0"
                              "{\"commands\":[]}";
    CHECK(parse_batch_commands(nul, sizeof(nul) - 1, args, ONODE_MAX_BATCH) == 0,
          "batch: a raw NUL inside the declared length is refused");
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
    { "t_H4_policy_mode_consults_driver",     t_H4_policy_mode_consults_driver },
    { "t_H4_challenge_consults_driver",       t_H4_challenge_consults_driver },
    { "t_M1_whole_buffer_exact_length_no_duplicate_keys",
                                              t_M1_whole_buffer_exact_length_no_duplicate_keys },
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
