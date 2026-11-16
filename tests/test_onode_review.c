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
 * Socket harness: drive handle_client() itself over a socketpair.
 *
 * The request is written first and handle_client() is then called on the
 * other end, on this thread: it reads one frame, answers, and closes. No
 * listener, no worker thread, no SO_PEERCRED — the peer uid is the
 * argument the accept loop would have threaded in. Returns the response
 * payload length, or -1 if the daemon closed without answering. A 4-byte
 * payload is a framed virp_error_t; fx_resp_err() decodes it.
 * ========================================================================= */

static ssize_t fx_request_raw(onode_state_t *st, uid_t uid,
                              const void *payload, size_t plen,
                              uint8_t *resp, size_t resp_cap)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;
    uint32_t n = htonl((uint32_t)plen + 1);
    uint8_t ver = VIRP_FRAME_VERSION;
    if (send(sv[0], &n, 4, 0) != 4 || send(sv[0], &ver, 1, 0) != 1 ||
        (plen && send(sv[0], payload, plen, 0) != (ssize_t)plen)) {
        close(sv[0]); close(sv[1]);
        return -1;
    }
    handle_client(st, sv[1], uid);          /* closes sv[1] */

    uint32_t rn = 0;
    ssize_t got = recv(sv[0], &rn, 4, MSG_WAITALL);
    if (got != 4) { close(sv[0]); return -1; }
    rn = ntohl(rn);
    if (rn > resp_cap) { close(sv[0]); return -1; }
    if (rn && recv(sv[0], resp, rn, MSG_WAITALL) != (ssize_t)rn) {
        close(sv[0]);
        return -1;
    }
    close(sv[0]);
    return (ssize_t)rn;
}

static ssize_t fx_request(onode_state_t *st, uid_t uid, const char *json,
                          uint8_t *resp, size_t resp_cap)
{
    return fx_request_raw(st, uid, json, strlen(json), resp, resp_cap);
}

/* The framed error a response carries, or VIRP_OK if it is not one. */
static virp_error_t fx_resp_err(const uint8_t *resp, ssize_t n)
{
    if (n != 4) return VIRP_OK;
    uint32_t v;
    memcpy(&v, resp, 4);
    return (virp_error_t)(int32_t)ntohl(v);
}

/* One request, one answer: the error it was refused with (VIRP_OK if it
 * was answered with something else). */
static virp_error_t fx_ask(onode_state_t *st, uid_t uid, const char *json)
{
    static uint8_t resp[VIRP_MAX_MESSAGE_SIZE + 64];
    ssize_t n = fx_request(st, uid, json, resp, sizeof(resp));
    if (n < 0) return VIRP_ERR_NULL_PTR;
    return fx_resp_err(resp, n);
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
 * M2 — a supplied field that cannot be used refuses the request
 * ========================================================================= */

/* {"action":"heartbeat","<key>":"<n x's>"} */
static bool m2_with_len(const char *key, size_t n)
{
    static char buf[8192];
    int off = snprintf(buf, sizeof(buf), "{\"action\":\"heartbeat\",\"%s\":\"",
                       key);
    memset(buf + off, 'x', n);
    snprintf(buf + off + n, sizeof(buf) - (size_t)off - n, "\"}");
    return m1_parse(buf, strlen(buf));
}

static void t_M2_overlength_optional_field_rejects_request(void)
{
    printf("\n  M2: present-but-over-length optional fields reject the request\n");
    /* Receiver widths from onode_request_t, including the NUL. */
    static const struct { const char *key; size_t width; } F[] = {
        { "device", 64 },          { "command", 1024 },
        { "intent_id", 128 },      { "confidence", 16 },
        { "intent_json", 4096 },   { "proposed_actions", 2048 },
        { "constraints", 512 },    { "client_id", 64 },
        { "client_nonce", 17 },    { "server_nonce", 17 },
        { "versions", 32 },        { "algorithms", 32 },
        { "intent_hash", 65 },
    };
    for (size_t i = 0; i < sizeof(F) / sizeof(F[0]); i++) {
        char msg[128];
        snprintf(msg, sizeof(msg), "%s: longest fitting value accepted, "
                 "one byte more REJECTS the request", F[i].key);
        CHECK(m2_with_len(F[i].key, F[i].width - 1) &&
              !m2_with_len(F[i].key, F[i].width), msg);
    }
    CHECK(!m1_parse(M1_STR("{\"action\":\"heartbeat\",\"device\":7}")),
          "a non-string device rejects the request");
    CHECK(!m1_parse(M1_STR("{\"action\":\"heartbeat\","
                           "\"constraints\":{\"max\":1}}")),
          "an object where a string belongs rejects the request");
    CHECK(m1_parse(M1_STR("{\"action\":\"heartbeat\",\"device\":null}")),
          "JSON null is 'not supplied' and is accepted");
}

static void t_M2_handshake_hex_exact_length(void)
{
    printf("\n  M2: handshake hex fields decode to their exact length or refuse\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m2-hs")) { CHECK(false, "fixture"); return; }
    onode_state_t *st = &fx->st;
    uid_t me = getuid();
#define M2_HELLO(extra) "{\"action\":\"session_hello\",\"client_id\":\"rev\"" extra "}"

    CHECK(fx_ask(st, me, M2_HELLO(",\"client_nonce\":\"0011223344556677\""))
              == VIRP_OK, "a 16-hex client_nonce is accepted");
    CHECK(fx_ask(st, me, M2_HELLO(",\"client_nonce\":\"zz11223344556677\""))
              == VIRP_ERR_INVALID_LENGTH, "a non-hex client_nonce is refused");
    CHECK(fx_ask(st, me, M2_HELLO(",\"client_nonce\":\"00112233445566\""))
              == VIRP_ERR_INVALID_LENGTH, "a short client_nonce is refused");
    CHECK(fx_ask(st, me, M2_HELLO(",\"client_nonce\":\"001122334455667\""))
              == VIRP_ERR_INVALID_LENGTH, "an odd-length client_nonce is refused");
    CHECK(fx_ask(st, me, M2_HELLO(",\"versions\":\"2,x\""))
              == VIRP_ERR_INVALID_LENGTH, "a non-numeric version token is refused");
    CHECK(fx_ask(st, me, M2_HELLO(",\"versions\":\"258\""))
              == VIRP_ERR_INVALID_LENGTH,
          "version 258 is refused, not wrapped to 2");
    CHECK(fx_ask(st, me, M2_HELLO(",\"versions\":\"1,2,3,4,5,6,7,8,9\""))
              == VIRP_ERR_INVALID_LENGTH,
          "more versions than the handshake holds is refused, not trimmed");
    CHECK(fx_ask(st, me, M2_HELLO(",\"algorithms\":\"1,,2\""))
              == VIRP_ERR_INVALID_LENGTH, "an empty algorithm token is refused");
    CHECK(fx_ask(st, me, M2_HELLO(",\"versions\":\"2,1\",\"algorithms\":\"1\""))
              == VIRP_OK, "well-formed lists still negotiate");

    /* BIND: all three hex fields required, each at its exact length. */
    CHECK(fx_ask(st, me, "{\"action\":\"session_bind\",\"client_id\":\"rev\","
                 "\"session_id\":\"abcd\","
                 "\"client_nonce\":\"0011223344556677\","
                 "\"server_nonce\":\"0011223344556677\"}")
              == VIRP_ERR_INVALID_LENGTH, "bind: a short session_id is refused");
    CHECK(fx_ask(st, me, "{\"action\":\"session_bind\",\"client_id\":\"rev\","
                 "\"session_id\":\"00112233445566778899aabbccddeeff\","
                 "\"client_nonce\":\"0011223344556677\"}")
              == VIRP_ERR_INVALID_LENGTH, "bind: a missing server_nonce is refused");
    CHECK(fx_ask(st, me, "{\"action\":\"session_bind\",\"client_id\":\"rev\","
                 "\"session_id\":\"00112233445566778899aabbccddeegg\","
                 "\"client_nonce\":\"0011223344556677\","
                 "\"server_nonce\":\"0011223344556677\"}")
              == VIRP_ERR_INVALID_LENGTH, "bind: a non-hex session_id is refused");
#undef M2_HELLO
    fx_destroy(fx);
}

/* =========================================================================
 * M3 — the device name is validated at ingress, and an unknown one cannot
 * name a chain session
 * ========================================================================= */

static int fx_session_entries(fx_t *fx, const char *session)
{
    sqlite3_stmt *st = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(fx->st.chain.db,
            "SELECT COUNT(*) FROM chain_entries WHERE session_id = ?",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, session, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            n = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    return n;
}

static int fx_distinct_sessions(fx_t *fx, const char *like)
{
    sqlite3_stmt *st = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(fx->st.chain.db,
            "SELECT COUNT(DISTINCT session_id) FROM chain_entries "
            "WHERE session_id LIKE ?", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, like, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            n = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    return n;
}

static void t_M3_device_name_validated_at_ingress(void)
{
    printf("\n  M3: a non-canonical device name is refused at ingress\n");
    CHECK(m1_parse(M1_STR("{\"action\":\"execute\",\"device\":\"R-1 core\","
                          "\"command\":\"show version\"}")),
          "an ordinary device name parses");
    CHECK(!m1_parse(M1_STR("{\"action\":\"execute\",\"device\":\"R1\\\"x\","
                           "\"command\":\"show version\"}")),
          "a device name containing a quote is refused");
    CHECK(!m1_parse(M1_STR("{\"action\":\"execute\",\"device\":\"R1\\nx\","
                           "\"command\":\"show version\"}")),
          "a device name containing a newline is refused");
    CHECK(!m1_parse(M1_STR("{\"action\":\"execute\",\"device\":\"R1\\\\x\","
                           "\"command\":\"show version\"}")),
          "a device name containing a backslash is refused");
    CHECK(!m1_parse(M1_STR("{\"action\":\"health\",\"device\":\"\xc0\xaf\"}")),
          "a device name that is not well-formed UTF-8 is refused");

    static batch_thread_arg_t args[ONODE_MAX_BATCH];
    const char *bad = "{\"commands\":[{\"device\":\"R1\",\"command\":\"show version\"},"
                      "{\"device\":\"R2\\\"x\",\"command\":\"show version\"}]}";
    CHECK(parse_batch_commands(bad, strlen(bad), args, ONODE_MAX_BATCH) == 0,
          "batch: one non-canonical device name refuses the batch");
}

static void t_M3_unknown_device_uses_fixed_separator_session(void)
{
    printf("\n  M3: separator refusals for unknown devices share ONE fixed session\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m3-sep")) { CHECK(false, "fixture"); return; }
    uint8_t ot = 0;
    char payload[2048];

    /* A known device keeps its own session, as before. */
    CHECK(fx_run(fx, FX_DEV, "show version ; reload", NULL, (uid_t)-1, &ot,
                 payload, sizeof(payload)) == 0 && ot == VIRP_OBS_ERROR,
          "a separator-carrying command is refused");
    CHECK(fx_session_entries(fx, "gate-separator:" FX_DEV) == 1,
          "known device: recorded under gate-separator:<hostname>");

    /* Three invented devices, one of them long enough that the session
     * id built from it would not fit the 64-byte field. */
    static const char *const GHOSTS[] = {
        "ghost-one", "ghost-two",
        "a-device-name-that-is-sixty-three-characters-long-xxxxxxxxxxxxx",
    };
    for (size_t i = 0; i < 3; i++) {
        ot = 0;
        CHECK(fx_run(fx, GHOSTS[i], "show version ; reload", NULL, (uid_t)-1,
                     &ot, payload, sizeof(payload)) == 0 &&
              ot == VIRP_OBS_ERROR,
              "a separator-carrying command for an unknown device is refused");
    }
    CHECK(fx_session_entries(fx, "gate-separator:_unknown") == 3,
          "all three are recorded under the ONE fixed session");
    CHECK(fx_distinct_sessions(fx, "gate-separator:%") == 2,
          "and the caller's device names minted no session of their own");

    /* The reserved name cannot be a configured device. */
    virp_device_t d;
    memset(&d, 0, sizeof(d));
    snprintf(d.hostname, sizeof(d.hostname), "_unknown");
    snprintf(d.host, sizeof(d.host), "10.255.7.99");
    d.vendor = VIRP_VENDOR_MOCK; d.node_id = 0x5EC0D0D9; d.enabled = true;
    CHECK(onode_add_device(&fx->st, &d) != VIRP_OK,
          "a device may not take the reserved name");
    fx_destroy(fx);
}

/* =========================================================================
 * M4 — intent store / get: validated at store, well-formed when fetched
 * ========================================================================= */

/* JSON-string-escape `in` (quotes and backslashes only — enough for the
 * payloads below) so a JSON text can ride inside a request as a string. */
static void m4_esc(const char *in, char *out, size_t cap)
{
    size_t o = 0;
    for (; *in && o + 2 < cap; in++) {
        if (*in == '"' || *in == '\\') out[o++] = '\\';
        out[o++] = *in;
    }
    out[o] = '\0';
}

/* Build an intent_store request. hash == NULL means "the true sha256". */
static const char *m4_store(const char *id, const char *intent_json,
                            const char *hash, const char *confidence,
                            const char *actions, const char *constraints)
{
    static char req[8192];
    char h[65], ej[2048], ea[1024], ec[1024], ei[256], ef[64];
    gate_sha256_hex(intent_json, strlen(intent_json), h);
    m4_esc(intent_json, ej, sizeof(ej));
    m4_esc(actions ? actions : "", ea, sizeof(ea));
    m4_esc(constraints ? constraints : "", ec, sizeof(ec));
    m4_esc(id, ei, sizeof(ei));
    m4_esc(confidence, ef, sizeof(ef));
    int off = snprintf(req, sizeof(req),
        "{\"action\":\"intent_store\",\"intent_id\":\"%s\","
        "\"intent_hash\":\"%s\",\"intent_json\":\"%s\","
        "\"confidence\":\"%s\",\"max_commands\":3",
        ei, hash ? hash : h, ej, ef);
    if (actions)
        off += snprintf(req + off, sizeof(req) - (size_t)off,
                        ",\"proposed_actions\":\"%s\"", ea);
    if (constraints)
        off += snprintf(req + off, sizeof(req) - (size_t)off,
                        ",\"constraints\":\"%s\"", ec);
    snprintf(req + off, sizeof(req) - (size_t)off, "}");
    return req;
}

/* Send a request and return the JSON payload of the signed observation
 * that answers it, parsed — or NULL if it was refused / not JSON. */
static cJSON *fx_ask_json(fx_t *fx, uid_t uid, const char *json,
                          uint8_t want_obs_type, int *dup_keys)
{
    static uint8_t resp[VIRP_MAX_MESSAGE_SIZE + 64];
    ssize_t n = fx_request(&fx->st, uid, json, resp, sizeof(resp));
    if (n <= 4) return NULL;
    virp_header_t hdr;
    if (virp_validate_message(resp, (size_t)n, &fx->st.okey, &hdr) != VIRP_OK)
        return NULL;
    virp_observation_t obs;
    const uint8_t *data;
    uint16_t dl;
    if (virp_parse_observation(resp + VIRP_HEADER_SIZE,
                               (size_t)n - VIRP_HEADER_SIZE, &obs, &data, &dl)
            != VIRP_OK || obs.obs_type != want_obs_type)
        return NULL;
    static char text[VIRP_MAX_MESSAGE_SIZE];
    memcpy(text, data, dl);
    text[dl] = '\0';
    cJSON *o = cJSON_ParseWithLengthOpts(text, (size_t)dl + 1, NULL, 1);
    if (o && dup_keys)
        *dup_keys = json_object_has_duplicate_keys(o, 1024) ? 1 : 0;
    return o;
}

static void t_M4_intent_store_validates_and_get_is_wellformed(void)
{
    printf("\n  M4: intent_store validates its fields; intent_get returns well-formed JSON\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m4-intent")) { CHECK(false, "fixture"); return; }
    onode_state_t *st = &fx->st;
    uid_t me = getuid();
    const char *IJ = "{\"goal\":\"audit\",\"n\":1}";

    /* The well-formed case, with whitespace the daemon should normalize. */
    int dups = -1;
    cJSON *stored = fx_ask_json(fx, me,
        m4_store("intent-ok", IJ, NULL, "high", "[ \"show version\" , 2 ]",
                 "{ \"max\" : 1 }"),
        VIRP_OBS_INTENT_STORED, &dups);
    CHECK(stored != NULL && dups == 0 &&
          cJSON_IsString(cJSON_GetObjectItemCaseSensitive(stored, "signature_hmac")),
          "a well-formed intent is stored and acknowledged");
    if (stored) cJSON_Delete(stored);

    cJSON *got = fx_ask_json(fx, me,
        "{\"action\":\"intent_get\",\"intent_id\":\"intent-ok\"}",
        VIRP_OBS_INTENT_FETCHED, &dups);
    CHECK(got != NULL && dups == 0, "intent_get returns one well-formed object");
    if (got) {
        const cJSON *c = cJSON_GetObjectItemCaseSensitive(got, "constraints");
        const cJSON *a = cJSON_GetObjectItemCaseSensitive(got, "proposed_actions");
        const cJSON *j = cJSON_GetObjectItemCaseSensitive(got, "intent_json");
        const cJSON *t = cJSON_GetObjectItemCaseSensitive(got, "created_at_ns");
        CHECK(cJSON_IsObject(c) && cJSON_IsArray(a) && cJSON_IsObject(j) &&
              cJSON_GetArraySize(a) == 2,
              "the three bodies come back as parsed JSON values");
        CHECK(cJSON_IsNumber(t) && t->valuedouble > 1e18,
              "timestamps are still JSON numbers (wire shape unchanged)");
        cJSON_Delete(got);
    }
    /* What is kept for the two normalized fields is the parse. */
    virp_intent_entry_t ie;
    CHECK(virp_chain_intent_get(&st->chain, "intent-ok", &ie) == VIRP_OK &&
          strcmp(ie.proposed_actions, "[\"show version\",2]") == 0 &&
          strcmp(ie.constraints, "{\"max\":1}") == 0 &&
          strcmp(ie.intent_json, IJ) == 0,
          "proposed_actions/constraints stored re-serialized; intent_json byte-for-byte");

    /* Injection through a body that is not JSON. */
    CHECK(fx_ask(st, me, m4_store("inj-constraints", IJ, NULL, "high", NULL,
              "{},\"signature_hmac\":\"" H2_HASH "\""))
              == VIRP_ERR_INVALID_TYPE,
          "constraints that would inject a second signature_hmac are refused");
    CHECK(fx_ask(st, me, m4_store("inj-actions", IJ, NULL, "high",
              "[],\"max_commands\":999", NULL)) == VIRP_ERR_INVALID_TYPE,
          "proposed_actions that would inject a member are refused");
    CHECK(fx_ask(st, me, m4_store("shape-actions", IJ, NULL, "high",
              "{\"not\":\"an array\"}", NULL)) == VIRP_ERR_INVALID_TYPE,
          "proposed_actions must be a JSON array");
    CHECK(fx_ask(st, me, m4_store("shape-constraints", IJ, NULL, "high", NULL,
              "[1]")) == VIRP_ERR_INVALID_TYPE,
          "constraints must be a JSON object");
    CHECK(fx_ask(st, me, m4_store("not-json", "definitely not json", NULL,
              "high", NULL, NULL)) == VIRP_ERR_INVALID_TYPE,
          "intent_json that is not JSON is refused");

    /* Injection through the quoted fields. */
    CHECK(fx_ask(st, me, m4_store("inj-conf", IJ, NULL, "a\",\"b\":\"c",
              NULL, NULL)) == VIRP_ERR_INVALID_LENGTH,
          "a confidence containing a quote is refused");
    CHECK(fx_ask(st, me, m4_store("id\",\"x\":\"y", IJ, NULL, "high",
              NULL, NULL)) == VIRP_ERR_INVALID_LENGTH,
          "an intent_id containing a quote is refused");

    /* intent_hash must commit to intent_json. */
    CHECK(fx_ask(st, me, m4_store("bad-hash", IJ, H2_HASH, "high", NULL, NULL))
              == VIRP_ERR_CHAIN_BROKEN,
          "an intent_hash that is not sha256(intent_json) is refused");
    char upper[65];
    gate_sha256_hex(IJ, strlen(IJ), upper);
    for (int i = 0; i < 64; i++)
        if (upper[i] >= 'a' && upper[i] <= 'f') upper[i] = (char)(upper[i] - 32);
    CHECK(fx_ask(st, me, m4_store("upper-hash", IJ, upper, "high", NULL, NULL))
              == VIRP_ERR_INVALID_LENGTH,
          "an upper-case intent_hash is refused (64 LOWERCASE hex)");
    CHECK(virp_chain_intent_get(&st->chain, "bad-hash", &ie)
              == VIRP_ERR_INTENT_NOT_FOUND &&
          virp_chain_intent_get(&st->chain, "inj-constraints", &ie)
              == VIRP_ERR_INTENT_NOT_FOUND,
          "a refused intent was not stored");

    /* A row written before these checks existed: it must not be signed. */
    memset(&ie, 0, sizeof(ie));
    snprintf(ie.intent_id, sizeof(ie.intent_id), "legacy-row");
    gate_sha256_hex(IJ, strlen(IJ), ie.intent_hash);
    snprintf(ie.intent_json, sizeof(ie.intent_json), "%s", IJ);
    snprintf(ie.confidence, sizeof(ie.confidence), "high");
    snprintf(ie.constraints, sizeof(ie.constraints),
             "{},\"signature_hmac\":\"" H2_HASH "\"");
    CHECK(virp_chain_intent_store(&st->chain, &ie) == VIRP_OK,
          "(a pre-M4 style row is planted directly in the store)");
    CHECK(fx_ask(st, me, "{\"action\":\"intent_get\","
                         "\"intent_id\":\"legacy-row\"}") != VIRP_OK,
          "intent_get refuses a stored row it cannot render as JSON");

    fx_destroy(fx);
}

static void t_M4_intent_body_store_failure_is_reported(void)
{
    printf("\n  M4: a failed intent body store is an error, not an acknowledgement\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m4-artifact")) { CHECK(false, "fixture"); return; }
    /* Make the artifact store — and only it — fail. */
    CHECK(sqlite3_exec(fx->st.chain.db, "DROP TABLE artifacts;", NULL, NULL,
                       NULL) == SQLITE_OK, "(artifact table removed)");
    CHECK(fx_ask(&fx->st, getuid(),
                 m4_store("no-body", "{\"goal\":\"x\"}", NULL, "high",
                          NULL, NULL)) == VIRP_ERR_CHAIN_DB,
          "intent_store reports the body-store failure");
    fx_destroy(fx);
}

/* =========================================================================
 * M5 — the daemon's own chain sessions are not appendable from the socket
 * ========================================================================= */

/* A commitment-only evidence_item append: a legal type for an unrestricted
 * uid, so the only thing that can refuse it is the session. */
static const char *m5_append(const char *session)
{
    static char req[512];
    snprintf(req, sizeof(req),
             "{\"action\":\"chain_append\",\"session_id\":\"%s\","
             "\"artifact_type\":\"evidence_item\",\"artifact_id\":\"m5-item\","
             "\"artifact_hash\":\"" H2_HASH "\"}", session);
    return req;
}

static const char *m5_validate(const char *req_session,
                               const char *manifest_session)
{
    static char req[768];
    snprintf(req, sizeof(req),
             "{\"action\":\"validate_turn\",\"session_id\":\"%s\","
             "\"prose\":\"x\",\"manifest\":{\"session_id\":\"%s\"}}",
             req_session, manifest_session);
    return req;
}

static void t_M5_reserved_sessions_refused_externally(void)
{
    printf("\n  M5: external appends cannot target the daemon's own sessions\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m5-sess")) { CHECK(false, "fixture"); return; }
    onode_state_t *st = &fx->st;
    uid_t me = getuid();

    CHECK(fx_ask(st, me, m5_append("client-session-1")) == VIRP_OK,
          "an ordinary session is appendable");
    static const char *const RESERVED[] = {
        "gate-enforce:" FX_DEV, "gate-separator:" FX_DEV,
        "gate-separator:_unknown", "approval:" FX_DEV,
        "node-config:5EC00001", "gate-enforce:",
    };
    for (size_t i = 0; i < sizeof(RESERVED) / sizeof(RESERVED[0]); i++) {
        char msg[160];
        snprintf(msg, sizeof(msg), "chain_append to '%s' is refused",
                 RESERVED[i]);
        CHECK(fx_ask(st, me, m5_append(RESERVED[i])) == VIRP_ERR_ACTION_FORBIDDEN,
              msg);
        CHECK(fx_session_entries(fx, RESERVED[i]) == 0,
              "and nothing was appended there");
    }

    CHECK(fx_ask(st, me, m5_validate("gate-enforce:" FX_DEV, "turn-1"))
              == VIRP_ERR_ACTION_FORBIDDEN,
          "validate_turn with a reserved fallback session is refused");
    CHECK(fx_ask(st, me, m5_validate("turn-1", "approval:" FX_DEV))
              == VIRP_ERR_ACTION_FORBIDDEN,
          "validate_turn whose MANIFEST names a reserved session is refused");
    CHECK(fx_session_entries(fx, "approval:" FX_DEV) == 0 &&
          fx_session_entries(fx, "gate-enforce:" FX_DEV) == 0,
          "and no validation entry landed in either");
    CHECK(fx_ask(st, me, m5_validate("turn-1", "turn-1"))
              != VIRP_ERR_ACTION_FORBIDDEN,
          "validate_turn on an ordinary session is not refused by this gate");

    /* The epoch marker identifies the daemon's native namespace. */
    snprintf(st->chain.native_epoch, sizeof(st->chain.native_epoch), "ep1");
    CHECK(fx_ask(st, me, m5_append("anything@ep1")) == VIRP_ERR_ACTION_FORBIDDEN,
          "with a native epoch set, a session ending @<epoch> is refused");
    CHECK(fx_ask(st, me, m5_append("anything@ep2")) == VIRP_OK,
          "a different suffix is just a session id");
    st->chain.native_epoch[0] = '\0';

    /* Reading the daemon's sessions stays allowed. */
    CHECK(fx_ask(st, me, "{\"action\":\"chain_verify_session\","
                         "\"session_id\":\"gate-enforce:" FX_DEV "\"}")
              != VIRP_ERR_ACTION_FORBIDDEN,
          "chain_verify_session on a reserved session is still permitted");
    fx_destroy(fx);
}

/* =========================================================================
 * M6 — one observation, one registration
 * ========================================================================= */

/* Mint a real O-Key-signed observation and wrap it as a chain_append
 * request. Observation `which` (1..M6_OBS) is minted ONCE per fixture and
 * then reused byte-for-byte: the header carries a timestamp, so minting
 * again would be a different observation with a different hash. */
#define M6_OBS 4
static struct { uint8_t wire[512]; size_t n; } m6_obs[M6_OBS + 1];

static const char *m6_append(fx_t *fx, uint32_t which, const char *type,
                             const char *session, const char *id,
                             bool with_body)
{
    static char req[4096];
    if (which == 0 || which > M6_OBS) return "";
    if (m6_obs[which].n == 0 &&
        virp_build_observation(m6_obs[which].wire, sizeof(m6_obs[which].wire),
                               &m6_obs[which].n, fx->st.node_id, which,
                               VIRP_OBS_DEVICE_OUTPUT, VIRP_SCOPE_LOCAL,
                               (const uint8_t *)"m6 output", 9,
                               &fx->st.okey) != VIRP_OK)
        return "";
    char content[1024] = "base64:";
    EVP_EncodeBlock((unsigned char *)content + 7, m6_obs[which].wire,
                    (int)m6_obs[which].n);
    char hash[65];
    if (virp_chain_artifact_digest(content, hash) != VIRP_OK) return "";
    int off = snprintf(req, sizeof(req),
        "{\"action\":\"chain_append\",\"session_id\":\"%s\","
        "\"artifact_type\":\"%s\",\"artifact_id\":\"%s\","
        "\"artifact_hash\":\"%s\"", session, type, id, hash);
    if (with_body)
        off += snprintf(req + off, sizeof(req) - (size_t)off,
                        ",\"artifact_content\":\"%s\"", content);
    snprintf(req + off, sizeof(req) - (size_t)off, "}");
    return req;
}

static void t_M6_observation_registered_once(void)
{
    printf("\n  M6: a signed observation cannot be registered twice under another id or session\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m6-obs")) { CHECK(false, "fixture"); return; }
    onode_state_t *st = &fx->st;
    uid_t me = getuid();
    memset(m6_obs, 0, sizeof(m6_obs));     /* new fixture, new O-Key */

    CHECK(fx_ask(st, me, m6_append(fx, 1, "observation", "s1", "obs-a", true))
              == VIRP_OK, "an observation registers");
    CHECK(fx_ask(st, me, m6_append(fx, 1, "observation", "s1", "obs-a", true))
              == VIRP_OK,
          "the same id in the same session again is a retry, not a conflict");
    CHECK(fx_ask(st, me, m6_append(fx, 1, "observation", "s1", "obs-b", true))
              == VIRP_ERR_DUPLICATE_MISMATCH,
          "the same observation under a DIFFERENT id is refused");
    CHECK(fx_ask(st, me, m6_append(fx, 1, "observation", "s2", "obs-a", true))
              == VIRP_ERR_DUPLICATE_MISMATCH,
          "the same observation in a DIFFERENT session is refused");
    CHECK(fx_ask(st, me, m6_append(fx, 1, "fed_observation", "s3", "obs-c", true))
              == VIRP_ERR_DUPLICATE_MISMATCH,
          "re-registering it as fed_observation is refused too");
    CHECK(fx_ask(st, me, m6_append(fx, 1, "observation", "s4", "obs-d", false))
              == VIRP_ERR_DUPLICATE_MISMATCH,
          "a commitment-only re-registration is refused as well");
    CHECK(fx_session_entries(fx, "s2") == 0 && fx_session_entries(fx, "s3") == 0 &&
          fx_session_entries(fx, "s4") == 0 && fx_session_entries(fx, "s1") == 2,
          "nothing landed for the refused appends");

    CHECK(fx_ask(st, me, m6_append(fx, 2, "observation", "s2", "obs-a", true))
              == VIRP_OK,
          "a DIFFERENT observation may reuse an id in another session");

    /* A commitment-only prior counts: authority is the chain entry. */
    CHECK(fx_ask(st, me, m6_append(fx, 3, "fed_observation", "s5", "fo-1", false))
              == VIRP_OK, "a commitment-only fed_observation registers");
    CHECK(fx_ask(st, me, m6_append(fx, 3, "fed_observation", "s5", "fo-2", true))
              == VIRP_ERR_DUPLICATE_MISMATCH,
          "and its hash cannot then be registered under another id");

    /* The rule is about socket submissions; the library append that
     * tools and fixtures use is unchanged. */
    virp_chain_entry_t e;
    CHECK(virp_chain_append(&st->chain, "lib-1", "observation", "x1",
                            H2_HASH, &e) == VIRP_OK &&
          virp_chain_append(&st->chain, "lib-2", "observation", "x2",
                            H2_HASH, &e) == VIRP_OK,
          "virp_chain_append (direct library use) is not subject to it");
    fx_destroy(fx);
}

/* =========================================================================
 * M7 — a hostname must be usable as a chain session id
 * ========================================================================= */

static virp_error_t m7_add(onode_state_t *st, const char *hostname, uint32_t nid)
{
    virp_device_t d;
    memset(&d, 0, sizeof(d));
    snprintf(d.hostname, sizeof(d.hostname), "%s", hostname);
    snprintf(d.host, sizeof(d.host), "10.255.7.%u", nid & 0xff);
    d.vendor = VIRP_VENDOR_MOCK; d.node_id = nid; d.enabled = true;
    return onode_add_device(st, &d);
}

static const char *m7_name(size_t len)
{
    static char buf[64];
    memset(buf, 'h', len);
    buf[len] = '\0';
    return buf;
}

static void t_M7_hostname_must_fit_session_id(void)
{
    printf("\n  M7: hostnames the chain cannot carry as a session id are refused\n");
    static onode_state_t st;
    CHECK(onode_init(&st, 1, NULL, "/tmp/virp-review-unused.sock") == VIRP_OK,
          "state initialised");

    CHECK(m7_add(&st, "core\"sw", 0x70000001) == VIRP_ERR_INVALID_LENGTH,
          "a hostname containing a quote is refused");
    CHECK(m7_add(&st, "core\\sw", 0x70000002) == VIRP_ERR_INVALID_LENGTH,
          "a hostname containing a backslash is refused");
    CHECK(m7_add(&st, "core\nsw", 0x70000003) == VIRP_ERR_INVALID_LENGTH,
          "a hostname containing a control byte is refused");

    /* No epoch: gate-separator:<host> is the longest id; 15 + 48 = 63. */
    CHECK(m7_add(&st, m7_name(49), 0x70000004) == VIRP_ERR_INVALID_LENGTH,
          "49 bytes: gate-separator:<host> would be 64 > 63, refused");
    CHECK(m7_add(&st, m7_name(48), 0x70000005) == VIRP_OK,
          "48 bytes: fits exactly, accepted");
    CHECK(st.device_count == 1, "only the fitting device was added");

    /* With a 16-char epoch: gate-enforce:<host>@<epoch> = 13 + L + 17. */
    snprintf(st.chain.native_epoch, sizeof(st.chain.native_epoch),
             "0123456789abcdef");
    char a34[64], a33[64];
    memset(a34, 'e', 34); a34[34] = '\0';
    memset(a33, 'f', 33); a33[33] = '\0';
    CHECK(m7_add(&st, a34, 0x70000006) == VIRP_ERR_INVALID_LENGTH,
          "with a 16-char epoch, 34 bytes is refused");
    CHECK(m7_add(&st, a33, 0x70000007) == VIRP_OK,
          "with a 16-char epoch, 33 bytes fits");
    st.chain.native_epoch[0] = '\0';
    onode_destroy(&st);
}

/* Before the fix this does not return: onode_start() binds and serves. */
static void t_M7_start_rechecks_hostnames_against_epoch(void)
{
    printf("\n  M7: onode_start re-checks hostnames once the epoch is final\n");
    static onode_state_t st;
    char sock[128];
    snprintf(sock, sizeof(sock), "%s/m7-start.sock", g_root);
    CHECK(onode_init(&st, 1, NULL, sock) == VIRP_OK, "state initialised");
    CHECK(m7_add(&st, m7_name(48), 0x70000011) == VIRP_OK,
          "a 48-byte hostname loads while no epoch is configured");
    snprintf(st.chain.native_epoch, sizeof(st.chain.native_epoch), "v3-20261016");
    CHECK(onode_start(&st) == VIRP_ERR_INVALID_LENGTH,
          "onode_start refuses: the epoch made that hostname's session id too long");
    CHECK(access(sock, F_OK) != 0, "and nothing was bound");
    st.chain.native_epoch[0] = '\0';
    onode_destroy(&st);
}

/* =========================================================================
 * M8 — nanosecond evidence integers leave the daemon as decimal strings
 * ========================================================================= */

/* The newest stored body of `type`, parsed. Caller cJSON_Delete()s. */
static cJSON *fx_latest_body(fx_t *fx, const char *type)
{
    sqlite3_stmt *st = NULL;
    cJSON *o = NULL;
    if (sqlite3_prepare_v2(fx->st.chain.db,
            "SELECT artifact_content FROM artifacts WHERE artifact_type = ? "
            "ORDER BY id DESC LIMIT 1", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, type, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            o = cJSON_Parse((const char *)sqlite3_column_text(st, 0));
    }
    sqlite3_finalize(st);
    return o;
}

/* A member that is a string of 19 decimal digits (a 2026-era ns clock),
 * returned as a number; 0 if it is anything else. */
static uint64_t m8_ns_string(const cJSON *o, const char *key)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);
    if (!cJSON_IsString(v) || !v->valuestring) return 0;
    if (strlen(v->valuestring) != 19 ||
        strspn(v->valuestring, "0123456789") != 19)
        return 0;
    return strtoull(v->valuestring, NULL, 10);
}

static uint64_t m8_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void t_M8_ns_fields_are_decimal_strings(void)
{
    printf("\n  M8: intent_ns / emitted_ns / approved_at_ns are exact decimal strings\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m8-ns")) { CHECK(false, "fixture"); return; }
    onode_state_t *st = &fx->st;
    uint8_t ot = 0;
    char payload[2048];

    /* gate_intent.intent_ns */
    uint64_t t0 = m8_now_ns();
    CHECK(fx_run(fx, FX_DEV, "show version", NULL, (uid_t)-1, &ot, payload,
                 sizeof(payload)) == 0, "a GREEN read executes");
    uint64_t t1 = m8_now_ns();
    cJSON *intent = fx_latest_body(fx, "gate_intent");
    uint64_t ins = intent ? m8_ns_string(intent, "intent_ns") : 0;
    CHECK(ins >= t0 && ins <= t1,
          "gate_intent.intent_ns is a decimal string inside the dispatch window");
    if (intent) cJSON_Delete(intent);

    /* node_config.emitted_ns */
    t0 = m8_now_ns();
    CHECK(onode_emit_node_config(st) == VIRP_OK, "node_config recorded");
    t1 = m8_now_ns();
    cJSON *nc = fx_latest_body(fx, "node_config");
    uint64_t ens = nc ? m8_ns_string(nc, "emitted_ns") : 0;
    CHECK(ens >= t0 && ens <= t1,
          "node_config.emitted_ns is a decimal string inside the emit window");
    if (nc) cJSON_Delete(nc);

    /* approval challenge: the displayed value must be the SIGNED value. */
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    CHECK(fx_propose(fx, "reload", pid) == 0, "proposal filed");
    char reqbuf[256];
    snprintf(reqbuf, sizeof(reqbuf),
             "{\"action\":\"approval_challenge\",\"proposal_id\":\"%s\"}", pid);
    cJSON *ch = fx_ask_json(fx, getuid(), reqbuf, VIRP_OBS_APPROVAL_CHALLENGE,
                            NULL);
    CHECK(ch != NULL, "challenge issued");
    uint64_t shown = ch ? m8_ns_string(ch, "approved_at_ns") : 0;
    uint64_t in_canon = 0;
    uint8_t canon[VIRP_APPROVAL_CANON_SIZE];
    const cJSON *cj = ch ? cJSON_GetObjectItemCaseSensitive(ch, "canonical") : NULL;
    if (cJSON_IsString(cj) &&
        virp_hex_decode(cj->valuestring, canon, sizeof(canon)) == (int)sizeof(canon))
        for (int i = 0; i < 8; i++)
            in_canon = (in_canon << 8) | canon[60 + i];
    CHECK(shown != 0 && shown == in_canon,
          "challenge approved_at_ns is a decimal string EQUAL to the 8 bytes being signed");

    /* approval result */
    uint8_t sig[VIRP_APPROVER_SIG_SIZE];
    char kid[33], sighex[2 * VIRP_APPROVER_SIG_SIZE + 1], sub[512];
    fx_keyid_hex(&fx->kp, kid);
    CHECK(in_canon != 0 &&
          virp_fed_sign(&fx->kp, canon, VIRP_APPROVAL_CANON_SIZE, sig) == VIRP_OK,
          "challenge signed");
    hex_of(sig, sizeof(sig), sighex);
    snprintf(sub, sizeof(sub),
             "{\"action\":\"approval_submit\",\"proposal_id\":\"%s\","
             "\"key_id\":\"%s\",\"signature\":\"%s\"}", pid, kid, sighex);
    cJSON *res = fx_ask_json(fx, getuid(), sub, VIRP_OBS_APPROVAL_RESULT, NULL);
    CHECK(res != NULL && m8_ns_string(res, "approved_at_ns") == in_canon,
          "approval result approved_at_ns is the same exact decimal string");
    if (ch) cJSON_Delete(ch);
    if (res) cJSON_Delete(res);
    fx_destroy(fx);
}

/* =========================================================================
 * M9 — an owner-policy refusal is recorded and answered with a signed
 * observation, not a bare error code
 * ========================================================================= */

/* How many gate_rejection bodies in `session` carry this refusal_stage
 * (any stage when NULL). *last_out, if asked for, is the newest match. */
static int fx_rejections(fx_t *fx, const char *session, const char *stage,
                         cJSON **last_out)
{
    sqlite3_stmt *st = NULL;
    int n = 0;
    if (last_out) *last_out = NULL;
    if (sqlite3_prepare_v2(fx->st.chain.db,
            "SELECT a.artifact_content FROM chain_entries c "
            "JOIN artifacts a ON a.artifact_id = c.artifact_id "
            "               AND a.artifact_hash = c.artifact_hash "
            "WHERE c.session_id = ? AND c.artifact_type = 'gate_rejection' "
            "ORDER BY c.sequence", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, session, -1, SQLITE_TRANSIENT);
    while (sqlite3_step(st) == SQLITE_ROW) {
        cJSON *o = cJSON_Parse((const char *)sqlite3_column_text(st, 0));
        if (!o) continue;
        const cJSON *s = cJSON_GetObjectItemCaseSensitive(o, "refusal_stage");
        bool match = stage ? (cJSON_IsString(s) && !strcmp(s->valuestring, stage))
                           : true;
        if (match) {
            n++;
            if (last_out) {
                if (*last_out) cJSON_Delete(*last_out);
                *last_out = o;
                continue;
            }
        }
        cJSON_Delete(o);
    }
    sqlite3_finalize(st);
    return n;
}

static void t_M9_policy_refusal_is_chained_and_signed(void)
{
    printf("\n  M9: owner-policy refusals leave a chain record and a signed answer\n");
    fx_t *fx = &g_fx;
    sqlite3 *db = NULL;
    if (!h4_init(fx, "m9-policy", &db, "observe")) {
        CHECK(false, "fixture (needs a plain build, without LINUX=1)");
        return;
    }
    uid_t me = getuid();
    uint8_t ot = 0;
    char payload[2048] = "";

    /* Observe profile, disruptive operation: refused by the policy. */
    CHECK(fx_run(fx, H4_DEV, "reboot", NULL, me, &ot, payload,
                 sizeof(payload)) == 0 && ot == VIRP_OBS_ERROR,
          "a policy refusal is a signed ERROR observation, not a bare code");
    CHECK(strstr(payload, "owner policy refused 'reboot'") != NULL &&
          strstr(payload, "nothing was dispatched") != NULL,
          "it says what was refused and that nothing ran");
    CHECK(h4_dispatches == 0, "nothing was dispatched");
    cJSON *body = NULL;
    CHECK(fx_rejections(fx, "gate-enforce:" H4_DEV, "owner-policy", &body) == 1,
          "ONE gate_rejection, stage owner-policy, in the device's gate session");
    if (body) {
        const cJSON *uid = cJSON_GetObjectItemCaseSensitive(body, "uid");
        const cJSON *ex  = cJSON_GetObjectItemCaseSensitive(body, "executed");
        const cJSON *cmd = cJSON_GetObjectItemCaseSensitive(body, "command");
        CHECK(cJSON_IsNumber(uid) && (uid_t)uid->valuedouble == me &&
              cJSON_IsFalse(ex) && cJSON_IsString(cmd) &&
              !strcmp(cmd->valuestring, "reboot"),
              "the record names the uid and the command, executed=false");
        cJSON_Delete(body);
    }

    /* Outside the policy's closed grammar. */
    ot = 0;
    CHECK(fx_run(fx, H4_DEV, "rm -rf /", NULL, me, &ot, payload,
                 sizeof(payload)) == 0 && ot == VIRP_OBS_ERROR &&
          fx_rejections(fx, "gate-enforce:" H4_DEV, "owner-policy", NULL) == 2,
          "a command outside the grammar is refused the same way");

    /* A principal the policy does not know. */
    ot = 0;
    CHECK(fx_run(fx, H4_DEV, "uptime", NULL, me + 1, &ot, payload,
                 sizeof(payload)) == 0 && ot == VIRP_OBS_ERROR &&
          fx_rejections(fx, "gate-enforce:" H4_DEV, "owner-policy", NULL) == 3,
          "an unknown principal is refused the same way");

    /* A device this node does not serve: one fixed session. */
    ot = 0;
    CHECK(fx_run(fx, "ghost-device", "uptime", NULL, me, &ot, payload,
                 sizeof(payload)) == 0 && ot == VIRP_OBS_ERROR &&
          strstr(payload, "device not served by this node") != NULL,
          "policy mode: an unknown device is a signed ERROR observation");
    body = NULL;
    CHECK(fx_rejections(fx, "gate-enforce:_unknown", "owner-policy", &body) == 1 &&
          fx_session_entries(fx, "gate-enforce:ghost-device") == 0,
          "recorded under the fixed session, not one the caller named");
    if (body) {
        CHECK(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(body, "device_known")),
              "and marked device_known=false");
        cJSON_Delete(body);
    }

    /* Control bytes are not relayed in the signed payload. */
    ot = 0;
    CHECK(fx_run(fx, H4_DEV, "up\x01time\nreboot", NULL, me, &ot, payload,
                 sizeof(payload)) == 0 && ot == VIRP_OBS_ERROR &&
          strstr(payload, "'up?time?reboot'") != NULL,
          "control bytes in the refused command are rendered '?' in the observation");
    CHECK(h4_dispatches == 0, "still nothing dispatched");

    fx_destroy(fx);
    sqlite3_close(db);
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
    { "t_M2_overlength_optional_field_rejects_request",
                                              t_M2_overlength_optional_field_rejects_request },
    { "t_M2_handshake_hex_exact_length",      t_M2_handshake_hex_exact_length },
    { "t_M3_device_name_validated_at_ingress", t_M3_device_name_validated_at_ingress },
    { "t_M3_unknown_device_uses_fixed_separator_session",
                                              t_M3_unknown_device_uses_fixed_separator_session },
    { "t_M4_intent_store_validates_and_get_is_wellformed",
                                              t_M4_intent_store_validates_and_get_is_wellformed },
    { "t_M4_intent_body_store_failure_is_reported",
                                              t_M4_intent_body_store_failure_is_reported },
    { "t_M5_reserved_sessions_refused_externally",
                                              t_M5_reserved_sessions_refused_externally },
    { "t_M6_observation_registered_once",     t_M6_observation_registered_once },
    { "t_M7_hostname_must_fit_session_id",    t_M7_hostname_must_fit_session_id },
    { "t_M7_start_rechecks_hostnames_against_epoch",
                                              t_M7_start_rechecks_hostnames_against_epoch },
    { "t_M8_ns_fields_are_decimal_strings",   t_M8_ns_fields_are_decimal_strings },
    { "t_M9_policy_refusal_is_chained_and_signed",
                                              t_M9_policy_refusal_is_chained_and_signed },
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
