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
/* Thread-creation seam (see ONODE_PTHREAD_CREATE in the daemon source):
 * every pthread_create the daemon makes goes through this, so a test can
 * make the Nth one fail. Declared before the daemon source is included. */
#define _POSIX_C_SOURCE 200809L   /* the same two the daemon source sets; */
#define _GNU_SOURCE               /* they must precede the first header   */
#include <pthread.h>
static int review_pthread_create(pthread_t *t, const pthread_attr_t *a,
                                 void *(*fn)(void *), void *arg);
#define ONODE_PTHREAD_CREATE review_pthread_create

#include "../src/virp_onode.c"

#include "virp_federation.h"
#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/wait.h>

extern void virp_driver_mock_init(void);
/* The production config loader (virp_onode_prod.c, linked NO_MAIN). */
extern int load_devices(onode_state_t *state, const char *path);
extern int load_devices_production(onode_state_t *state, const char *path);
extern int  virp_driver_mock_exec_attempts_reset(void);

/* Fail the Nth creation from now (1 = the next one); 0 = never. */
static int review_fail_create_in;
/* Smallest stack size any creation asked for since it was last reset
 * (SIZE_MAX = none seen; 0 = one was created with default attributes). */
static size_t review_min_stack = SIZE_MAX;

static int review_pthread_create(pthread_t *t, const pthread_attr_t *a,
                                 void *(*fn)(void *), void *arg)
{
    size_t sz = 0;
    if (a && pthread_attr_getstacksize(a, &sz) != 0) sz = 0;
    /* The watchdog is not a request thread and is created with default
     * attributes on purpose; only attributed creations are sampled, plus
     * any un-attributed one that is not the watchdog's. */
    if (a || fn != watchdog_thread_fn)
        if (sz < review_min_stack) review_min_stack = sz;
    if (review_fail_create_in > 0 && --review_fail_create_in == 0)
        return EAGAIN;
    return pthread_create(t, a, fn, arg);
}

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
static void (*h4_on_execute)(void);  /* runs inside execute(), mid-command */

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
    if (h4_on_execute) h4_on_execute();
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
    h4_on_execute = NULL;
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
 * M10 — refusals and proposals say which uid they are about
 * ========================================================================= */

/* true iff body.uid is the number `want`, or JSON null when want is the
 * internal caller. */
static bool m10_uid_is(const cJSON *body, uid_t want)
{
    const cJSON *u = body ? cJSON_GetObjectItemCaseSensitive(body, "uid") : NULL;
    if (want == (uid_t)-1) return cJSON_IsNull(u);
    return cJSON_IsNumber(u) && (uid_t)u->valuedouble == want;
}

static void t_M10_uid_in_rejections_and_proposer(void)
{
    printf("\n  M10: gate_rejection bodies and proposals carry the peer uid\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m10-uid")) { CHECK(false, "fixture"); return; }
    const uid_t who = 4242;
    uint8_t ot = 0;
    char payload[2048];
    char want[64];

    /* Tier refusal (RED over the YELLOW ceiling) from a socket uid. */
    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1] = "";
    CHECK(fx_run(fx, FX_DEV, "reload", NULL, who, &ot, payload,
                 sizeof(payload)) == 0 && ot == VIRP_OBS_ERROR &&
          fx_extract_pid(payload, pid) == 0, "a RED command is refused, proposal filed");
    cJSON *body = NULL;
    (void)fx_rejections(fx, "gate-enforce:" FX_DEV, NULL, &body);
    CHECK(m10_uid_is(body, who), "the tier gate_rejection names the uid");
    if (body) cJSON_Delete(body);

    virp_proposal_rec_t prop;
    snprintf(want, sizeof(want), "uid:%lu", (unsigned long)who);
    CHECK(virp_approval_load_proposal(fx->dir, pid, &prop) == VIRP_OK &&
          strstr(prop.proposer, want) != NULL &&
          strncmp(prop.proposer, "unauthenticated-v1 ", 19) == 0,
          "the proposal's proposer is '<session marker> uid:<n>'");
    CHECK(strcmp(prop.session_id, "unauthenticated-v1") == 0,
          "its session_id keeps the bare session marker");

    /* Separator refusal. */
    CHECK(fx_run(fx, FX_DEV, "show version ; reload", NULL, who, &ot, payload,
                 sizeof(payload)) == 0, "a separator-carrying command is refused");
    body = NULL;
    (void)fx_rejections(fx, "gate-separator:" FX_DEV, "ingress-separator", &body);
    CHECK(m10_uid_is(body, who), "the separator gate_rejection names the uid");
    if (body) cJSON_Delete(body);

    /* Replay refusal: approve, apply, apply again as the same uid. */
    virp_approval_rec_t apr;
    CHECK(fx_approve(fx, pid, &apr) == VIRP_OK, "approval submitted");
    CHECK(fx_run(fx, FX_DEV, "reload", pid, who, &ot, payload,
                 sizeof(payload)) == 0, "first apply");
    CHECK(fx_run(fx, FX_DEV, "reload", pid, who, &ot, payload,
                 sizeof(payload)) == 0 && ot == VIRP_OBS_ERROR &&
          strstr(payload, "approval_reused") != NULL, "second apply refused");
    body = NULL;
    (void)fx_rejections(fx, "gate-enforce:" FX_DEV, NULL, &body);
    const cJSON *reason = body ? cJSON_GetObjectItemCaseSensitive(body, "reason") : NULL;
    CHECK(cJSON_IsString(reason) && !strcmp(reason->valuestring, "approval_reused") &&
          m10_uid_is(body, who),
          "the replay gate_rejection names the uid that tried it");
    if (body) cJSON_Delete(body);

    /* The internal caller is explicit, never 4294967295. */
    char pid2[VIRP_APPROVAL_ID_HEX_LEN + 1] = "";
    CHECK(fx_run(fx, FX_DEV, "erase flash", NULL, (uid_t)-1, &ot, payload,
                 sizeof(payload)) == 0 && fx_extract_pid(payload, pid2) == 0,
          "an internal caller's RED command is refused, proposal filed");
    body = NULL;
    (void)fx_rejections(fx, "gate-enforce:" FX_DEV, NULL, &body);
    CHECK(m10_uid_is(body, (uid_t)-1), "internal caller: uid is JSON null");
    if (body) cJSON_Delete(body);
    CHECK(virp_approval_load_proposal(fx->dir, pid2, &prop) == VIRP_OK &&
          strstr(prop.proposer, "uid:internal") != NULL,
          "internal caller: proposer says uid:internal");
    fx_destroy(fx);
}

/* =========================================================================
 * M11 — a verify response says everything the verifier concluded
 * ========================================================================= */

static bool m11_has_all(const cJSON *o)
{
    static const struct { const char *key; int kind; } WANT[] = {
        /* kind: 0 bool, 1 number, 2 string */
        { "verifier_error", 0 }, { "verifier_error_detail", 2 },
        { "sig_era", 2 },        { "valid_signed", 0 },
        { "hmac_checked", 0 },   { "sig_checked", 0 },
        { "head_authenticated", 0 },
        { "artifacts_bound", 1 }, { "artifacts_unverifiable", 1 },
        { "executions_closed", 1 },
        /* and the members that were already there */
        { "valid", 0 }, { "entries_checked", 1 }, { "executions_open", 1 },
        { "first_broken", 1 }, { "from_sequence", 1 }, { "to_sequence", 1 },
        { "error_detail", 2 },
    };
    for (size_t i = 0; i < sizeof(WANT) / sizeof(WANT[0]); i++) {
        const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, WANT[i].key);
        bool ok = WANT[i].kind == 0 ? cJSON_IsBool(v)
                : WANT[i].kind == 1 ? cJSON_IsNumber(v) : cJSON_IsString(v);
        if (!ok) {
            printf("      missing or mistyped member: %s\n", WANT[i].key);
            return false;
        }
    }
    return true;
}

static void t_M11_verify_response_carries_verifier_state(void)
{
    printf("\n  M11: chain_verify responses report verifier error, era and grades\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m11-verify")) { CHECK(false, "fixture"); return; }
    uid_t me = getuid();
    uint8_t ot = 0;
    char payload[2048];

    /* Two GREEN reads: two intent/execution pairs in the gate session. */
    CHECK(fx_run(fx, FX_DEV, "show version", NULL, me, &ot, payload,
                 sizeof(payload)) == 0 &&
          fx_run(fx, FX_DEV, "show clock", NULL, me, &ot, payload,
                 sizeof(payload)) == 0, "two reads executed");

    int dups = -1;
    cJSON *vs = fx_ask_json(fx, me,
        "{\"action\":\"chain_verify_session\","
        "\"session_id\":\"gate-enforce:" FX_DEV "\"}",
        VIRP_OBS_CHAIN_VERIFY, &dups);
    CHECK(vs != NULL && dups == 0, "chain_verify_session answers one object");
    bool complete = vs && m11_has_all(vs);
    CHECK(complete, "it carries all ten added members, typed");
    /* The value checks dereference those members, so only with all present. */
    if (complete) {
        CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(vs, "valid")) &&
              cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(vs, "verifier_error")) &&
              cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(vs, "hmac_checked")) &&
              cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(vs, "head_authenticated")),
              "an intact session: valid, no verifier error, HMACs and head checked");
        CHECK(cJSON_GetObjectItemCaseSensitive(vs, "executions_closed")->valuedouble == 2 &&
              cJSON_GetObjectItemCaseSensitive(vs, "artifacts_bound")->valuedouble == 4,
              "two closed executions, four bound bodies");
        /* This fixture's chain has no Ed25519 signing: intact is not the
         * same as signed, and the response now says so. */
        CHECK(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(vs, "valid_signed")) &&
              strcmp(cJSON_GetObjectItemCaseSensitive(vs, "sig_era")->valuestring,
                     "SIGNED") != 0,
              "valid_signed is false and sig_era is not SIGNED for an unsigned chain");
    }
    if (vs) cJSON_Delete(vs);

    cJSON *v = fx_ask_json(fx, me,
        "{\"action\":\"chain_verify\","
        "\"session_id\":\"gate-enforce:" FX_DEV "\","
        "\"from_sequence\":0,\"to_sequence\":3}",
        VIRP_OBS_CHAIN_VERIFY, &dups);
    CHECK(v != NULL && dups == 0 && m11_has_all(v),
          "chain_verify (ranged) carries the same members");
    if (v) cJSON_Delete(v);

    /* A detail string quoting text from the database must not be able to
     * reshape the response. */
    virp_chain_verify_result_t r;
    memset(&r, 0, sizeof(r));
    r.first_broken = -1;
    r.verifier_error = true;
    snprintf(r.error_detail, sizeof(r.error_detail),
             "entry 'x\",\"valid\":true,\"y\":\"' has no body");
    snprintf(r.verifier_error_detail, sizeof(r.verifier_error_detail),
             "prepare failed: near \"\\\": syntax error");
    r.to_sequence = INT64_MAX;
    char buf[2048];
    int n = chain_verify_result_json(&r, buf, sizeof(buf));
    cJSON *o = n > 0 ? cJSON_ParseWithLengthOpts(buf, (size_t)n + 1, NULL, 1) : NULL;
    CHECK(o != NULL && !json_object_has_duplicate_keys(o, 1024) &&
          cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(o, "valid")) &&
          cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(o, "verifier_error")) &&
          !strcmp(cJSON_GetObjectItemCaseSensitive(o, "error_detail")->valuestring,
                  r.error_detail),
          "quotes in a detail string are escaped: valid stays false, one member each");
    CHECK(strstr(buf, "\"to_sequence\":9223372036854775807") != NULL,
          "to_sequence is echoed exactly, not through a double");
    if (o) cJSON_Delete(o);
    fx_destroy(fx);
}

/* =========================================================================
 * M12 — a session lost AFTER the device acted is not a bare error
 * ========================================================================= */

/* Real handshake over the socket: HELLO, then BIND with what came back. */
static bool m12_bind_session(fx_t *fx, uid_t uid)
{
    static uint8_t resp[4096];
    ssize_t n = fx_request(&fx->st, uid,
        "{\"action\":\"session_hello\",\"client_id\":\"m12\","
        "\"client_nonce\":\"0011223344556677\"}", resp, sizeof(resp) - 1);
    if (n <= 4) return false;
    resp[n] = '\0';
    cJSON *ack = cJSON_Parse((const char *)resp);
    if (!ack) return false;
    const cJSON *sid = cJSON_GetObjectItemCaseSensitive(ack, "session_id");
    const cJSON *cn  = cJSON_GetObjectItemCaseSensitive(ack, "client_nonce");
    const cJSON *sn  = cJSON_GetObjectItemCaseSensitive(ack, "server_nonce");
    char bind[512];
    bool ok = cJSON_IsString(sid) && cJSON_IsString(cn) && cJSON_IsString(sn);
    if (ok)
        snprintf(bind, sizeof(bind),
                 "{\"action\":\"session_bind\",\"client_id\":\"m12\","
                 "\"session_id\":\"%s\",\"client_nonce\":\"%s\","
                 "\"server_nonce\":\"%s\"}",
                 sid->valuestring, cn->valuestring, sn->valuestring);
    cJSON_Delete(ack);
    if (!ok) return false;
    n = fx_request(&fx->st, uid, bind, resp, sizeof(resp) - 1);
    if (n <= 4) return false;
    resp[n] = '\0';
    return strstr((const char *)resp, "\"bound\"") != NULL;
}

/* The session ends while the command is on the device. */
static void m12_close_session_mid_command(void)
{
    onode_session_lock(&g_fx.st);
    virp_handle_session_close(g_fx.st.ctx);
    pthread_mutex_unlock(&g_fx.st.session_mutex);
}

/* Run and unpack whatever comes back as a v1 O-Key observation. Returns
 * the daemon's error code; *obs_type is 0 unless a v1 observation that
 * verifies under the O-Key was returned. */
static virp_error_t m12_run(fx_t *fx, int obs_version, uid_t uid,
                            uint8_t *obs_type, char *payload, size_t pcap)
{
    static uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = 0;
    *obs_type = 0;
    payload[0] = '\0';
    virp_error_t err = onode_execute_obs_ex(&fx->st, H4_DEV, "uptime",
                                            obs_version, NULL, uid,
                                            buf, sizeof(buf), &len);
    if (err != VIRP_OK || len < VIRP_HEADER_SIZE || buf[0] != VIRP_VERSION)
        return err;
    virp_header_t hdr;
    virp_observation_t obs;
    const uint8_t *data;
    uint16_t dl;
    if (virp_validate_message(buf, len, &fx->st.okey, &hdr) == VIRP_OK &&
        virp_parse_observation(buf + VIRP_HEADER_SIZE, len - VIRP_HEADER_SIZE,
                               &obs, &data, &dl) == VIRP_OK) {
        *obs_type = obs.obs_type;
        size_t n = dl < pcap - 1 ? dl : pcap - 1;
        memcpy(payload, data, n);
        payload[n] = '\0';
    }
    return err;
}

static void m12_case(const char *name, int obs_version, bool v3)
{
    fx_t *fx = &g_fx;
    sqlite3 *db = NULL;
    if (!h4_init(fx, name, &db, "autonomous")) {
        CHECK(false, "fixture (needs a plain build, without LINUX=1)");
        return;
    }
    /* Plain gate, no owner policy: this is about the session, not policy. */
    virp_policy_close(fx->st.policy);
    fx->st.policy = NULL;
    uid_t me = getuid();
    uint8_t ot = 0;
    char payload[1024];

    if (v3) {
        char kpath[200], ppath[200];
        snprintf(kpath, sizeof(kpath), "%s/%s/obs-sign.key", g_root, name);
        snprintf(ppath, sizeof(ppath), "%s/%s/obs-sign.pub", g_root, name);
        bool keyed = virp_obskey_generate(&fx->st.obskey) == VIRP_OK &&
                     virp_obskey_save(&fx->st.obskey, kpath, ppath) == VIRP_OK &&
                     virp_chain_enable_signing(&fx->st.chain, kpath) == VIRP_OK;
        CHECK(keyed, "(v3 signing key loaded)");
        fx->st.obskey_loaded = true;
    }

    /* No session at all: refused BEFORE dispatch. This stays a bare code,
     * and correctly — nothing ran. */
    CHECK(m12_run(fx, obs_version, me, &ot, payload, sizeof(payload))
              == VIRP_ERR_SESSION_INVALID && h4_dispatches == 0,
          "no session: bare SESSION_INVALID and nothing dispatched");

    CHECK(m12_bind_session(fx, me), "session bound over the socket");
    CHECK(m12_run(fx, obs_version, me, &ot, payload, sizeof(payload))
              == VIRP_OK && h4_dispatches == 1,
          "with a live session the command runs and is answered");

    /* The session ends while the command is running. */
    h4_on_execute = m12_close_session_mid_command;
    virp_error_t err = m12_run(fx, obs_version, me, &ot, payload,
                               sizeof(payload));
    h4_on_execute = NULL;
    CHECK(h4_dispatches == 2, "the command was dispatched");
    CHECK(err == VIRP_OK && ot == VIRP_OBS_ERROR,
          "session lost mid-command: an O-Key-signed ERROR observation, not a bare code");
    CHECK(strstr(payload, "DISPATCHED") != NULL &&
          strstr(payload, "session ended") != NULL &&
          strstr(payload, "would execute it a second time") != NULL,
          "it says the command ran and that re-running would repeat it");
    CHECK(strstr(payload, "h4 fixture output") == NULL,
          "it carries none of the device's output");
    CHECK(fx_session_entries(fx, "gate-enforce:" H4_DEV) == 4,
          "both executions are on the chain (intent + execution each)");

    fx_destroy(fx);
    sqlite3_close(db);
}

static void t_M12_v2_session_lost_after_dispatch(void)
{
    printf("\n  M12 (v2): session lost after the device acted\n");
    m12_case("m12-v2", 2, false);
}

static void t_M12_v3_session_lost_after_dispatch(void)
{
    printf("\n  M12 (v3): session lost after the device acted\n");
    m12_case("m12-v3", 3, true);
}

/* =========================================================================
 * M13 — a long command cannot push the proposal id out of the refusal
 * ========================================================================= */

static void t_M13_proposal_id_survives_long_command(void)
{
    printf("\n  M13: the refusal carries its proposal id whatever the command length\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m13-msg")) { CHECK(false, "fixture"); return; }
    uint8_t ot = 0;
    static char payload[4096];

    /* 500 bytes, RED on the mock ("reload ..."): well past the ~380
     * bytes at which the old 448-byte buffer dropped the id, and inside
     * the 511 canonical bytes a proposal's command hash can cover. */
    static char longcmd[501];
    memset(longcmd, 'x', sizeof(longcmd) - 1);
    memcpy(longcmd, "reload ", 7);
    longcmd[sizeof(longcmd) - 1] = '\0';

    char pid[VIRP_APPROVAL_ID_HEX_LEN + 1] = "";
    CHECK(fx_run(fx, FX_DEV, longcmd, NULL, (uid_t)-1, &ot, payload,
                 sizeof(payload)) == 0 && ot == VIRP_OBS_ERROR,
          "a 500-byte RED command is refused");
    CHECK(fx_extract_pid(payload, pid) == 0,
          "the refusal still carries proposal_id=<32 hex>");
    virp_proposal_rec_t prop;
    CHECK(pid[0] && virp_approval_load_proposal(fx->dir, pid, &prop) == VIRP_OK &&
          strcmp(prop.command, longcmd) == 0,
          "and it is the id of the proposal filed for exactly that command");

    const char *idpos  = strstr(payload, "proposal_id=");
    const char *cmdpos = strstr(payload, "'reload ");
    CHECK(strncmp(payload, "ERROR: tier gate blocked proposal_id=", 37) == 0 &&
          idpos && cmdpos && idpos < cmdpos,
          "the id comes BEFORE the command text, straight after the fixed prefix");
    size_t plen = strlen(payload);
    static const char TAIL[] = "' on '" FX_DEV "' (tier=RED max=YELLOW)";
    CHECK(plen > sizeof(TAIL) &&
          strcmp(payload + plen - (sizeof(TAIL) - 1), TAIL) == 0,
          "the device and tier after the command were not truncated either");

    /* What the chain kept matches what the caller was told. */
    cJSON *body = NULL;
    (void)fx_rejections(fx, "gate-enforce:" FX_DEV, NULL, &body);
    const cJSON *msg = body ? cJSON_GetObjectItemCaseSensitive(body, "message") : NULL;
    CHECK(cJSON_IsString(msg) && strcmp(msg->valuestring, payload) == 0,
          "the chain body's message is the same text as the signed observation");
    if (body) cJSON_Delete(body);

    /* The longest command the socket can carry. No proposal can be filed
     * for it — its canonical form exceeds what a proposal's command hash
     * covers, a limit that predates this change — but the refusal itself
     * must still arrive whole. */
    static char maxcmd[1024];
    memset(maxcmd, 'y', sizeof(maxcmd) - 1);
    memcpy(maxcmd, "reload ", 7);
    maxcmd[sizeof(maxcmd) - 1] = '\0';
    CHECK(fx_run(fx, FX_DEV, maxcmd, NULL, (uid_t)-1, &ot, payload,
                 sizeof(payload)) == 0 && ot == VIRP_OBS_ERROR,
          "a 1023-byte RED command is refused");
    plen = strlen(payload);
    CHECK(plen > sizeof(TAIL) &&
          strcmp(payload + plen - (sizeof(TAIL) - 1), TAIL) == 0,
          "and its refusal is not truncated: device and tier are intact");

    /* No proposal (BLACK): the layout is the historical one, unchanged. */
    CHECK(fx_run(fx, FX_DEV, "selfdestruct", NULL, (uid_t)-1, &ot, payload,
                 sizeof(payload)) == 0 && ot == VIRP_OBS_ERROR &&
          strncmp(payload, "ERROR: tier gate blocked 'selfdestruct' on '",
                  44) == 0 && strstr(payload, "proposal_id=") == NULL,
          "a BLACK refusal files no proposal and keeps the old layout");
    fx_destroy(fx);
}

/* =========================================================================
 * M14 — bounded client I/O and a per-uid share of the worker pool
 * ========================================================================= */

static int64_t m14_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

typedef struct { int fd; int bytes; int gap_ms; } m14_drip_t;

/* Send one byte every gap_ms — each well inside a per-read timeout. */
static void *m14_drip(void *arg)
{
    m14_drip_t *d = arg;
    for (int i = 0; i < d->bytes; i++) {
        struct timespec gap = { 0, (long)d->gap_ms * 1000000L };
        nanosleep(&gap, NULL);
        if (send(d->fd, "x", 1, MSG_NOSIGNAL) != 1) break;
    }
    return NULL;
}

static void t_M14_request_deadline_is_absolute(void)
{
    printf("\n  M14: a slow sender cannot hold a worker past the request deadline\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m14-recv")) { CHECK(false, "fixture"); return; }
    fx->st.request_deadline_ms = 400;

    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    /* Declare a 200-byte frame, then drip it at 10 bytes a second: every
     * byte arrives long before any per-read timeout, and the frame would
     * take 20 seconds to complete. */
    uint32_t n = htonl(200);
    uint8_t ver = VIRP_FRAME_VERSION;
    CHECK(send(sv[0], &n, 4, 0) == 4 && send(sv[0], &ver, 1, 0) == 1,
          "frame header sent");
    m14_drip_t drip = { sv[0], 199, 100 };
    pthread_t t;
    CHECK(pthread_create(&t, NULL, m14_drip, &drip) == 0, "slow sender started");

    int64_t t0 = m14_now_ms();
    handle_client(&fx->st, sv[1], getuid());
    int64_t took = m14_now_ms() - t0;
    CHECK(took >= 350 && took < 2000,
          "handle_client gave up at the request deadline, not at end of frame");
    printf("      (returned after %lld ms; the frame needed ~20000)\n",
           (long long)took);

    shutdown(sv[0], SHUT_RDWR);        /* stop the sender */
    pthread_join(t, NULL);
    close(sv[0]);
    fx_destroy(fx);
}

static void t_M14_send_timeout_abandons_a_stalled_reader(void)
{
    printf("\n  M14: a peer that stops reading its response is abandoned\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m14-send")) { CHECK(false, "fixture"); return; }
    fx->st.send_timeout_ms = 300;

    /* A large list_devices answer: many refused config entries with long
     * reasons make the listing tens of kilobytes. */
    char reason[128];
    memset(reason, 'r', sizeof(reason) - 1);
    reason[sizeof(reason) - 1] = '\0';
    for (int i = 0; i < ONODE_MAX_DEVICES; i++)
        onode_note_rejected(&fx->st, "refused-device-name", "10.255.9.9",
                            VIRP_VENDOR_MOCK, reason);

    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    int small = 2048;                  /* the kernel's floor is a few KiB */
    setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
    const char *req = "{\"action\":\"list_devices\"}";
    uint32_t n = htonl((uint32_t)strlen(req) + 1);
    uint8_t ver = VIRP_FRAME_VERSION;
    CHECK(send(sv[0], &n, 4, 0) == 4 && send(sv[0], &ver, 1, 0) == 1 &&
          send(sv[0], req, strlen(req), 0) == (ssize_t)strlen(req),
          "request sent; the client now never reads");

    int64_t t0 = m14_now_ms();
    handle_client(&fx->st, sv[1], getuid());   /* pre-fix: blocks forever */
    int64_t took = m14_now_ms() - t0;
    CHECK(took >= 250 && took < 3000,
          "the worker returned once the send timeout expired");
    printf("      (returned after %lld ms)\n", (long long)took);
    close(sv[0]);
    fx_destroy(fx);
}

static void t_M14_per_uid_worker_cap(void)
{
    printf("\n  M14: no single uid can take the whole worker pool\n");
    static onode_state_t st;
    CHECK(onode_init(&st, 1, NULL, "/tmp/virp-review-unused.sock") == VIRP_OK,
          "state initialised");
    CHECK(ONODE_MAX_WORKERS_PER_UID < ONODE_MAX_WORKERS,
          "the per-uid cap is below the pool size");

    int got = 0;
    for (int i = 0; i < ONODE_MAX_WORKERS; i++)
        if (onode_worker_admit(&st, 5001)) got++;
    CHECK(got == ONODE_MAX_WORKERS_PER_UID,
          "one uid is admitted up to the cap and no further");
    CHECK(onode_worker_admit(&st, 5002),
          "a different uid is still admitted while the first is at its cap");
    CHECK(st.workers_rejected_uid_cap ==
              (uint32_t)(ONODE_MAX_WORKERS - ONODE_MAX_WORKERS_PER_UID),
          "every refusal was counted");

    onode_worker_release(&st, 5001);
    CHECK(onode_worker_admit(&st, 5001) && !onode_worker_admit(&st, 5001),
          "releasing one worker frees exactly one admission");

    /* Returning everything empties the table for other uids to use. */
    for (int i = 0; i < ONODE_MAX_WORKERS_PER_UID; i++)
        onode_worker_release(&st, 5001);
    onode_worker_release(&st, 5002);
    int distinct = 0;
    for (uid_t u = 6000; u < 6000 + ONODE_MAX_WORKERS; u++)
        if (onode_worker_admit(&st, u)) distinct++;
    CHECK(distinct == ONODE_MAX_WORKERS,
          "a full pool of distinct uids fits (released slots are reused)");
    onode_destroy(&st);
}

/* =========================================================================
 * M15 — chain_verify is bounded per request and per uid
 * ========================================================================= */

static const char *m15_verify(const char *session, long long from, long long to)
{
    static char req[256];
    snprintf(req, sizeof(req),
             "{\"action\":\"chain_verify\",\"session_id\":\"%s\","
             "\"from_sequence\":\"%lld\",\"to_sequence\":\"%lld\"}",
             session, from, to);
    return req;
}

static void t_M15_verify_range_is_capped(void)
{
    printf("\n  M15: one chain_verify request covers a bounded range\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m15-range")) { CHECK(false, "fixture"); return; }
    onode_state_t *st = &fx->st;
    uid_t me = getuid();
    uint8_t ot;
    char payload[1024];
    CHECK(fx_run(fx, FX_DEV, "show version", NULL, me, &ot, payload,
                 sizeof(payload)) == 0, "a session exists to verify");
    const char *S = "gate-enforce:" FX_DEV;

    CHECK(fx_ask(st, me, m15_verify(S, 0, 1)) == VIRP_OK,
          "a small range is verified");
    CHECK(fx_ask(st, me, m15_verify(S, 0, ONODE_CHAIN_VERIFY_MAX_RANGE - 1))
              == VIRP_OK, "a range of exactly the cap is accepted");
    CHECK(fx_ask(st, me, m15_verify(S, 0, ONODE_CHAIN_VERIFY_MAX_RANGE))
              == VIRP_ERR_MESSAGE_TOO_LARGE,
          "one entry more than the cap is refused");
    CHECK(fx_ask(st, me, m15_verify(S, 0, INT64_MAX))
              == VIRP_ERR_MESSAGE_TOO_LARGE,
          "to_sequence = INT64_MAX is refused, not walked");
    CHECK(fx_ask(st, me, m15_verify(S, INT64_MAX - 5, INT64_MAX)) == VIRP_OK,
          "a small range at the top of the number space is not confused for a huge one");
    CHECK(fx_ask(st, me, "{\"action\":\"chain_verify_session\","
                         "\"session_id\":\"gate-enforce:" FX_DEV "\"}")
              == VIRP_OK,
          "chain_verify_session (no range) is still answered");
    fx_destroy(fx);
}

static void t_M15_verify_is_rate_limited_per_uid(void)
{
    printf("\n  M15: verify time is budgeted per uid\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m15-rate")) { CHECK(false, "fixture"); return; }
    onode_state_t *st = &fx->st;
    const int64_t T = 1000000;                 /* an arbitrary monotonic ms */
    const int64_t WINDOW = (int64_t)ONODE_VERIFY_WINDOW_SEC * 1000;

    CHECK(onode_verify_enter(st, 7001, T), "a first verify is admitted");
    CHECK(!onode_verify_enter(st, 7001, T + 1),
          "a second while it is in flight is refused");
    CHECK(onode_verify_enter(st, 7002, T + 1),
          "another uid is unaffected");
    onode_verify_leave(st, 7001, 100);
    onode_verify_leave(st, 7002, 100);
    CHECK(onode_verify_enter(st, 7001, T + 200), "admitted again once it finished");

    /* Spend the whole budget. */
    onode_verify_leave(st, 7001, ONODE_VERIFY_BUDGET_MS);
    CHECK(!onode_verify_enter(st, 7001, T + 300),
          "with the window's budget spent, further verifies are refused");
    CHECK(onode_verify_enter(st, 7002, T + 300),
          "that does not touch another uid's budget");
    onode_verify_leave(st, 7002, 1);
    CHECK(!onode_verify_enter(st, 7001, T + WINDOW - 1),
          "still refused just before the window ends");
    CHECK(onode_verify_enter(st, 7001, T + WINDOW + 1),
          "a new window restores the budget");
    onode_verify_leave(st, 7001, 1);

    /* And the socket path actually asks. */
    uid_t me = getuid();
    CHECK(fx_ask(st, me, "{\"action\":\"chain_verify_session\","
                         "\"session_id\":\"s\"}") != VIRP_ERR_RATE_LIMITED,
          "a uid inside its budget is not rate limited");
    int64_t now = onode_monotonic_ms();
    CHECK(onode_verify_enter(st, me, now), "(budget consumed for this uid)");
    onode_verify_leave(st, me, ONODE_VERIFY_BUDGET_MS);
    CHECK(fx_ask(st, me, "{\"action\":\"chain_verify_session\","
                         "\"session_id\":\"s\"}") == VIRP_ERR_RATE_LIMITED,
          "chain_verify_session over budget answers RATE_LIMITED");
    CHECK(fx_ask(st, me, m15_verify("s", 0, 1)) == VIRP_ERR_RATE_LIMITED,
          "chain_verify over budget answers RATE_LIMITED");
    CHECK(strcmp(virp_error_str(VIRP_ERR_RATE_LIMITED), "Unknown error") != 0,
          "the new code has its own error text");
    fx_destroy(fx);
}

/* =========================================================================
 * M16 — one open proposal per (device, command, proposer); bounded per uid
 * ========================================================================= */

static int m16_count_proposals(const fx_t *fx)
{
    char cmd[400];
    snprintf(cmd, sizeof(cmd), "ls -1 %s/proposals 2>/dev/null | wc -l", fx->dir);
    FILE *p = popen(cmd, "r");
    int n = -1;
    if (p) { if (fscanf(p, "%d", &n) != 1) n = -1; pclose(p); }
    return n;
}

/* Refuse `cmd` as `uid`; returns the proposal id in the refusal ("" if
 * the refusal carried none). */
static const char *m16_refuse(fx_t *fx, const char *cmd, uid_t uid)
{
    static char pid[VIRP_APPROVAL_ID_HEX_LEN + 1];
    static char payload[2048];
    uint8_t ot = 0;
    pid[0] = '\0';
    if (fx_run(fx, FX_DEV, cmd, NULL, uid, &ot, payload, sizeof(payload)) != 0 ||
        ot != VIRP_OBS_ERROR)
        return "!";
    (void)fx_extract_pid(payload, pid);
    return pid;
}

static void t_M16_open_proposals_are_deduplicated(void)
{
    printf("\n  M16: repeating a refused command does not file another proposal\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m16-dedupe")) { CHECK(false, "fixture"); return; }
    const uid_t A = 4301, B = 4302;
    char first[33], again[33], other_uid[33], other_cmd[33], ws[33];

    snprintf(first, sizeof(first), "%s", m16_refuse(fx, "reload", A));
    CHECK(strlen(first) == 32, "the first refusal files a proposal");
    int chain0 = fx_session_entries(fx, "approval:" FX_DEV);
    for (int i = 0; i < 5; i++)
        snprintf(again, sizeof(again), "%s", m16_refuse(fx, "reload", A));
    CHECK(strcmp(first, again) == 0,
          "five repeats are answered with the SAME proposal id");
    CHECK(m16_count_proposals(fx) == 1 &&
          fx_session_entries(fx, "approval:" FX_DEV) == chain0,
          "and filed no further record or PROPOSAL chain entry");

    /* Whitespace does not make it a different command: the proposal's
     * hash is over the canonical form. */
    snprintf(ws, sizeof(ws), "%s", m16_refuse(fx, "reload  ", A));
    CHECK(strcmp(first, ws) == 0,
          "a whitespace variant with the same command hash is the same proposal");

    snprintf(other_uid, sizeof(other_uid), "%s", m16_refuse(fx, "reload", B));
    CHECK(strlen(other_uid) == 32 && strcmp(first, other_uid) != 0,
          "a different proposer gets a proposal of its own");
    snprintf(other_cmd, sizeof(other_cmd), "%s", m16_refuse(fx, "erase flash", A));
    CHECK(strlen(other_cmd) == 32 && strcmp(first, other_cmd) != 0,
          "a different command gets a proposal of its own");
    CHECK(m16_count_proposals(fx) == 3, "three distinct proposals on record");

    /* Once approved the proposal is no longer open: a new refusal of the
     * same command needs — and gets — a new proposal. */
    virp_approval_rec_t apr;
    CHECK(fx_approve(fx, first, &apr) == VIRP_OK, "the first proposal is approved");
    snprintf(again, sizeof(again), "%s", m16_refuse(fx, "reload", A));
    CHECK(strlen(again) == 32 && strcmp(first, again) != 0,
          "after approval, the same refusal files a NEW proposal");
    fx_destroy(fx);
}

static void t_M16_proposals_are_rate_limited_per_uid(void)
{
    printf("\n  M16: new proposals per uid are bounded per window\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m16-rate")) { CHECK(false, "fixture"); return; }
    const uid_t A = 4311, B = 4312;
    char cmd[64];

    int filed = 0, without = 0;
    for (int i = 0; i < ONODE_PROPOSAL_BURST + 5; i++) {
        snprintf(cmd, sizeof(cmd), "reload in %d", i + 1);   /* distinct, RED */
        const char *pid = m16_refuse(fx, cmd, A);
        if (strlen(pid) == 32) filed++;
        else if (pid[0] == '\0') without++;
    }
    CHECK(filed == ONODE_PROPOSAL_BURST && without == 5,
          "one uid files up to the burst; further refusals carry no proposal id");
    CHECK(m16_count_proposals(fx) == ONODE_PROPOSAL_BURST,
          "and no record was written past the limit");
    CHECK(fx_rejections(fx, "gate-enforce:" FX_DEV, NULL, NULL)
              == ONODE_PROPOSAL_BURST + 5,
          "every refusal — limited or not — is still on the chain");

    CHECK(strlen(m16_refuse(fx, "reload in 999", B)) == 32,
          "another uid still files");
    CHECK(strlen(m16_refuse(fx, "reload in 3", A)) == 32,
          "an already-open proposal is still handed back to the limited uid");

    /* The window turning over restores the allowance. */
    pthread_mutex_lock(&fx->st.proposal_mutex);
    for (int i = 0; i < ONODE_MAX_WORKERS; i++)
        if (fx->st.proposal_uid[i].in_use && fx->st.proposal_uid[i].uid == A)
            fx->st.proposal_uid[i].window_start_ms -=
                (int64_t)ONODE_PROPOSAL_WINDOW_SEC * 1000 + 1;
    pthread_mutex_unlock(&fx->st.proposal_mutex);
    CHECK(strlen(m16_refuse(fx, "reload in 1000", A)) == 32,
          "after the window, the uid files again");

    /* The internal caller is not a socket principal. */
    int internal = 0;
    for (int i = 0; i < ONODE_PROPOSAL_BURST + 3; i++) {
        snprintf(cmd, sizeof(cmd), "erase %d", i + 1);
        if (strlen(m16_refuse(fx, cmd, (uid_t)-1)) == 32) internal++;
    }
    CHECK(internal == ONODE_PROPOSAL_BURST + 3,
          "the internal caller is not rate limited");
    fx_destroy(fx);
}

/* =========================================================================
 * M17 — a batch item whose thread could not be created is an error
 * ========================================================================= */

static void t_M17_batch_thread_create_failure(void)
{
    printf("\n  M17: a batch item with no worker thread is reported as an error\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m17-batch")) { CHECK(false, "fixture"); return; }
    static uint8_t resp[4 * VIRP_MAX_MESSAGE_SIZE];
    const char *req =
        "{\"action\":\"batch_execute\",\"commands\":["
        "{\"device\":\"" FX_DEV "\",\"command\":\"show version\"},"
        "{\"device\":\"" FX_DEV "\",\"command\":\"show inventory\"},"
        "{\"device\":\"" FX_DEV "\",\"command\":\"show clock\"}]}";

    (void)virp_driver_mock_exec_attempts_reset();
    review_fail_create_in = 2;                 /* the SECOND item's thread */
    ssize_t n = fx_request(&fx->st, getuid(), req, resp, sizeof(resp));
    review_fail_create_in = 0;
    CHECK(n > 4, "the batch is answered");

    /* count, then per item: BE32 length + bytes. */
    uint32_t count = 0, len[3] = { 0, 0, 0 };
    const uint8_t *item[3] = { NULL, NULL, NULL };
    bool framed = n > 4;
    if (framed) {
        memcpy(&count, resp, 4);
        count = ntohl(count);
        size_t off = 4;
        for (uint32_t i = 0; framed && i < count && i < 3; i++) {
            if (off + 4 > (size_t)n) { framed = false; break; }
            memcpy(&len[i], resp + off, 4);
            len[i] = ntohl(len[i]);
            off += 4;
            if (off + len[i] > (size_t)n) { framed = false; break; }
            item[i] = resp + off;
            off += len[i];
        }
    }
    CHECK(framed && count == 3, "three items come back, well framed");
    if (framed && count == 3) {
        uint32_t code = 0;
        if (len[1] == 4) { memcpy(&code, item[1], 4); code = ntohl(code); }
        CHECK(len[1] == 4 && (int32_t)code == (int32_t)VIRP_ERR_RATE_LIMITED,
              "the item with no thread carries a real error, not code 0");
        virp_header_t hdr;
        CHECK(len[0] > 4 && len[2] > 4 &&
              virp_validate_message(item[0], len[0], &fx->st.okey, &hdr) == VIRP_OK &&
              virp_validate_message(item[2], len[2], &fx->st.okey, &hdr) == VIRP_OK,
              "its neighbours ran and returned signed observations");
    }
    CHECK(virp_driver_mock_exec_attempts_reset() == 2,
          "exactly the two items that got a thread were dispatched");
    fx_destroy(fx);
}

/* ---- a real listening daemon, for what only the accept loop decides ---- */

static void *fx_server_thread(void *arg)
{
    (void)onode_start((onode_state_t *)arg);
    return NULL;
}

static int fx_connect(const onode_state_t *st)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof(a.sun_path), "%s", st->socket_path);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static bool fx_server_start(fx_t *fx, pthread_t *thread)
{
    if (pthread_create(thread, NULL, fx_server_thread, &fx->st) != 0)
        return false;
    for (int i = 0; i < 300; i++) {
        if (access(fx->st.socket_path, F_OK) == 0 && fx->st.running)
            return true;
        struct timespec p = { 0, 10 * 1000000L };
        nanosleep(&p, NULL);
    }
    return false;
}

/* Ask the daemon to stop and wait for onode_start() to return. The extra
 * connect only matters to a daemon whose accept loop has no shutdown wake
 * of its own; it is harmless otherwise. */
static void fx_server_stop(fx_t *fx, pthread_t thread)
{
    onode_shutdown(&fx->st);
    int wake = fx_connect(&fx->st);
    if (wake >= 0) close(wake);
    pthread_join(thread, NULL);
}

/* true iff the peer closed this connection within wait_ms. */
static bool fx_peer_closed(int fd, int wait_ms)
{
    struct pollfd p = { .fd = fd, .events = POLLIN, .revents = 0 };
    if (poll(&p, 1, wait_ms) <= 0) return false;
    char c;
    return recv(fd, &c, 1, MSG_DONTWAIT) == 0;
}

static void t_M14_accept_loop_enforces_per_uid_cap(void)
{
    printf("\n  M14: the accept loop closes a uid's connection over its cap\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m14-accept")) { CHECK(false, "fixture"); return; }
    fx->st.request_deadline_ms = 4000;      /* idle connections are held */
    pthread_t srv;
    if (!fx_server_start(fx, &srv)) { CHECK(false, "server start"); return; }

    int held[ONODE_MAX_WORKERS_PER_UID];
    int ok = 0;
    for (int i = 0; i < ONODE_MAX_WORKERS_PER_UID; i++) {
        held[i] = fx_connect(&fx->st);
        if (held[i] >= 0) ok++;
    }
    CHECK(ok == ONODE_MAX_WORKERS_PER_UID, "a full per-uid share of connections opened");

    int over = fx_connect(&fx->st);
    CHECK(over >= 0 && fx_peer_closed(over, 1500),
          "one more connection from the same uid is closed at accept");
    bool others_alive = true;
    for (int i = 0; i < ONODE_MAX_WORKERS_PER_UID; i++)
        if (held[i] >= 0 && fx_peer_closed(held[i], 0)) others_alive = false;
    CHECK(others_alive, "the connections inside the cap are still being served");

    /* Give one back: the next connection is admitted again. */
    close(held[0]);
    held[0] = -1;
    int again = -1;
    bool admitted = false;
    for (int tries = 0; tries < 50 && !admitted; tries++) {
        struct timespec p = { 0, 20 * 1000000L };
        nanosleep(&p, NULL);
        again = fx_connect(&fx->st);
        if (again < 0) continue;
        if (!fx_peer_closed(again, 150)) admitted = true;
        else { close(again); again = -1; }
    }
    CHECK(admitted, "after one worker finishes, the uid is admitted again");

    if (over >= 0) close(over);
    if (again >= 0) close(again);
    for (int i = 0; i < ONODE_MAX_WORKERS_PER_UID; i++)
        if (held[i] >= 0) close(held[i]);
    fx_server_stop(fx, srv);
    fx_destroy(fx);
}

/* =========================================================================
 * M18 — shutdown is prompt, signal-safe, and acknowledged
 * ========================================================================= */

static double m18_join_seconds(pthread_t t)
{
    int64_t t0 = m14_now_ms();
    pthread_join(t, NULL);
    return (double)(m14_now_ms() - t0) / 1000.0;
}

static void m18_sig_handler(int sig)
{
    (void)sig;
    onode_shutdown(&g_fx.st);       /* exactly what both mains' handlers do */
}

static void t_M18_shutdown_wakes_the_accept_loop(void)
{
    printf("\n  M18: onode_shutdown() wakes the accept loop at once\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m18-wake")) { CHECK(false, "fixture"); return; }
    pthread_t srv;
    if (!fx_server_start(fx, &srv)) { CHECK(false, "server start"); return; }

    /* No connection, no signal: nothing else can wake select(), whose
     * timeout is the 30 s heartbeat. */
    onode_shutdown(&fx->st);
    double took = m18_join_seconds(srv);
    CHECK(took < 3.0, "onode_start() returned promptly, not at the next heartbeat tick");
    printf("      (loop exited %.2f s after onode_shutdown)\n", took);
    CHECK(!atomic_load(&fx->st.running) &&
          atomic_load(&fx->st.shutdown_requested),
          "running is cleared and the request is latched");
    fx_destroy(fx);
}

static void t_M18_shutdown_from_signal_handler(void)
{
    printf("\n  M18: a handler that only calls onode_shutdown() stops the daemon\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m18-signal")) { CHECK(false, "fixture"); return; }
    pthread_t srv;
    if (!fx_server_start(fx, &srv)) { CHECK(false, "server start"); return; }

    struct sigaction sa, old;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = m18_sig_handler;
    sigemptyset(&sa.sa_mask);
    CHECK(sigaction(SIGUSR1, &sa, &old) == 0, "handler installed");
    errno = EXDEV;
    raise(SIGUSR1);                 /* delivered on THIS thread, not the loop's */
    CHECK(errno == EXDEV, "onode_shutdown() preserved errno across the handler");
    double took = m18_join_seconds(srv);
    CHECK(took < 3.0, "the accept loop on another thread woke and returned");
    sigaction(SIGUSR1, &old, NULL);
    fx_destroy(fx);
}

static void t_M18_shutdown_before_start_is_not_lost(void)
{
    printf("\n  M18: a shutdown requested during startup is honoured\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m18-early")) { CHECK(false, "fixture"); return; }
    onode_shutdown(&fx->st);        /* e.g. SIGTERM before the loop exists */
    pthread_t srv;
    CHECK(pthread_create(&srv, NULL, fx_server_thread, &fx->st) == 0,
          "onode_start() called after the request");
    double took = m18_join_seconds(srv);
    CHECK(took < 3.0, "onode_start() returned without serving");
    fx_destroy(fx);
}

static void t_M18_shutdown_action_is_acknowledged(void)
{
    printf("\n  M18: the shutdown action is acknowledged and takes effect at once\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m18-action")) { CHECK(false, "fixture"); return; }
    pthread_t srv;
    if (!fx_server_start(fx, &srv)) { CHECK(false, "server start"); return; }

    int fd = fx_connect(&fx->st);
    const char *req = "{\"action\":\"shutdown\"}";
    uint32_t n = htonl((uint32_t)strlen(req) + 1);
    uint8_t ver = VIRP_FRAME_VERSION;
    CHECK(fd >= 0 && send(fd, &n, 4, 0) == 4 && send(fd, &ver, 1, 0) == 1 &&
          send(fd, req, strlen(req), 0) == (ssize_t)strlen(req),
          "shutdown requested over the socket");
    char ack[128] = "";
    uint32_t alen = 0;
    bool got = recv(fd, &alen, 4, MSG_WAITALL) == 4;
    alen = ntohl(alen);
    got = got && alen > 0 && alen < sizeof(ack) &&
          recv(fd, ack, alen, MSG_WAITALL) == (ssize_t)alen;
    CHECK(got && strcmp(ack, "{\"status\":\"shutting_down\"}") == 0,
          "the caller receives a framed acknowledgement, not a bare EOF");
    if (fd >= 0) close(fd);
    double took = m18_join_seconds(srv);
    CHECK(took < 3.0, "and the daemon stops without waiting for a heartbeat tick");
    fx_destroy(fx);
}

/* =========================================================================
 * M19 — the session belongs to the uid that bound it
 * ========================================================================= */

static void m19_case(const char *name, int obs_version, bool v3)
{
    fx_t *fx = &g_fx;
    sqlite3 *db = NULL;
    if (!h4_init(fx, name, &db, "autonomous")) {
        CHECK(false, "fixture (needs a plain build, without LINUX=1)");
        return;
    }
    virp_policy_close(fx->st.policy);
    fx->st.policy = NULL;
    onode_state_t *st = &fx->st;
    const uid_t A = 4401, B = 4402;
    uint8_t ot = 0;
    char payload[1024];

    if (v3) {
        char kpath[200], ppath[200];
        snprintf(kpath, sizeof(kpath), "%s/%s/obs-sign.key", g_root, name);
        snprintf(ppath, sizeof(ppath), "%s/%s/obs-sign.pub", g_root, name);
        CHECK(virp_obskey_generate(&st->obskey) == VIRP_OK &&
              virp_obskey_save(&st->obskey, kpath, ppath) == VIRP_OK &&
              virp_chain_enable_signing(&st->chain, kpath) == VIRP_OK,
              "(v3 signing key loaded)");
        st->obskey_loaded = true;
    }

    CHECK(m12_bind_session(fx, A), "uid A binds a session");
    CHECK(m12_run(fx, obs_version, A, &ot, payload, sizeof(payload)) == VIRP_OK &&
          h4_dispatches == 1, "A's session-bound execute runs");

    CHECK(m12_run(fx, obs_version, B, &ot, payload, sizeof(payload))
              == VIRP_ERR_SESSION_INVALID && h4_dispatches == 1,
          "uid B's execute is refused before dispatch: B has no session");
    CHECK(fx_ask(st, B, "{\"action\":\"session_close\"}")
              == VIRP_ERR_ACTION_FORBIDDEN,
          "uid B may not close A's session");
    CHECK(m12_run(fx, obs_version, A, &ot, payload, sizeof(payload)) == VIRP_OK &&
          h4_dispatches == 2, "A's session survived B's close attempt");

    CHECK(fx_ask(st, A, "{\"action\":\"session_close\"}") == VIRP_OK,
          "A closes its own session");
    CHECK(m12_run(fx, obs_version, A, &ot, payload, sizeof(payload))
              == VIRP_ERR_SESSION_INVALID && h4_dispatches == 2,
          "after closing, A has no session either");

    /* The session is free: B binds and now B is the owner. */
    CHECK(m12_bind_session(fx, B), "uid B binds a new session");
    CHECK(m12_run(fx, obs_version, B, &ot, payload, sizeof(payload)) == VIRP_OK &&
          h4_dispatches == 3, "B's session-bound execute runs");
    CHECK(m12_run(fx, obs_version, A, &ot, payload, sizeof(payload))
              == VIRP_ERR_SESSION_INVALID && h4_dispatches == 3,
          "and now it is A that is refused");

    /* Closing a session that is not active stays the harmless reset it
     * was, whoever asks. */
    CHECK(fx_ask(st, B, "{\"action\":\"session_close\"}") == VIRP_OK &&
          fx_ask(st, A, "{\"action\":\"session_close\"}") == VIRP_OK,
          "closing an already-closed session is not refused");

    fx_destroy(fx);
    sqlite3_close(db);
}

static void t_M19_v2_session_is_owned_by_binding_uid(void)
{
    printf("\n  M19 (v2): only the binding uid may use or close the session\n");
    m19_case("m19-v2", 2, false);
}

static void t_M19_v3_session_is_owned_by_binding_uid(void)
{
    printf("\n  M19 (v3): only the binding uid may use or close the session\n");
    m19_case("m19-v3", 3, true);
}

/* =========================================================================
 * M20 — one daemon per socket, and a v1 sequence that never restarts
 * ========================================================================= */

static void t_M20_second_instance_refuses_to_start(void)
{
    printf("\n  M20: a second daemon on the same socket refuses to start\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "m20-lock")) { CHECK(false, "fixture"); return; }
    pthread_t srv;
    if (!fx_server_start(fx, &srv)) { CHECK(false, "server start"); return; }

    static onode_state_t second;
    CHECK(onode_init(&second, 0x5EC00002, NULL, fx->st.socket_path) == VIRP_OK,
          "a second daemon state for the SAME socket path");
    int64_t t0 = m14_now_ms();
    virp_error_t e = onode_start(&second);   /* pre-fix: steals the socket and serves */
    CHECK(e != VIRP_OK && m14_now_ms() - t0 < 2000,
          "its onode_start() refuses, immediately");
    onode_destroy(&second);

    /* The first daemon's socket was not unlinked, and it still answers. */
    CHECK(access(fx->st.socket_path, F_OK) == 0,
          "the running daemon's socket is still there");
    int fd = fx_connect(&fx->st);
    const char *req = "{\"action\":\"heartbeat\"}";
    uint32_t n = htonl((uint32_t)strlen(req) + 1);
    uint8_t ver = VIRP_FRAME_VERSION;
    uint32_t rlen = 0;
    CHECK(fd >= 0 && send(fd, &n, 4, 0) == 4 && send(fd, &ver, 1, 0) == 1 &&
          send(fd, req, strlen(req), 0) == (ssize_t)strlen(req) &&
          recv(fd, &rlen, 4, MSG_WAITALL) == 4 && ntohl(rlen) > 4,
          "and it is still the one answering requests");
    if (fd >= 0) close(fd);

    /* The lock is held until the first daemon is torn down, not merely
     * until its loop exits — so stop AND destroy it, then try again. */
    char path[sizeof(fx->st.socket_path)];
    memcpy(path, fx->st.socket_path, sizeof(path));
    fx_server_stop(fx, srv);
    fx_destroy(fx);

    CHECK(onode_init(&second, 0x5EC00002, NULL, path) == VIRP_OK,
          "(the first daemon is gone)");
    /* An action entry for our own uid, so that the allowlist the first
     * start seeds is still acceptable to the restart below (a seeded
     * allowlist reads as an explicit one the second time round). */
    const onode_action_t hb_only[1] = { ONODE_ACTION_HEARTBEAT };
    CHECK(onode_set_uid_actions(&second, getuid(), hb_only, 1) == VIRP_OK,
          "(action entry for this uid)");
    onode_shutdown(&second);                 /* so start returns at once */
    CHECK(onode_start(&second) == VIRP_OK,
          "with the lock released, a new daemon may take the socket");
    /* The same state started again without being destroyed in between
     * already holds the lock, and must not be locked out by itself. */
    CHECK(onode_start(&second) == VIRP_OK,
          "a state restarted without teardown is not refused by its own lock");
    onode_destroy(&second);
}

static void t_M20_v1_sequence_survives_restart(void)
{
    printf("\n  M20: the v1 sequence high-water is persisted\n");
    char path[160];
    snprintf(path, sizeof(path), "%s/m20.v1seq", g_root);
    static onode_state_t st;

    /* First run. */
    CHECK(onode_init(&st, 1, NULL, "/tmp/virp-review-unused.sock") == VIRP_OK &&
          onode_set_seq_store(&st, path) == VIRP_OK, "first run: store created");
    uint32_t last = 0;
    for (int i = 0; i < 5; i++) last = onode_next_seq(&st);
    CHECK(last == 5, "the sequence starts at 1 on a first run");

    /* CRASH: no onode_destroy, the state is simply abandoned. */
    static onode_state_t crashed_then_restarted;
    CHECK(onode_init(&crashed_then_restarted, 1, NULL,
                     "/tmp/virp-review-unused.sock") == VIRP_OK &&
          onode_set_seq_store(&crashed_then_restarted, path) == VIRP_OK,
          "restart after a crash: store loaded");
    uint32_t after_crash = onode_next_seq(&crashed_then_restarted);
    CHECK(after_crash > last,
          "after a crash the next number is above every number issued before");
    printf("      (issued up to %u, resumed at %u)\n", last, after_crash);

    /* Cross a reservation boundary: every number stays covered on disk. */
    uint32_t hi = after_crash;
    for (unsigned i = 0; i < ONODE_SEQ_RESERVE_BLOCK + 10; i++)
        hi = onode_next_seq(&crashed_then_restarted);
    CHECK(crashed_then_restarted.seq_reserved >= hi &&
          !crashed_then_restarted.seq_store_failed,
          "the durable reservation is extended before numbers pass it");

    /* CLEAN shutdown records the exact high-water: no gap next time. */
    onode_destroy(&crashed_then_restarted);
    CHECK(onode_init(&st, 1, NULL, "/tmp/virp-review-unused.sock") == VIRP_OK &&
          onode_set_seq_store(&st, path) == VIRP_OK, "restart after a clean stop");
    CHECK(onode_next_seq(&st) == hi + 1,
          "after a clean shutdown the sequence continues exactly, with no gap");
    onode_destroy(&st);

    /* A store that is not a number is refused, not read as zero. */
    FILE *f = fopen(path, "w");
    if (f) { fputs("12abc\n", f); fclose(f); }
    CHECK(onode_init(&st, 1, NULL, "/tmp/virp-review-unused.sock") == VIRP_OK &&
          onode_set_seq_store(&st, path) != VIRP_OK && st.seq_num == 0 &&
          st.seq_store_path[0] == '\0',
          "a corrupt store is an error, not a silent restart at zero");
    onode_destroy(&st);

    /* An unwritable location is an error at setup. */
    CHECK(onode_init(&st, 1, NULL, "/tmp/virp-review-unused.sock") == VIRP_OK &&
          onode_set_seq_store(&st, "/nonexistent-dir-for-review/x.v1seq") != VIRP_OK,
          "a store that cannot be written is refused at setup");
    onode_destroy(&st);
}

/* =========================================================================
 * M21 — the observation key is its own key
 * ========================================================================= */

static void t_M21_v3_with_separate_observation_key(void)
{
    printf("\n  M21: v3 execute works when the observation key is NOT the chain-signing key\n");
    fx_t *fx = &g_fx;
    sqlite3 *db = NULL;
    if (!h4_init(fx, "m21-keys", &db, "autonomous")) {
        CHECK(false, "fixture (needs a plain build, without LINUX=1)");
        return;
    }
    virp_policy_close(fx->st.policy);
    fx->st.policy = NULL;
    onode_state_t *st = &fx->st;
    uid_t me = getuid();

    /* Chain-signing key: one keypair. */
    virp_obskey_t chain_key;
    char kpath[200], ppath[200];
    snprintf(kpath, sizeof(kpath), "%s/m21-keys/chain-sign.key", g_root);
    snprintf(ppath, sizeof(ppath), "%s/m21-keys/chain-sign.pub", g_root);
    CHECK(virp_obskey_generate(&chain_key) == VIRP_OK &&
          virp_obskey_save(&chain_key, kpath, ppath) == VIRP_OK &&
          virp_chain_enable_signing(&st->chain, kpath) == VIRP_OK,
          "chain signing enabled with one key");
    /* Observation key: a DIFFERENT keypair. */
    CHECK(virp_obskey_generate(&st->obskey) == VIRP_OK &&
          memcmp(st->obskey.public_key, chain_key.public_key, 32) != 0,
          "the observation key is a different key");
    st->obskey_loaded = true;

    CHECK(m12_bind_session(fx, me), "session bound");
    static uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = 0;
    virp_error_t err = onode_execute_obs_ex(st, H4_DEV, "uptime", 3, NULL, me,
                                            buf, sizeof(buf), &len);
    CHECK(err == VIRP_OK && len > 0 && buf[0] == VIRP_VERSION_3 &&
          h4_dispatches == 1,
          "a v3 execute is served (it used to be refused: keys had to match)");
    CHECK(err == VIRP_OK &&
          virp_verify_observation_ed25519(st->obskey.public_key, buf, len,
                                          NULL, NULL, NULL) == VIRP_OK,
          "the observation verifies under the OBSERVATION key");
    CHECK(err == VIRP_OK &&
          virp_verify_observation_ed25519(chain_key.public_key, buf, len,
                                          NULL, NULL, NULL) != VIRP_OK,
          "and does NOT verify under the chain-signing key");

    /* Still required: an observation key at all. */
    st->obskey_loaded = false;
    CHECK(onode_execute_obs_ex(st, H4_DEV, "uptime", 3, NULL, me, buf,
                               sizeof(buf), &len) == VIRP_ERR_KEY_NOT_LOADED &&
          h4_dispatches == 1,
          "with no observation key loaded, v3 is refused before dispatch");
    st->obskey_loaded = true;
    fx_destroy(fx);
    sqlite3_close(db);
}

/* =========================================================================
 * M22 — the device config is refused for what it does not say clearly
 * ========================================================================= */

/* Write `json` as a config file and load it into a fresh state.
 * Returns load_devices()' result (-1 = refused). */
static int cfg_load(const char *name, const char *json, onode_state_t *out)
{
    static onode_state_t scratch;
    onode_state_t *st = out ? out : &scratch;
    char path[200];
    snprintf(path, sizeof(path), "%s/%s.json", g_root, name);
    FILE *f = fopen(path, "w");
    if (!f) return -99;
    fputs(json, f);
    fclose(f);
    if (onode_init(st, 1, NULL, "/tmp/virp-review-unused.sock") != VIRP_OK)
        return -98;
    int rc = load_devices(st, path);
    if (!out) onode_destroy(st);
    return rc;
}

static void t_M22_unknown_top_level_key_is_fatal(void)
{
    printf("\n  M22: an unrecognized top-level config key refuses the config\n");
    CHECK(cfg_load("m22-plain", "{\"devices\":[]}", NULL) == 0,
          "a minimal config loads");
    CHECK(cfg_load("m22-comment",
                   "{\"_comment\":\"why\",\"_gate_note\":{\"x\":1},"
                   "\"devices\":[]}", NULL) == 0,
          "keys beginning with '_' are annotations and are accepted");
    static const char *const TYPOS[] = {
        "{\"gate_max_teir\":\"green\",\"devices\":[]}",
        "{\"evidence_requried\":true,\"devices\":[]}",
        "{\"gate_defualt_mode\":\"enforce\",\"devices\":[]}",
        "{\"socket_allowed_uid\":[7],\"devices\":[]}",
        "{\"Devices\":[],\"devices\":[]}",
        "{\"notes\":\"free text\",\"devices\":[]}",
    };
    for (size_t i = 0; i < sizeof(TYPOS) / sizeof(TYPOS[0]); i++) {
        char msg[200];
        snprintf(msg, sizeof(msg), "refused: %.70s", TYPOS[i]);
        CHECK(cfg_load("m22-typo", TYPOS[i], NULL) == -1, msg);
    }
    /* The case that mattered: a misspelled ceilings map used to leave
     * every uid at the node-wide ceiling. */
    static onode_state_t st;
    CHECK(cfg_load("m22-ceil-typo",
                   "{\"socket_allowed_uids\":[7],"
                   "\"socket_uid_tier_cielings\":{\"7\":\"green\"},"
                   "\"devices\":[]}", &st) == -1 && st.uid_ceiling_count == 0,
          "a misspelled socket_uid_tier_ceilings is refused, not ignored");
    onode_destroy(&st);
    CHECK(cfg_load("m22-notobj", "[]", NULL) == -1,
          "a config that is not a JSON object is refused");
}

static void t_M22_explicit_allowlist_requires_ceilings(void)
{
    printf("\n  M22: socket_allowed_uids without socket_uid_tier_ceilings is refused\n");
    CHECK(cfg_load("m22-noceil",
                   "{\"socket_allowed_uids\":[7,8],\"devices\":[]}", NULL) == -1,
          "an explicit allowlist with no ceilings map is refused");
    static onode_state_t st;
    CHECK(cfg_load("m22-ceil",
                   "{\"socket_allowed_uids\":[7,8],"
                   "\"socket_uid_tier_ceilings\":{\"7\":\"green\",\"8\":\"red\"},"
                   "\"devices\":[]}", &st) == 0 &&
          onode_effective_max_tier(&st, 7) == VIRP_TIER_GREEN &&
          onode_effective_max_tier(&st, 8) == VIRP_TIER_RED,
          "with a ceiling for every allowed uid it loads, and they apply");
    onode_destroy(&st);
    CHECK(cfg_load("m22-partial",
                   "{\"socket_allowed_uids\":[7,8],"
                   "\"socket_uid_tier_ceilings\":{\"7\":\"green\"},"
                   "\"devices\":[]}", NULL) == -1,
          "a map that omits an allowed uid is still refused");
    CHECK(cfg_load("m22-default", "{\"gate_max_tier\":\"green\",\"devices\":[]}",
                   NULL) == 0,
          "no allowlist at all (the self-seeded default) needs no ceilings");
}

/* The configs this repository ships must still load under the stricter
 * rules. Placeholders are substituted the way render-devices.sh would. */
static void t_M22_shipped_templates_still_load(void)
{
    printf("\n  M22: every shipped device template passes the stricter loader\n");
    static const char *const SHIPPED[] = {
        "deploy/devices.template.json", "deploy/devices.home.template.json",
        "deploy/devices.node2.template.json", "demo/devices.json",
    };
    for (size_t i = 0; i < sizeof(SHIPPED) / sizeof(SHIPPED[0]); i++) {
        static char text[512 * 1024], out[512 * 1024];
        FILE *f = fopen(SHIPPED[i], "r");
        if (!f) { CHECK(false, SHIPPED[i]); continue; }
        size_t n = fread(text, 1, sizeof(text) - 1, f);
        fclose(f);
        text[n] = '\0';
        /* ${NAME} -> 900 (a number that works as a uid, a port, a string). */
        size_t o = 0;
        for (size_t k = 0; k < n && o + 4 < sizeof(out); k++) {
            if (text[k] == '$' && text[k + 1] == '{') {
                const char *end = strchr(text + k, '}');
                if (end) {
                    memcpy(out + o, "900", 3); o += 3;
                    k = (size_t)(end - text);
                    continue;
                }
            }
            out[o++] = text[k];
        }
        out[o] = '\0';
        char msg[160];
        snprintf(msg, sizeof(msg), "%s is not refused", SHIPPED[i]);
        CHECK(cfg_load("m22-shipped", out, NULL) >= 0, msg);
    }
}

/* =========================================================================
 * M23 — a gate key the loader cannot use is fatal, not defaulted
 * ========================================================================= */

static void t_M23_gate_config_values_are_strict(void)
{
    printf("\n  M23: unusable gate_max_tier / gate_default_mode / gate_modes are fatal\n");
    static const struct { const char *json; const char *what; } BAD[] = {
        { "{\"gate_max_tier\":\"grren\",\"devices\":[]}",
          "a misspelled gate_max_tier (was: silently YELLOW)" },
        { "{\"gate_max_tier\":\"green \",\"devices\":[]}",
          "gate_max_tier with trailing space" },
        { "{\"gate_max_tier\":1,\"devices\":[]}",
          "a numeric gate_max_tier (was: silently ignored)" },
        { "{\"gate_max_tier\":\"black\",\"devices\":[]}",
          "gate_max_tier \"black\"" },
        { "{\"gate_default_mode\":\"shadoww\",\"devices\":[]}",
          "a misspelled gate_default_mode" },
        { "{\"gate_default_mode\":true,\"devices\":[]}",
          "a boolean gate_default_mode" },
        { "{\"gate_mode\":\"enforced\",\"devices\":[]}",
          "a misspelled gate_mode (deprecated alias)" },
        { "{\"gate_default_mode\":\"enforce\",\"gate_mode\":\"shadow\","
          "\"devices\":[]}",
          "gate_default_mode and gate_mode together" },
        { "{\"gate_modes\":{\"linux\":\"shdow\"},\"devices\":[]}",
          "a misspelled gate_modes value (was: ignored)" },
        { "{\"gate_modes\":{\"linux\":1},\"devices\":[]}",
          "a numeric gate_modes value (was: skipped)" },
        { "{\"gate_modes\":[\"linux\"],\"devices\":[]}",
          "gate_modes that is not an object" },
        { "{\"gate_modes\":\"shadow\",\"devices\":[]}",
          "gate_modes that is a string" },
    };
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
        char msg[160];
        snprintf(msg, sizeof(msg), "refused: %s", BAD[i].what);
        CHECK(cfg_load("m23-bad", BAD[i].json, NULL) == -1, msg);
    }

    /* More overrides than the table holds: the extras used to be dropped. */
    char many[2048];
    size_t off = (size_t)snprintf(many, sizeof(many), "{\"gate_modes\":{");
    for (int i = 0; i <= ONODE_MAX_GATE_OVERRIDES; i++)
        off += (size_t)snprintf(many + off, sizeof(many) - off,
                                "%s\"drv%d\":\"shadow\"", i ? "," : "", i);
    snprintf(many + off, sizeof(many) - off, "},\"devices\":[]}");
    CHECK(cfg_load("m23-many", many, NULL) == -1,
          "refused: more gate_modes entries than fit (was: extras dropped)");

    /* Valid values still load and take effect. */
    static onode_state_t st;
    CHECK(cfg_load("m23-ok",
                   "{\"gate_max_tier\":\"GREEN\","
                   "\"gate_default_mode\":\"shadow\","
                   "\"gate_modes\":{\"linux\":\"enforce\",\"mock\":\"shadow\"},"
                   "\"devices\":[]}", &st) == 0 &&
          st.gate_max_tier == VIRP_TIER_GREEN &&
          st.gate_default_mode == GATE_MODE_SHADOW &&
          st.gate_overrides_count == 2 &&
          gate_effective_mode(&st, "linux") == GATE_MODE_ENFORCE &&
          gate_effective_mode(&st, "juniper") == GATE_MODE_SHADOW,
          "well-formed gate keys load and apply (case-insensitive values)");
    onode_destroy(&st);
    CHECK(cfg_load("m23-alias", "{\"gate_mode\":\"shadow\",\"devices\":[]}",
                   &st) == 0 && st.gate_default_mode == GATE_MODE_SHADOW,
          "the deprecated gate_mode alias still works on its own");
    onode_destroy(&st);
}

/* =========================================================================
 * M24 — the uid keys of the per-uid policy maps are parsed as uids
 * ========================================================================= */

static void t_M24_uid_keys_are_parsed_strictly(void)
{
    printf("\n  M24: per-uid action/type maps take real uids, each once\n");
    static const char *const MAPS[] = {
        "socket_uid_action_allow", "socket_uid_chain_append_types",
    };
    static const char *const VALUE[] = { "[\"health\"]", "[\"observation\"]" };
    static const struct { const char *key; const char *what; } BAD[] = {
        { "-1",         "\"-1\" (would be the unknown-identity sentinel)" },
        { "4294967295", "\"4294967295\" ((uid_t)-1 spelled out)" },
        { "4294967303", "\"4294967303\" (wraps to uid 7)" },
        { "+7",         "\"+7\"" },
        { " 7",         "\" 7\"" },
        { "7x",         "\"7x\"" },
        { "0x7",        "\"0x7\"" },
        { "",           "an empty key" },
        { "seven",      "\"seven\" (was: logged and skipped)" },
    };
    for (int m = 0; m < 2; m++) {
        for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
            char json[256], msg[200];
            snprintf(json, sizeof(json), "{\"%s\":{\"%s\":%s},\"devices\":[]}",
                     MAPS[m], BAD[i].key, VALUE[m]);
            snprintf(msg, sizeof(msg), "%s: refused key %s", MAPS[m],
                     BAD[i].what);
            CHECK(cfg_load("m24-bad", json, NULL) == -1, msg);
        }
        char dup[256], msg[160];
        snprintf(dup, sizeof(dup),
                 "{\"%s\":{\"7\":%s,\"07\":[]},\"devices\":[]}",
                 MAPS[m], VALUE[m]);
        snprintf(msg, sizeof(msg),
                 "%s: the same uid under two keys (\"7\", \"07\") is refused",
                 MAPS[m]);
        CHECK(cfg_load("m24-dup", dup, NULL) == -1, msg);
        snprintf(dup, sizeof(dup), "{\"%s\":[7],\"devices\":[]}", MAPS[m]);
        snprintf(msg, sizeof(msg), "%s: a non-object map is refused", MAPS[m]);
        CHECK(cfg_load("m24-type", dup, NULL) == -1, msg);
    }

    static onode_state_t st;
    CHECK(cfg_load("m24-ok",
                   "{\"socket_uid_action_allow\":{\"7\":[\"health\"],"
                   "\"8\":[\"chain_append\"]},"
                   "\"socket_uid_chain_append_types\":{\"8\":[\"observation\"]},"
                   "\"devices\":[]}", &st) == 0 &&
          onode_uid_action_set_has(&st, 7, ONODE_ACTION_HEALTH) &&
          !onode_uid_action_set_has(&st, 7, ONODE_ACTION_SHUTDOWN) &&
          onode_uid_capp_type_allowed(&st, 8, "observation"),
          "well-formed maps load and apply to exactly the uids written");
    CHECK(!onode_uid_has_capp_policy(&st, (uid_t)-1) &&
          !onode_uid_action_set_has(&st, (uid_t)-1, ONODE_ACTION_HEALTH),
          "nothing was installed for the unknown-identity sentinel");
    onode_destroy(&st);
}

/* =========================================================================
 * M25 — a declared protected_vmids that comes out empty refuses the config
 * ========================================================================= */

/* One proxmox device whose protected_vmids member is `pv` (raw JSON), or
 * absent when pv is NULL. */
static const char *m25_cfg(const char *vendor, const char *pv)
{
    static char json[1024];
    int off = snprintf(json, sizeof(json),
        "{\"devices\":[{\"hostname\":\"pve-m25\",\"host\":\"10.255.7.25\","
        "\"vendor\":\"%s\",\"node_id\":\"0A0000FD\"", vendor);
    if (pv)
        off += snprintf(json + off, sizeof(json) - (size_t)off,
                        ",\"protected_vmids\":%s", pv);
    snprintf(json + off, sizeof(json) - (size_t)off, "}]}");
    return json;
}

static void t_M25_declared_empty_protected_vmids_is_fatal(void)
{
    printf("\n  M25: protected_vmids declared but empty refuses the config\n");
    static const struct { const char *pv; const char *what; } BAD[] = {
        { "[313, \"x\"]",    "an array with a non-integer entry (was: list ignored, host loaded)" },
        { "[313, 3.5]",       "an array with a non-integer number" },
        { "[]",               "an explicitly empty array" },
        { "313",              "a bare number (was: silently ignored)" },
        { "{\"vmid\":313}",   "an object (was: silently ignored)" },
        { "true",             "a boolean" },
        { "null",             "null" },
        { "\"\"",             "an empty string" },
    };
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
        char msg[200];
        snprintf(msg, sizeof(msg), "proxmox: refused — %s", BAD[i].what);
        CHECK(cfg_load("m25-bad", m25_cfg("proxmox", BAD[i].pv), NULL) == -1, msg);
    }
    CHECK(cfg_load("m25-linux", m25_cfg("linux", "[313, \"x\"]"), NULL) == -1,
          "linux: the same refusal");

    static onode_state_t st;
    CHECK(cfg_load("m25-ok", m25_cfg("proxmox", "[313, 105]"), &st) == 1 &&
          strcmp(st.devices[0].protected_vmids, "313,105") == 0,
          "a well-formed array loads and normalizes to CSV");
    onode_destroy(&st);
    CHECK(cfg_load("m25-csv", m25_cfg("proxmox", "\"313,105\""), &st) == 1 &&
          strcmp(st.devices[0].protected_vmids, "313,105") == 0,
          "the CSV string spelling still loads");
    onode_destroy(&st);
    CHECK(cfg_load("m25-absent", m25_cfg("proxmox", NULL), NULL) == 1,
          "a host that declares no protected_vmids loads as before");
    CHECK(cfg_load("m25-other", m25_cfg("mock", "313"), NULL) == 1,
          "the key is not policed on a vendor that has no VMIDs");
}

/* =========================================================================
 * M26 — production refuses "evidence_required": false
 * ========================================================================= */

static int cfg_load_production(const char *name, const char *json,
                               onode_state_t *st)
{
    char path[200];
    snprintf(path, sizeof(path), "%s/%s.json", g_root, name);
    FILE *f = fopen(path, "w");
    if (!f) return -99;
    fputs(json, f);
    fclose(f);
    if (onode_init(st, 1, NULL, "/tmp/virp-review-unused.sock") != VIRP_OK)
        return -98;
    return load_devices_production(st, path);
}

static void t_M26_production_refuses_evidence_required_false(void)
{
    printf("\n  M26: the production loader refuses evidence_required=false\n");
    static onode_state_t st;

    CHECK(cfg_load_production("m26-false",
              "{\"evidence_required\":false,\"devices\":[]}", &st) == -1,
          "production: \"evidence_required\": false is a fatal config error");
    CHECK(st.evidence_required,
          "and the refused load did not clear the flag on its way out");
    onode_destroy(&st);

    CHECK(cfg_load_production("m26-true",
              "{\"evidence_required\":true,\"devices\":[]}", &st) == 0 &&
          st.evidence_required, "production: true loads");
    onode_destroy(&st);
    CHECK(cfg_load_production("m26-absent", "{\"devices\":[]}", &st) == 0 &&
          st.evidence_required,
          "production: absent keeps the compiled-in true");
    onode_destroy(&st);
    CHECK(cfg_load_production("m26-string",
              "{\"evidence_required\":\"false\",\"devices\":[]}", &st) == -1,
          "production: a non-boolean is fatal, as it always was");
    onode_destroy(&st);

    /* The lab loader keeps the documented opt-out. */
    CHECK(cfg_load("m26-lab", "{\"evidence_required\":false,\"devices\":[]}",
                   &st) == 0 && !st.evidence_required,
          "lab loader: false is still accepted (mock daemon, fixtures)");
    onode_destroy(&st);
}

/* =========================================================================
 * LOW — the small ones, one check each
 * ========================================================================= */

static void t_LOW_request_threads_get_an_explicit_stack(void)
{
    printf("\n  LOW: worker and batch threads are created with an explicit stack size\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "low-stack")) { CHECK(false, "fixture"); return; }
    static uint8_t resp[4 * VIRP_MAX_MESSAGE_SIZE];

    review_min_stack = SIZE_MAX;
    ssize_t n = fx_request(&fx->st, getuid(),
        "{\"action\":\"batch_execute\",\"commands\":["
        "{\"device\":\"" FX_DEV "\",\"command\":\"show version\"},"
        "{\"device\":\"" FX_DEV "\",\"command\":\"show clock\"}]}",
        resp, sizeof(resp));
    CHECK(n > 4 && review_min_stack != SIZE_MAX &&
          review_min_stack >= ONODE_THREAD_STACK_BYTES,
          "batch item threads: stack size set, at least ONODE_THREAD_STACK_BYTES");

    pthread_t srv;
    review_min_stack = SIZE_MAX;
    if (!fx_server_start(fx, &srv)) { CHECK(false, "server start"); return; }
    int fd = fx_connect(&fx->st);
    const char *req = "{\"action\":\"heartbeat\"}";
    uint32_t len = htonl((uint32_t)strlen(req) + 1), rlen = 0;
    uint8_t ver = VIRP_FRAME_VERSION;
    bool answered = fd >= 0 && send(fd, &len, 4, 0) == 4 &&
                    send(fd, &ver, 1, 0) == 1 &&
                    send(fd, req, strlen(req), 0) == (ssize_t)strlen(req) &&
                    recv(fd, &rlen, 4, MSG_WAITALL) == 4;
    if (fd >= 0) close(fd);
    CHECK(answered && review_min_stack != SIZE_MAX &&
          review_min_stack >= ONODE_THREAD_STACK_BYTES,
          "connection workers: stack size set, at least ONODE_THREAD_STACK_BYTES");

    /* While it is up: the listening socket is close-on-exec. */
    int fl = fcntl(fx->st.listen_fd, F_GETFD);
    CHECK(fl >= 0 && (fl & FD_CLOEXEC),
          "the listening socket is close-on-exec");
    fx_server_stop(fx, srv);
    fx_destroy(fx);
}

static void t_LOW_failed_start_forgets_the_listen_fd(void)
{
    printf("\n  LOW: a failed bind does not leave a stale listen_fd behind\n");
    static onode_state_t st;
    char path[128];
    /* A DIRECTORY at the socket path: unlink() of it fails, so bind()
     * fails with EADDRINUSE after the socket was created. */
    snprintf(path, sizeof(path), "%s/low-bind.d", g_root);
    CHECK(mkdir(path, 0700) == 0, "(a directory occupies the socket path)");
    CHECK(onode_init(&st, 1, NULL, path) == VIRP_OK, "state initialised");
    CHECK(onode_start(&st) != VIRP_OK, "onode_start() fails at bind");
    CHECK(st.listen_fd == -1,
          "listen_fd is -1 afterwards, so teardown cannot close a recycled fd number");
    /* Prove the point: whatever now holds the lowest free descriptor
     * must survive onode_destroy(). */
    int canary = open("/dev/null", O_RDONLY);
    onode_destroy(&st);
    CHECK(canary >= 0 && fcntl(canary, F_GETFD) >= 0,
          "a descriptor opened after the failure survives onode_destroy()");
    if (canary >= 0) close(canary);
}

static void t_LOW_heartbeat_is_honest(void)
{
    printf("\n  LOW: the heartbeat does not vouch for the R-Node or wrap its count\n");
    static onode_state_t st;
    CHECK(onode_init(&st, 7, NULL, "/tmp/virp-review-unused.sock") == VIRP_OK,
          "state initialised");
    st.observations_sent = 70000;            /* past the 16-bit wire field */
    uint8_t buf[256];
    size_t len = 0;
    virp_heartbeat_t hb;
    memset(&hb, 0xff, sizeof(hb));
    CHECK(onode_heartbeat(&st, buf, sizeof(buf), &len) == VIRP_OK &&
          virp_parse_heartbeat(buf + VIRP_HEADER_SIZE, len - VIRP_HEADER_SIZE,
                               &hb) == VIRP_OK, "heartbeat built and parsed");
    CHECK(hb.onode_ok == 1 && hb.rnode_ok == 0,
          "onode_ok is set; rnode_ok is NOT asserted");
    CHECK(hb.active_observations == UINT16_MAX,
          "70000 observations saturate the 16-bit field at 65535 (it used to wrap to 4464)");
    st.observations_sent = 12;
    CHECK(onode_heartbeat(&st, buf, sizeof(buf), &len) == VIRP_OK &&
          virp_parse_heartbeat(buf + VIRP_HEADER_SIZE, len - VIRP_HEADER_SIZE,
                               &hb) == VIRP_OK && hb.active_observations == 12,
          "a count that fits is reported exactly");
    onode_destroy(&st);
}

static void t_LOW_every_action_answers(void)
{
    printf("\n  LOW: failures answer with a framed error; a missing context is not a crash\n");
    fx_t *fx = &g_fx;
    if (!fx_init(fx, "low-answers")) { CHECK(false, "fixture"); return; }
    onode_state_t *st = &fx->st;
    uid_t me = getuid();
    static uint8_t resp[VIRP_MAX_MESSAGE_SIZE + 64];

    /* No protocol context: the handshake actions must refuse, not
     * dereference NULL (session_bind did). */
    virp_context_t *ctx = st->ctx;
    st->ctx = NULL;
    CHECK(fx_ask(st, me, "{\"action\":\"session_bind\",\"client_id\":\"x\","
                 "\"session_id\":\"00112233445566778899aabbccddeeff\","
                 "\"client_nonce\":\"0011223344556677\","
                 "\"server_nonce\":\"0011223344556677\"}")
              == VIRP_ERR_SESSION_INVALID,
          "session_bind with no protocol context is refused (it used to crash)");
    CHECK(fx_ask(st, me, "{\"action\":\"session_hello\",\"client_id\":\"x\"}")
              == VIRP_ERR_SESSION_INVALID,
          "session_hello with no protocol context is refused");
    st->ctx = ctx;

    /* Make the signer fail: every builder below then returns an error,
     * and each action must still put a frame on the wire. */
    virp_signing_key_t saved = st->okey;
    memset(&st->okey, 0, sizeof(st->okey));
    static const char *const ACTIONS[] = { "heartbeat", "list_devices", "list_fleet" };
    for (size_t i = 0; i < 3; i++) {
        char req[64], msg[96];
        snprintf(req, sizeof(req), "{\"action\":\"%s\"}", ACTIONS[i]);
        ssize_t n = fx_request(st, me, req, resp, sizeof(resp));
        snprintf(msg, sizeof(msg), "%s: a failed build answers with a framed "
                 "error code", ACTIONS[i]);
        CHECK(n == 4 && fx_resp_err(resp, n) != VIRP_OK, msg);
    }
    st->okey = saved;
    fx_destroy(fx);
}

static void t_LOW_device_numbers_are_range_checked(void)
{
    printf("\n  LOW: port, node_id and device_id are refused when out of range\n");
#define LOW_DEV(extra) "{\"devices\":[{\"hostname\":\"r1\",\"host\":\"10.255.7.31\"," \
                       "\"vendor\":\"mock\"" extra "}]}"
    static const struct { const char *json; const char *what; } BAD[] = {
        { LOW_DEV(",\"node_id\":\"0A000001\",\"port\":70000"),
          "port 70000 (was: wrapped to 4464)" },
        { LOW_DEV(",\"node_id\":\"0A000001\",\"port\":0"), "port 0" },
        { LOW_DEV(",\"node_id\":\"0A000001\",\"port\":-1"),
          "port -1 (was: 65535)" },
        { LOW_DEV(",\"node_id\":\"0A000001\",\"port\":\"22\""),
          "a string port (was: ignored)" },
        { LOW_DEV(",\"node_id\":\"0A000001\",\"api_port\":99999"),
          "api_port 99999" },
        { LOW_DEV(",\"node_id\":\"1FFFFFFFF\""),
          "a 9-digit node_id (was: truncated)" },
        { LOW_DEV(",\"node_id\":\"0x0A000001\""),
          "node_id with a 0x prefix (was: read as 0)" },
        { LOW_DEV(",\"node_id\":\"0A00zz01\""), "a non-hex node_id" },
        { LOW_DEV(",\"node_id\":-5"), "a negative node_id" },
        { LOW_DEV(",\"node_id\":4294967296"), "a node_id past 32 bits" },
        { LOW_DEV(",\"node_id\":true"), "a boolean node_id" },
        { LOW_DEV(",\"node_id\":\"0A000001\",\"device_id\":\"12345678901234567\""),
          "a 17-digit device_id" },
    };
    for (size_t i = 0; i < sizeof(BAD) / sizeof(BAD[0]); i++) {
        char msg[160];
        snprintf(msg, sizeof(msg), "refused: %s", BAD[i].what);
        CHECK(cfg_load("low-range", BAD[i].json, NULL) == -1, msg);
    }
    static onode_state_t st;
    CHECK(cfg_load("low-range-ok",
                   LOW_DEV(",\"node_id\":\"0A000001\",\"port\":2222,"
                           "\"device_id\":\"00000000000000AB\""), &st) == 1 &&
          st.devices[0].port == 2222 && st.devices[0].node_id == 0x0A000001 &&
          st.devices[0].device_id == 0xAB,
          "in-range values load exactly as written");
    onode_destroy(&st);
    CHECK(cfg_load("low-range-int", LOW_DEV(",\"node_id\":167772161"), &st) == 1 &&
          st.devices[0].node_id == 167772161u && st.devices[0].port == 22,
          "an integer node_id loads; an absent port is the default 22");
    onode_destroy(&st);
#undef LOW_DEV
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
    { "t_M10_uid_in_rejections_and_proposer", t_M10_uid_in_rejections_and_proposer },
    { "t_M11_verify_response_carries_verifier_state",
                                              t_M11_verify_response_carries_verifier_state },
    { "t_M12_v2_session_lost_after_dispatch", t_M12_v2_session_lost_after_dispatch },
    { "t_M12_v3_session_lost_after_dispatch", t_M12_v3_session_lost_after_dispatch },
    { "t_M13_proposal_id_survives_long_command",
                                              t_M13_proposal_id_survives_long_command },
    { "t_M15_verify_range_is_capped",         t_M15_verify_range_is_capped },
    { "t_M15_verify_is_rate_limited_per_uid", t_M15_verify_is_rate_limited_per_uid },
    { "t_M16_open_proposals_are_deduplicated", t_M16_open_proposals_are_deduplicated },
    { "t_M16_proposals_are_rate_limited_per_uid",
                                              t_M16_proposals_are_rate_limited_per_uid },
    { "t_M17_batch_thread_create_failure",    t_M17_batch_thread_create_failure },
    { "t_M19_v2_session_is_owned_by_binding_uid",
                                              t_M19_v2_session_is_owned_by_binding_uid },
    { "t_M19_v3_session_is_owned_by_binding_uid",
                                              t_M19_v3_session_is_owned_by_binding_uid },
    { "t_M20_second_instance_refuses_to_start",
                                              t_M20_second_instance_refuses_to_start },
    { "t_M20_v1_sequence_survives_restart",   t_M20_v1_sequence_survives_restart },
    { "t_M21_v3_with_separate_observation_key",
                                              t_M21_v3_with_separate_observation_key },
    { "t_M22_unknown_top_level_key_is_fatal", t_M22_unknown_top_level_key_is_fatal },
    { "t_M22_explicit_allowlist_requires_ceilings",
                                              t_M22_explicit_allowlist_requires_ceilings },
    { "t_M22_shipped_templates_still_load",   t_M22_shipped_templates_still_load },
    { "t_M23_gate_config_values_are_strict",  t_M23_gate_config_values_are_strict },
    { "t_M24_uid_keys_are_parsed_strictly",   t_M24_uid_keys_are_parsed_strictly },
    { "t_M25_declared_empty_protected_vmids_is_fatal",
                                              t_M25_declared_empty_protected_vmids_is_fatal },
    { "t_M26_production_refuses_evidence_required_false",
                                              t_M26_production_refuses_evidence_required_false },
    { "t_LOW_request_threads_get_an_explicit_stack",
                                              t_LOW_request_threads_get_an_explicit_stack },
    { "t_LOW_failed_start_forgets_the_listen_fd",
                                              t_LOW_failed_start_forgets_the_listen_fd },
    { "t_LOW_heartbeat_is_honest",            t_LOW_heartbeat_is_honest },
    { "t_LOW_every_action_answers",           t_LOW_every_action_answers },
    { "t_LOW_device_numbers_are_range_checked",
                                              t_LOW_device_numbers_are_range_checked },
    { "t_M18_shutdown_wakes_the_accept_loop", t_M18_shutdown_wakes_the_accept_loop },
    { "t_M18_shutdown_from_signal_handler",   t_M18_shutdown_from_signal_handler },
    { "t_M18_shutdown_before_start_is_not_lost",
                                              t_M18_shutdown_before_start_is_not_lost },
    { "t_M18_shutdown_action_is_acknowledged", t_M18_shutdown_action_is_acknowledged },
    { "t_M14_request_deadline_is_absolute",   t_M14_request_deadline_is_absolute },
    { "t_M14_send_timeout_abandons_a_stalled_reader",
                                              t_M14_send_timeout_abandons_a_stalled_reader },
    { "t_M14_per_uid_worker_cap",             t_M14_per_uid_worker_cap },
    { "t_M14_accept_loop_enforces_per_uid_cap",
                                              t_M14_accept_loop_enforces_per_uid_cap },
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
