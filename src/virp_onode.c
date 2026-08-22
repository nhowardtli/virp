/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * O-Node Daemon Implementation
 *
 * This process holds the O-Key and is the ONLY entity that can
 * produce signed observations. It listens on a Unix domain socket,
 * accepts requests, executes commands on devices through drivers,
 * and returns signed VIRP OBSERVATION messages.
 *
 * The R-Node (AI) talks to this process. It never touches SSH.
 * It never touches the O-Key. Channel separation is enforced
 * by process isolation.
 */

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE   /* struct ucred (SO_PEERCRED) */

#include "virp_onode.h"
#include "virp_fault_inject.h"   /* lab-only; compiles away without -DVIRP_FAULT_INJECT */
#include "virp_message.h"
#include "virp_handshake.h"
#include "virp_transcript.h"
#include "virp_context.h"
#include "virp_validator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "cJSON.h"
#include "virp_approval.h"

/* =========================================================================
 * JSON Request Parsing
 *
 * cJSON (vendored at src/third_party/cJSON.{c,h}, v1.7.18, MIT) is the
 * sole parser. The hand-rolled strstr-based extractor that used to
 * live here had multiple soundness bugs (key matching inside string
 * values, lossy \u handling, silent surrogate replacement) and was
 * deleted once DUAL_PARSE logged zero disagreements for 48h.
 *
 * All request fields go through cJSON_GetObjectItemCaseSensitive on
 * the root object — never a substring search — so a notes field like
 * "notes":"\"action\":\"shutdown\"" cannot trigger an action. Integer
 * fields that feed into unsigned receiver types (supported_channels,
 * sequence numbers, expires_at_ns) are range-checked: negatives and
 * values above the receiver's max are rejected outright.
 * ========================================================================= */

typedef struct {
    onode_action_t  action;
    char            device[64];
    char            command[1024];
    int32_t         obs_version;            /* 1 = legacy O-Key, 2 = session-bound,
                                               3 = session-bound + Ed25519 */
    char            proposal_id[VIRP_APPROVAL_ID_HEX_LEN + 1]; /* apply/approve ref */
    char            signature[2 * VIRP_APPROVER_SIG_SIZE + 1]; /* approval submit sig (hex) */
    char            key_id[VIRP_APPROVER_KEYID_HEX + 1];       /* approval submit key_id */
    /* Chain fields (Primitive 6) */
    char            session_id[64];
    char            artifact_type[16];
    char            artifact_id[128];
    char            artifact_hash[65];
    char            artifact_content[8192]; /* Raw payload for artifact store */
    int64_t         from_sequence;
    int64_t         to_sequence;
    /* Intent fields (durable intent store) */
    char            intent_id[128];
    char            intent_hash[65];
    char            confidence[16];
    int64_t         expires_at_ns;
    int32_t         max_commands;
    char            intent_json[4096];      /* Canonical JSON */
    char            proposed_actions[2048];  /* JSON array */
    char            constraints[512];       /* JSON object */
    /* Handshake fields */
    char            client_id[64];
    char            client_nonce[17];       /* hex string (8 bytes = 16 hex chars) */
    char            server_nonce[17];
    char            versions[32];           /* comma-separated, e.g. "2,1" */
    char            algorithms[32];
    int64_t         supported_channels;
} onode_request_t;

/*
 * Extract a string-valued key from a JSON object. Writes at most
 * out_len-1 bytes plus a NUL. Returns false if the key is absent,
 * null, or not a string; out[0] is set to NUL in that case so the
 * caller's zero-initialized req struct is unchanged.
 */
static bool json_extract_string_cjson(cJSON *root, const char *key,
                                       char *out, size_t out_len)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(root, key);
    if (!cJSON_IsString(item) || item->valuestring == NULL) {
        out[0] = '\0';
        return false;
    }
    snprintf(out, out_len, "%s", item->valuestring);
    return true;
}

/*
 * The typed-operation profile a device's driver declares, or NULL.
 *
 * Single resolver so the three places that bind a command to a hash —
 * the v2 observation header, the approval proposal, and the approval
 * verify/consume — cannot disagree about which hash a command is under.
 * If they disagreed, an approval issued under one derivation would fail
 * (or worse, succeed) against a command hashed under the other.
 *
 * The profile is a static driver DECLARATION; the command text is never
 * inspected to decide.
 */
/* TODO(scope: deliberate session): bind the driver/registry VERSION into
 * approvals and observations alongside the profile id, so an approval
 * cannot survive a table change that alters what an op id means.
 * See "out of scope" list, 2026-08-01. */
static const char *onode_typed_profile(onode_state_t *state, int dev_idx)
{
    if (!state || dev_idx < 0) return NULL;
    const virp_driver_t *drv =
        virp_driver_lookup(state->devices[dev_idx].vendor);
    return drv ? drv->typed_profile : NULL;
}

/*
 * Extract a signed-integer-valued key. Accepts cJSON numbers only.
 * Returns false (leaving *out untouched) if absent or non-numeric.
 */
static bool json_extract_int64_cjson(cJSON *root, const char *key,
                                      int64_t *out)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(root, key);
    if (cJSON_IsNumber(item)) {
        *out = (int64_t)item->valuedouble;
        return true;
    }
    return false;
}

/*
 * Extract a non-negative integer bounded by [0, max]. Returns false
 * (without touching *out) if absent OR if the value is negative or
 * exceeds max. Use this for any field whose receiver is unsigned
 * (supported_channels, etc.) or a sequence number, so attacker-
 * controlled negatives never silently become huge uints.
 */
static bool json_extract_u64_bounded(cJSON *root, const char *key,
                                      uint64_t max, uint64_t *out)
{
    int64_t v = 0;
    if (!json_extract_int64_cjson(root, key, &v)) return false;
    if (v < 0) return false;
    if ((uint64_t)v > max) return false;
    *out = (uint64_t)v;
    return true;
}

/*
 * Reject a request whose JSON encodes an embedded NUL.
 *
 * THE DIVERGENCE. cJSON decodes \u0000 to a real zero byte and keeps
 * parsing (cJSON.c parse_string), so item->valuestring holds a string
 * whose C length stops at that byte while the JSON value continues past
 * it. Every extractor here copies with snprintf("%s"), which also stops
 * at the NUL. So
 *
 *     "pbs op=backup.version.read\u0000 op=backup.verify.run"
 *
 * arrives as ONE JSON value, is copied as `pbs op=backup.version.read`,
 * and the rest is discarded without a word — a submitted command and an
 * executed command that are not the same object. Classification,
 * hashing and the chain all see the truncated form.
 *
 * This is the fourth parser-length divergence found in this codebase, so
 * the check lives at the INGRESS BOUNDARY and covers every key of every
 * request, not just the driver that happened to expose it.
 *
 * The scan is deliberately syntactic and conservative: it looks for a
 * \u0000 escape in the raw request text, counting preceding backslashes
 * so an escaped backslash (\\u0000, a literal six-character string) is
 * not mistaken for one. It rejects the WHOLE request rather than
 * sanitizing a field, because a request that tries to smuggle a NUL is
 * not a request with one bad field.
 *
 * REJECT, never truncate — the same rule the separator policy follows.
 */
/* TODO(scope: deliberate session): migrate the typed-op interface to
 * (const uint8_t *, size_t) end to end. This NUL rejection closes the
 * live divergence at the boundary; it does not make the interface
 * length-aware, so a future caller that bypasses this ingress still
 * hands a bare const char* to the parser. See FIX 2, 2026-08-01. */
static bool json_has_nul_escape(const char *json)
{
    if (!json) return false;
    for (const char *p = json; *p; p++) {
        if (*p != 'u' || p == json) continue;

        /* count the run of backslashes immediately before this 'u' */
        size_t bs = 0;
        const char *q = p - 1;
        while (q >= json && *q == '\\') { bs++; if (q == json) break; q--; }
        if ((bs % 2) == 0) continue;          /* not an escape introducer */

        /*
         * A \u escape MUST be followed by exactly four hex digits.
         * Anything else is malformed JSON — and cJSON does not reject it,
         * it feeds the partial digits to parse_hex4 and writes the
         * result. `\u000 ` therefore decodes to codepoint 0, i.e. a real
         * NUL, and the value silently truncates there. Found by the
         * near-miss case in tests/test_ingress_nul.c, which was written
         * expecting cJSON to refuse it.
         *
         * So: refuse a malformed \u escape outright, and refuse a
         * well-formed one that encodes U+0000.
         */
        const char *h = p + 1;
        int digits = 0, value = 0;
        for (; digits < 4; digits++) {
            char c = h[digits];
            int v;
            if      (c >= '0' && c <= '9') v = c - '0';
            else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
            else break;
            value = (value << 4) | v;
        }
        if (digits < 4) return true;          /* malformed -> refuse */
        if (value == 0) return true;          /* U+0000     -> refuse */
    }
    return false;
}

/*
 * The wire name ↔ action table — the ONE list parse_request and the
 * socket_uid_action_allow config loader both read, so the dispatch and
 * the policy can never disagree about what an action is called.
 */
static const struct { const char *name; onode_action_t action; }
ONODE_ACTION_NAMES[] = {
    { "execute",              ONODE_ACTION_EXECUTE },
    { "health",               ONODE_ACTION_HEALTH },
    { "heartbeat",            ONODE_ACTION_HEARTBEAT },
    { "list_devices",         ONODE_ACTION_LIST },
    { "list_fleet",           ONODE_ACTION_LIST_FLEET },
    { "sign_intent",          ONODE_ACTION_SIGN_INTENT },
    { "sign_outcome",         ONODE_ACTION_SIGN_OUTCOME },
    { "chain_append",         ONODE_ACTION_CHAIN_APPEND },
    { "chain_verify",         ONODE_ACTION_CHAIN_VERIFY },
    { "chain_verify_session", ONODE_ACTION_CHAIN_VERIFY_SESSION },
    { "intent_store",         ONODE_ACTION_INTENT_STORE },
    { "intent_get",           ONODE_ACTION_INTENT_GET },
    { "intent_execute",       ONODE_ACTION_INTENT_EXECUTE },
    { "batch_execute",        ONODE_ACTION_BATCH_EXECUTE },
    { "validate_turn",        ONODE_ACTION_VALIDATE_TURN },
    { "approval_challenge",   ONODE_ACTION_APPROVAL_CHALLENGE },
    { "approval_submit",      ONODE_ACTION_APPROVAL_SUBMIT },
    { "session_hello",        ONODE_ACTION_SESSION_HELLO },
    { "session_bind",         ONODE_ACTION_SESSION_BIND },
    { "session_close",        ONODE_ACTION_SESSION_CLOSE },
    { "shutdown",             ONODE_ACTION_SHUTDOWN },
};

onode_action_t onode_action_from_name(const char *name)
{
    if (!name) return (onode_action_t)0;
    for (size_t i = 0;
         i < sizeof(ONODE_ACTION_NAMES) / sizeof(ONODE_ACTION_NAMES[0]); i++)
        if (strcmp(name, ONODE_ACTION_NAMES[i].name) == 0)
            return ONODE_ACTION_NAMES[i].action;
    return (onode_action_t)0;
}

/* Reverse lookup for log lines. Never returns NULL. */
static const char *onode_action_name(onode_action_t action)
{
    for (size_t i = 0;
         i < sizeof(ONODE_ACTION_NAMES) / sizeof(ONODE_ACTION_NAMES[0]); i++)
        if (ONODE_ACTION_NAMES[i].action == action)
            return ONODE_ACTION_NAMES[i].name;
    return "unknown";
}

static bool parse_request(const char *json, onode_request_t *req)
{
    if (!json || !req) return false;

    memset(req, 0, sizeof(*req));

    /* Length divergence: refuse a request carrying an encoded NUL before
     * anything copies a field out of it. */
    if (json_has_nul_escape(json)) {
        fprintf(stderr, "[O-Node] request contains an encoded NUL "
                        "(\\u0000) — refusing the whole request; a value "
                        "that continues past a NUL is not the value that "
                        "would be executed\n");
        return false;
    }

    /*
     * Structural validation: cJSON_Parse rejects malformed JSON. We
     * additionally require the root be an object — a bare array or
     * string parses successfully but has no keys to look up, which
     * would silently bypass the action gate.
     */
    cJSON *root = cJSON_Parse(json);
    if (!root) return false;
    if (!cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return false;
    }

    /* Action (required) */
    char action_str[32];
    if (!json_extract_string_cjson(root, "action", action_str, sizeof(action_str))) {
        cJSON_Delete(root);
        return false;
    }
    if (action_str[0] == '\0') { cJSON_Delete(root); return false; }

    req->action = onode_action_from_name(action_str);
    if ((int)req->action == 0) {
        cJSON_Delete(root);
        return false;
    }

#define EXTRACT_STR(key, dst, sz)  json_extract_string_cjson(root, key, dst, sz)

    /* Extract optional string fields */
    EXTRACT_STR("device", req->device, sizeof(req->device));
    EXTRACT_STR("command", req->command, sizeof(req->command));

    /*
     * Approval reference for apply. If present it must be exactly the
     * 32-lowercase-hex proposal id — anything else rejects the request
     * outright (the value becomes a path component downstream, and a
     * malformed reference must never silently degrade to a plain
     * execute). Validated on the raw JSON value so truncation can never
     * disguise an over-long id.
     */
    {
        cJSON *pid = cJSON_GetObjectItemCaseSensitive(root, "proposal_id");
        if (pid) {
            if (!cJSON_IsString(pid) || !pid->valuestring ||
                strlen(pid->valuestring) != VIRP_APPROVAL_ID_HEX_LEN ||
                strspn(pid->valuestring, "0123456789abcdef")
                    != VIRP_APPROVAL_ID_HEX_LEN) {
                cJSON_Delete(root);
                return false;
            }
            snprintf(req->proposal_id, sizeof(req->proposal_id), "%s",
                     pid->valuestring);
        }
    }

    /* Approval submit: signature (128 hex) + key_id (32 hex). Strictly
     * validated on the raw value; a malformed field rejects the request. */
    {
        cJSON *sg = cJSON_GetObjectItemCaseSensitive(root, "signature");
        if (sg) {
            if (!cJSON_IsString(sg) || !sg->valuestring ||
                strlen(sg->valuestring) != 2 * VIRP_APPROVER_SIG_SIZE ||
                strspn(sg->valuestring, "0123456789abcdef")
                    != 2 * VIRP_APPROVER_SIG_SIZE) {
                cJSON_Delete(root);
                return false;
            }
            snprintf(req->signature, sizeof(req->signature), "%s",
                     sg->valuestring);
        }
        cJSON *kd = cJSON_GetObjectItemCaseSensitive(root, "key_id");
        if (kd) {
            if (!cJSON_IsString(kd) || !kd->valuestring ||
                strlen(kd->valuestring) != VIRP_APPROVER_KEYID_HEX ||
                strspn(kd->valuestring, "0123456789abcdef")
                    != VIRP_APPROVER_KEYID_HEX) {
                cJSON_Delete(root);
                return false;
            }
            snprintf(req->key_id, sizeof(req->key_id), "%s", kd->valuestring);
        }
    }

    /*
     * Observation version for execute/health. Absent → 1 (legacy
     * master-key signing, the compatibility default). 1, 2 and 3 are
     * meaningful (3 = v2 session binding + the O-Node's Ed25519
     * observation signature; needs a loaded obskey, see
     * onode_execute_obs_ex); anything else present-but-invalid rejects
     * the request so a client typo cannot silently downgrade to v1.
     */
    req->obs_version = 1;
    {
        uint64_t v = 0;
        if (json_extract_u64_bounded(root, "obs_version", 3, &v)) {
            if (v < 1) { cJSON_Delete(root); return false; }
            req->obs_version = (int32_t)v;
        } else if (cJSON_GetObjectItemCaseSensitive(root, "obs_version")) {
            cJSON_Delete(root);
            return false;
        }
    }

    /* Chain fields */
    EXTRACT_STR("session_id", req->session_id, sizeof(req->session_id));
    EXTRACT_STR("artifact_type", req->artifact_type, sizeof(req->artifact_type));
    EXTRACT_STR("artifact_id", req->artifact_id, sizeof(req->artifact_id));
    EXTRACT_STR("artifact_hash", req->artifact_hash, sizeof(req->artifact_hash));
    EXTRACT_STR("artifact_content", req->artifact_content,
                sizeof(req->artifact_content));

    /*
     * Chain sequence numbers: negative values are meaningless and would
     * have wrapped to huge positives in any int64→uint context. Cap at
     * INT64_MAX so the stored int64_t can't round-trip to an invalid
     * state, and reject negatives outright.
     */
    {
        uint64_t v = 0;
        if (json_extract_u64_bounded(root, "from_sequence",
                                     (uint64_t)INT64_MAX, &v))
            req->from_sequence = (int64_t)v;
        else if (cJSON_GetObjectItemCaseSensitive(root, "from_sequence")) {
            /* Present but invalid (negative or non-number) — reject the
             * whole request rather than silently proceed with 0. */
            cJSON_Delete(root);
            return false;
        }
        if (json_extract_u64_bounded(root, "to_sequence",
                                     (uint64_t)INT64_MAX, &v))
            req->to_sequence = (int64_t)v;
        else if (cJSON_GetObjectItemCaseSensitive(root, "to_sequence")) {
            cJSON_Delete(root);
            return false;
        }
    }

    /* Intent fields */
    EXTRACT_STR("intent_id", req->intent_id, sizeof(req->intent_id));
    EXTRACT_STR("intent_hash", req->intent_hash, sizeof(req->intent_hash));
    EXTRACT_STR("confidence", req->confidence, sizeof(req->confidence));
    {
        uint64_t v = 0;
        if (json_extract_u64_bounded(root, "expires_at_ns",
                                     (uint64_t)INT64_MAX, &v))
            req->expires_at_ns = (int64_t)v;
        else if (cJSON_GetObjectItemCaseSensitive(root, "expires_at_ns")) {
            cJSON_Delete(root);
            return false;
        }
    }
    {
        /* max_commands is a signed int32 so it tolerates the JSON
         * source being signed, but negative is nonsensical and the
         * value must fit an int32. Bound at INT32_MAX. */
        uint64_t v = 0;
        if (json_extract_u64_bounded(root, "max_commands",
                                     (uint64_t)INT32_MAX, &v))
            req->max_commands = (int32_t)v;
        else if (cJSON_GetObjectItemCaseSensitive(root, "max_commands")) {
            cJSON_Delete(root);
            return false;
        }
    }
    EXTRACT_STR("intent_json", req->intent_json, sizeof(req->intent_json));
    EXTRACT_STR("proposed_actions", req->proposed_actions,
                sizeof(req->proposed_actions));
    EXTRACT_STR("constraints", req->constraints, sizeof(req->constraints));

    /* Handshake fields */
    EXTRACT_STR("client_id", req->client_id, sizeof(req->client_id));
    EXTRACT_STR("client_nonce", req->client_nonce, sizeof(req->client_nonce));
    EXTRACT_STR("server_nonce", req->server_nonce, sizeof(req->server_nonce));
    EXTRACT_STR("versions", req->versions, sizeof(req->versions));
    EXTRACT_STR("algorithms", req->algorithms, sizeof(req->algorithms));

    /*
     * supported_channels is a bitmask that gets cast to uint32_t later
     * when building the SESSION_HELLO. Guarantee the cast is lossless
     * by bounding at UINT32_MAX and rejecting negatives here.
     */
    {
        uint64_t v = 0;
        if (json_extract_u64_bounded(root, "supported_channels",
                                     (uint64_t)UINT32_MAX, &v))
            req->supported_channels = (int64_t)v;
        else if (cJSON_GetObjectItemCaseSensitive(root, "supported_channels")) {
            cJSON_Delete(root);
            return false;
        }
    }

#undef EXTRACT_STR

    cJSON_Delete(root);
    return true;
}

/* =========================================================================
 * Sequence Number
 * ========================================================================= */

uint32_t onode_next_seq(onode_state_t *state)
{
    pthread_mutex_lock(&state->state_mutex);
    uint32_t seq = ++state->seq_num;
    pthread_mutex_unlock(&state->state_mutex);
    return seq;
}

/*
 * Atomically increment observations_sent. Worker threads call this
 * from handle_client after every successful framed send. Must not be
 * inlined into caller code without state_mutex, otherwise concurrent
 * workers will lose increments.
 */
static inline void onode_inc_observations(onode_state_t *state)
{
    pthread_mutex_lock(&state->state_mutex);
    state->observations_sent++;
    pthread_mutex_unlock(&state->state_mutex);
}

/* =========================================================================
 * Device Lookup
 * ========================================================================= */

static int find_device(onode_state_t *state, const char *hostname)
{
    for (int i = 0; i < state->device_count; i++) {
        if (strcmp(state->devices[i].hostname, hostname) == 0)
            return i;
    }
    return -1;
}

static void drop_connection(onode_state_t *state, int dev_idx)
{
    pthread_mutex_lock(&state->conn_mutex);
    virp_conn_t *conn = state->connections[dev_idx];
    state->connections[dev_idx] = NULL;

    /* Arm reconnect backoff — watchdog will pick this up */
    onode_reconnect_t *ri = &state->reconnect[dev_idx];
    if (ri->backoff_sec == 0)
        ri->backoff_sec = ONODE_RECONNECT_BACKOFF_INIT;
    ri->last_attempt = time(NULL);
    pthread_mutex_unlock(&state->conn_mutex);

    /* disconnect may block on SSH teardown — run outside the lock */
    if (conn) {
        const virp_driver_t *drv = virp_driver_lookup(state->devices[dev_idx].vendor);
        if (drv && drv->disconnect)
            drv->disconnect(conn);
    }

    fprintf(stderr, "[O-Node] Connection dropped: %s (backoff %ds)\n",
            state->devices[dev_idx].hostname, ri->backoff_sec);
}

static virp_conn_t *get_connection(onode_state_t *state, int dev_idx)
{
    pthread_mutex_lock(&state->conn_mutex);
    if (state->connections[dev_idx]) {
        virp_conn_t *conn = state->connections[dev_idx];
        pthread_mutex_unlock(&state->conn_mutex);
        return conn;
    }

    /* If watchdog is already reconnecting this device, don't double-connect */
    if (state->reconnect[dev_idx].reconnecting) {
        pthread_mutex_unlock(&state->conn_mutex);
        return NULL;
    }
    pthread_mutex_unlock(&state->conn_mutex);

    /* Lazy connect — may block, runs outside the lock */
    const virp_device_t *dev = &state->devices[dev_idx];
    const virp_driver_t *drv = virp_driver_lookup(dev->vendor);
    if (!drv) return NULL;

    virp_conn_t *new_conn = drv->connect(dev);

    /* Store result and track reconnect state */
    pthread_mutex_lock(&state->conn_mutex);
    onode_reconnect_t *ri = &state->reconnect[dev_idx];

    /* Another thread may have connected while we were blocked */
    if (state->connections[dev_idx]) {
        pthread_mutex_unlock(&state->conn_mutex);
        if (new_conn) {
            drv->disconnect(new_conn);
        }
        return state->connections[dev_idx];
    }

    state->connections[dev_idx] = new_conn;
    if (new_conn) {
        ri->backoff_sec = 0;
        ri->consecutive_fails = 0;
        ri->last_success = time(NULL);
    } else {
        ri->consecutive_fails++;
        ri->last_attempt = time(NULL);
        if (ri->backoff_sec == 0)
            ri->backoff_sec = ONODE_RECONNECT_BACKOFF_INIT;
    }
    pthread_mutex_unlock(&state->conn_mutex);

    return new_conn;
}

/* =========================================================================
 * Tier-Enforcement Gate (Phase B) — helpers
 *
 * The gate sits in onode_execute() between driver lookup and driver
 * execution. It classifies the command via the driver's optional
 * route_command() hook and compares the result to state->gate_max_tier.
 *
 * SHADOW mode logs the decision and proceeds. ENFORCE mode hard-rejects
 * over-tier and UNCLASSIFIED commands. The GREEN-hardcoded response tier
 * and rejection persistence are deliberately out of scope here (Phase C).
 * ========================================================================= */

static const char *gate_tier_name(virp_trust_tier_t t)
{
    switch (t) {
    case VIRP_TIER_UNCLASSIFIED: return "UNCLASSIFIED";
    case VIRP_TIER_GREEN:        return "GREEN";
    case VIRP_TIER_YELLOW:       return "YELLOW";
    case VIRP_TIER_RED:          return "RED";
    case VIRP_TIER_BLACK:        return "BLACK";
    default:                     return "?";
    }
}

/*
 * Would this tier be blocked under max_tier? Fail closed on UNCLASSIFIED
 * (driver has no classifier table) and always block BLACK. Otherwise
 * order is GREEN(1) < YELLOW(2) < RED(3): block anything above the max.
 */
static bool gate_tier_blocks(virp_trust_tier_t tier, virp_trust_tier_t max_tier)
{
    if (tier == VIRP_TIER_UNCLASSIFIED) return true;
    if (tier == VIRP_TIER_BLACK)        return true;
    return tier > max_tier;
}

/*
 * Effective ceiling for a specific connecting uid. Starts from the
 * node-wide gate_max_tier and TIGHTENS (never raises) it if that uid has
 * a per-uid ceiling configured. client_uid == (uid_t)-1 means an
 * internal / non-socket caller with no per-uid entry: the node-wide
 * ceiling applies unchanged. Because tiers order GREEN(1) < YELLOW(2) <
 * RED(3), "tighter" is the numerically smaller value.
 */
static virp_trust_tier_t onode_effective_max_tier(const onode_state_t *state,
                                                  uid_t client_uid)
{
    virp_trust_tier_t eff = state->gate_max_tier;
    if (client_uid == (uid_t)-1) return eff;
    for (size_t i = 0; i < state->uid_ceiling_count; i++) {
        if (state->uid_ceiling_uids[i] == client_uid) {
            if (state->uid_ceiling_tiers[i] < eff)
                eff = state->uid_ceiling_tiers[i];
            break;
        }
    }
    return eff;
}

/*
 * Where the effective ceiling that onode_effective_max_tier() returned came
 * from, for the audit record. "per-uid" only when this uid has a per-uid
 * entry AND that entry is at least as tight as the node-wide ceiling — a
 * LOOSER per-uid entry never binds, because the effective-ceiling helper
 * only tightens, so the node-wide ceiling is what actually decided. Mirrors
 * that helper's logic exactly so the recorded source can never disagree with
 * the recorded effective ceiling.
 */
static const char *onode_ceiling_source(const onode_state_t *state,
                                        uid_t client_uid)
{
    if (client_uid == (uid_t)-1) return "node-wide";
    for (size_t i = 0; i < state->uid_ceiling_count; i++) {
        if (state->uid_ceiling_uids[i] == client_uid) {
            return (state->uid_ceiling_tiers[i] <= state->gate_max_tier)
                       ? "per-uid" : "node-wide";
        }
    }
    return "node-wide";
}

/*
 * Classify a command via the driver's optional route_command() hook.
 * Drivers without a classifier (NULL hook) yield UNCLASSIFIED, which the
 * gate treats as block-worthy (fail closed).
 */
static virp_trust_tier_t gate_classify(const virp_driver_t *drv,
                                       const char *command)
{
    if (drv && drv->route_command)
        return drv->route_command(command);
    return VIRP_TIER_UNCLASSIFIED;
}

/*
 * Map a gate-computed tier to the value stamped on the observation header.
 *
 * Audit honesty (Snow): record the ACTUAL computed tier. GREEN/YELLOW/RED
 * AND UNCLASSIFIED all pass through unchanged, so a blocked or unclassified
 * op is NOT recorded in the chain as GREEN (the integrity gap this fixes).
 * UNCLASSIFIED is 0x00, which is a valid on-wire tier (virp_header_validate
 * accepts it; only BLACK and tier > RED are rejected).
 *
 * BLACK is the sole clamp: the protocol forbids BLACK on the wire
 * (virp_header_init / virp_header_validate reject 0xFF), so a BLACK-
 * classified op's observation cannot be built as BLACK. It is stamped RED —
 * the highest transmittable tier — which OVER-reports sensitivity and never
 * under-reports it, the safe direction for an audit record.
 *
 * Non-static so the hardening unit tests can assert this mapping directly.
 */
uint8_t gate_obs_tier(virp_trust_tier_t t)
{
    switch (t) {
    case VIRP_TIER_GREEN:
    case VIRP_TIER_YELLOW:
    case VIRP_TIER_RED:
    case VIRP_TIER_UNCLASSIFIED:
        return (uint8_t)t;
    case VIRP_TIER_BLACK:
    default:
        return VIRP_TIER_RED;
    }
}

/*
 * Log line for every signed ERROR observation. Errors must log AS errors:
 * before this existed, error paths logged nothing (or only a [GATE] line)
 * and several were built as DEVICE_OUTPUT observations, so the AI layer
 * rendered them as executed, change-logged output. executed=no is literal:
 * an ERROR observation is only emitted when the command did not run.
 */
static void log_error_obs(const char *device, virp_trust_tier_t tier,
                          const char *reason)
{
    fprintf(stderr, "[ERROR-OBS] device=%s tier=%s executed=no reason=\"%s\"\n",
            device, gate_tier_name(tier), reason);
}

/* SHA-256 → lowercase hex (65 bytes incl. NUL). Used to hash a gate
 * rejection record before persisting it to the trust chain. */
static void gate_sha256_hex(const void *data, size_t len, char out[65])
{
    unsigned char md[32];
    unsigned int mdlen = 0;
    EVP_Digest(data, len, md, &mdlen, EVP_sha256(), NULL);
    for (int i = 0; i < 32; i++)
        snprintf(out + i * 2, 3, "%02x", md[i]);
}

/*
 * Effective gate mode for a driver: its per-driver override if present in
 * gate_overrides, else gate_default_mode. Matched by driver name (drv->name).
 */
static onode_gate_mode_t gate_effective_mode(const onode_state_t *state,
                                             const char *driver_name)
{
    if (driver_name) {
        for (size_t i = 0; i < state->gate_overrides_count; i++) {
            if (strcmp(state->gate_overrides[i].driver, driver_name) == 0)
                return state->gate_overrides[i].mode;
        }
    }
    return state->gate_default_mode;
}

/* =========================================================================
 * O-Node Operations
 * ========================================================================= */

/*
 * Emit the OUTCOME chain entry for an approved apply, linking the
 * PROPOSAL and APPROVAL entries (by their chain entry hashes and by the
 * shared "approval:<device>" chain session). Best-effort like the other
 * gate chain writes: a chain failure is logged and never alters the
 * execution result already in hand.
 */
static void approval_emit_outcome(onode_state_t *state,
                                  const char *proposal_id,
                                  const virp_approval_rec_t *apr,
                                  const char *device_name,
                                  bool success)
{
    if (!state->chain_enabled)
        return;

    virp_proposal_rec_t prop;
    bool have_prop = state->approval_dir[0] &&
        virp_approval_load_proposal(state->approval_dir, proposal_id,
                                    &prop) == VIRP_OK;

    char content[1024];
    snprintf(content, sizeof(content),
             "{\"proposal_id\":\"%s\",\"proposal_entry_hash\":\"%s\","
             "\"approval_entry_hash\":\"%s\",\"device\":\"%s\","
             "\"command_hash\":\"%s\",\"success\":%s}",
             proposal_id,
             have_prop ? prop.chain_entry_hash : "",
             apr->chain_entry_hash,
             device_name, apr->command_hash,
             success ? "true" : "false");

    char artifact_hash[65];
    gate_sha256_hex(content, strlen(content), artifact_hash);
    char artifact_id[64];
    snprintf(artifact_id, sizeof(artifact_id), "outcome:%s", proposal_id);
    char chain_session[96];
    snprintf(chain_session, sizeof(chain_session), "approval:%s", device_name);

    /* Entry and body commit in one transaction; the mid_outcome fault
     * point lives inside virp_chain_append_with_artifact() now, between
     * the two inserts, where dying must lose both records instead of
     * stranding a body-less entry. */
    virp_chain_entry_t ce;
    virp_error_t cerr = virp_chain_append_with_artifact(&state->chain,
                                          chain_session, "outcome",
                                          artifact_id, artifact_hash,
                                          content, &ce);
    if (cerr == VIRP_OK) {
        fprintf(stderr, "[GATE] outcome persisted: proposal=%s seq=%lld "
                "hash=%.16s success=%s\n", proposal_id,
                (long long)ce.sequence, ce.chain_entry_hash,
                success ? "true" : "false");
    } else {
        fprintf(stderr, "[GATE] outcome chain append+store failed: %s\n",
                virp_error_str(cerr));
    }
}

/* =========================================================================
 * Auto-execution RECORD (2026-08-12)
 *
 * The counterpart to the gate_rejection write below. Until now the chain
 * was a complete record of what was REFUSED and a blank on what was
 * ALLOWED: a gate-permitted command executed on the device and its result
 * went back to the caller without ever being signed or chained. GREEN is
 * the one tier that executes with no human in the loop, so it is exactly
 * the tier where "what did the agent do, and what did the device return"
 * has to be captured.
 *
 * SCOPE: every execution the GATE admitted on its own — i.e. not via an
 * approval. An approved apply is already recorded by the OUTCOME entry
 * above (proposal -> approval -> outcome), so chaining here too would
 * double-record it; callers pass approved==true to skip. The record
 * carries the command's real classified tier rather than a hardcoded
 * GREEN: under a higher ceiling, or under SHADOW, something other than
 * GREEN can reach the device, and a record that called it GREEN would be
 * a lie in precisely the case that matters most.
 *
 * REDACTION. The body deliberately does NOT contain the device's response.
 * GREEN output can carry credential material, and the chain is
 * tamper-evident and therefore not scrubbable — durably embedding response
 * bodies would turn the ledger into a secret store. The entry commits to
 * sha256 of the response instead: that is enough for non-repudiation ("an
 * output with this digest was produced at this chain position") without
 * persisting the content. The raw body still goes back to the caller in
 * the signed observation, unchanged.
 *
 * The digest is over the FULL response the driver captured
 * (result->output_len bytes), which is not always what the caller
 * receives: the observation payload is clamped to 65530 bytes, and
 * output_truncated says whether the DRIVER already cut the device's
 * output short. Both lengths are recorded so a reader can tell which
 * bytes the digest covers instead of guessing.
 *
 * result == NULL means the driver never returned one (execute() itself
 * errored). That still gets an entry — an executed-but-errored action
 * must not leave a gap — with executed_reported=false marking that the
 * driver could not say what reached the device.
 *
 * Best-effort, like every other gate chain write: a chain failure is
 * logged and never alters the result already in hand.
 * ========================================================================= */
static void gate_emit_execution(onode_state_t *state,
                                const char *device_name,
                                const virp_driver_t *drv,
                                const char *command,
                                virp_trust_tier_t gate_tier,
                                virp_trust_tier_t eff_max,
                                onode_gate_mode_t mode,
                                uid_t client_uid,
                                const virp_exec_result_t *result,
                                const char *failure_msg)
{
    if (!state->chain_enabled)
        return;

    /* Same chain and same session as the rejections, so executions and
     * refusals interleave under one continuous prev-hash linkage and a
     * reader sees the whole gate story in sequence order. */
    char session_id[96];
    snprintf(session_id, sizeof(session_id),
             "gate-enforce:%s", device_name);

    /* The commitment to the response body. Computed over the captured
     * bytes with the codebase's existing digest helper — the same one the
     * rejection path commits its body with. A driver that returned no
     * result digests the empty string, which is still a well-defined
     * commitment ("nothing was captured"), not a missing field. */
    char response_digest[65];
    size_t response_len = result ? result->output_len : 0;
    gate_sha256_hex(result ? (const void *)result->output : "",
                    response_len, response_digest);

    /* cJSON does the escaping: command text and driver error strings are
     * arbitrary and must never be pasted into JSON by hand. */
    char *body = NULL;
    cJSON *o = cJSON_CreateObject();
    if (o) {
        cJSON_AddStringToObject(o, "schema", "gate_execution/1");
        cJSON_AddStringToObject(o, "device", device_name);
        cJSON_AddStringToObject(o, "driver", drv->name);
        cJSON_AddStringToObject(o, "command", command);
        cJSON_AddStringToObject(o, "classified_tier",
                                gate_tier_name(gate_tier));
        /* Both ceilings: the node-wide one (what gate_rejection/1 records
         * under this name) and the per-uid-tightened one that actually
         * decided this execution. */
        cJSON_AddStringToObject(o, "gate_max_tier",
                                gate_tier_name(state->gate_max_tier));
        cJSON_AddStringToObject(o, "effective_max_tier",
                                gate_tier_name(eff_max));
        cJSON_AddStringToObject(o, "ceiling_source",
                                onode_ceiling_source(state, client_uid));
        cJSON_AddStringToObject(o, "gate_mode",
                                mode == GATE_MODE_ENFORCE ? "ENFORCE"
                                                          : "SHADOW");
        cJSON_AddStringToObject(o, "decision", "auto-execute");
        /* (uid_t)-1 is the internal caller, not a real uid — null, so a
         * reader never renders it as 4294967295. */
        if (client_uid == (uid_t)-1)
            cJSON_AddNullToObject(o, "uid");
        else
            cJSON_AddNumberToObject(o, "uid", (double)client_uid);

        /* "executed" uses the codebase's own proof standard: assume the
         * command reached the device UNLESS the driver proved it did not
         * (no_dispatch) — the same test the retry logic turns on, and for
         * the same reason (absence of a response is not absence of a side
         * effect). A driver that errored outright proved nothing, so it
         * counts as executed and executed_reported=false says the driver
         * could not tell us what happened. */
        cJSON_AddBoolToObject(o, "executed",
                              !(result && result->no_dispatch));
        cJSON_AddBoolToObject(o, "executed_reported", result != NULL);
        cJSON_AddBoolToObject(o, "success", result ? result->success : false);
        if (result) {
            cJSON_AddNumberToObject(o, "exit_code", (double)result->exit_code);
            cJSON_AddBoolToObject(o, "exit_code_trusted",
                                  result->exit_code_trusted);
            cJSON_AddStringToObject(o, "disposition",
                                    virp_disposition_str(result->disposition));
            cJSON_AddBoolToObject(o, "response_truncated",
                                  result->output_truncated);
        } else {
            cJSON_AddNullToObject(o, "exit_code");
            cJSON_AddBoolToObject(o, "exit_code_trusted", false);
            cJSON_AddStringToObject(o, "disposition", "DRIVER_ERROR");
            cJSON_AddBoolToObject(o, "response_truncated", false);
        }

        /* The commitment, NOT the content. Nothing below may become the
         * response body itself — see REDACTION above. */
        cJSON_AddStringToObject(o, "response_sha256", response_digest);
        cJSON_AddNumberToObject(o, "response_len", (double)response_len);

        if (failure_msg && failure_msg[0])
            cJSON_AddStringToObject(o, "error", failure_msg);
        else if (result && result->error_msg[0])
            cJSON_AddStringToObject(o, "error", result->error_msg);
        else
            cJSON_AddNullToObject(o, "error");

        body = cJSON_PrintUnformatted(o);
        cJSON_Delete(o);
    }

    /* Commit to the body actually stored. If the body could not be built,
     * commit to the response digest alone rather than losing the entry —
     * an execution must always be recorded, exactly as a rejection must. */
    char artifact_hash[65];
    if (body)
        gate_sha256_hex(body, strlen(body), artifact_hash);
    else
        memcpy(artifact_hash, response_digest, sizeof(artifact_hash));
    char artifact_id[64];
    snprintf(artifact_id, sizeof(artifact_id),
             "gateexec-%.16s", artifact_hash);

    virp_chain_entry_t ce;
    virp_error_t cerr = virp_chain_append_with_artifact(
                            &state->chain, session_id,
                            "gate_execution", artifact_id,
                            artifact_hash, body, &ce);
    if (cerr == VIRP_OK) {
        if (!body)
            fprintf(stderr, "[GATE] execution record body could not be "
                    "built; entry %s retains only the commitment\n",
                    artifact_id);
        fprintf(stderr, "[GATE] execution persisted: session=%s seq=%lld "
                "hash=%.16s tier=%s success=%s response_sha256=%.16s\n",
                session_id, (long long)ce.sequence, ce.chain_entry_hash,
                gate_tier_name(gate_tier),
                (result && result->success) ? "true" : "false",
                response_digest);
    } else {
        fprintf(stderr, "[GATE] execution chain append+store failed: %s\n",
                virp_error_str(cerr));
    }

    if (body) free(body);
}

virp_error_t onode_execute(onode_state_t *state,
                           const char *device_name,
                           const char *command,
                           uint8_t *out_buf, size_t out_buf_len,
                           size_t *out_len)
{
    return onode_execute_obs_ex(state, device_name, command, 1, NULL,
                                (uid_t)-1,
                                out_buf, out_buf_len, out_len);
}

virp_error_t onode_execute_obs(onode_state_t *state,
                               const char *device_name,
                               const char *command,
                               int obs_version,
                               uint8_t *out_buf, size_t out_buf_len,
                               size_t *out_len)
{
    return onode_execute_obs_ex(state, device_name, command, obs_version,
                                NULL, (uid_t)-1,
                                out_buf, out_buf_len, out_len);
}

virp_error_t onode_set_approvers(onode_state_t *state,
                                 const char *dir,
                                 const char *registry_path)
{
    if (!state || !dir || !registry_path)
        return VIRP_ERR_NULL_PTR;
    if (strlen(dir) >= sizeof(state->approval_dir))
        return VIRP_ERR_INVALID_LENGTH;

    virp_error_t err = virp_approver_registry_load(&state->approvers,
                                                   registry_path);
    if (err != VIRP_OK) {
        state->approvers_loaded = false;
        return err;
    }
    if (state->approvers.count == 0) {
        /* File parsed but nothing usable enrolled — leave disabled. */
        state->approvers_loaded = false;
        return VIRP_ERR_KEY_NOT_LOADED;
    }

    snprintf(state->approval_dir, sizeof(state->approval_dir), "%s", dir);
    state->approvers_loaded = true;
    fprintf(stderr, "[APPROVAL] enabled: dir=%s registry=%s keys=%zu\n",
            dir, registry_path, state->approvers.count);
    return VIRP_OK;
}

/* =========================================================================
 * Approval submission handlers (daemon is the sole chain writer)
 * ========================================================================= */

static void hex_of(const uint8_t *in, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++)
        snprintf(out + i * 2, 3, "%02x", in[i]);
}

/* APPROVAL_CHALLENGE: return the canonical bytes to sign plus the proposal
 * summary, as an O-Key-signed observation. */
static virp_error_t onode_approval_challenge(onode_state_t *state,
                                             const char *proposal_id,
                                             uint8_t *out_buf,
                                             size_t out_buf_len,
                                             size_t *out_len)
{
    if (!state->approval_dir[0] || !state->approvers_loaded)
        return VIRP_ERR_KEY_NOT_LOADED;

    /*
     * APPLIABILITY, before a signature is collected.
     *
     * apply re-classifies the command and refuses BLACK with
     * TIER_VIOLATION before any signature work. If that is going to be
     * the answer, the operator must learn it HERE — otherwise approve
     * collects a real signature, writes a real approval record, and the
     * flow dead-ends at apply on a command that was never appliable.
     *
     * The proposal's stored `tier` field is NOT consulted: it records
     * what the classifier said at propose time, which is history, not a
     * prediction. A table change between propose and approve can turn a
     * RED proposal BLACK, and this check must reflect the table that
     * apply will actually run — the same reason apply re-classifies
     * rather than trusting the record.
     *
     * Loaded and judged BEFORE virp_approval_challenge() so a BLACK
     * proposal never gets a challenge record written for it at all.
     */
    {
        virp_proposal_rec_t prop;
        virp_error_t perr = virp_approval_load_proposal(state->approval_dir,
                                                        proposal_id, &prop);
        if (perr != VIRP_OK) {
            fprintf(stderr, "[APPROVAL] challenge rejected: proposal=%s "
                    "code=%d (%s)\n", proposal_id, (int)perr,
                    virp_approval_err_name(perr));
            return perr;
        }

        int didx = find_device(state, prop.device);
        if (didx < 0) {
            fprintf(stderr, "[APPROVAL] challenge refused: proposal=%s names "
                    "device '%s', which this node does not serve\n",
                    proposal_id, prop.device);
            return VIRP_ERR_APPROVAL_DEVICE_MISMATCH;
        }

        const virp_driver_t *drv =
            virp_driver_lookup(state->devices[didx].vendor);
        if (gate_classify(drv, prop.command) == VIRP_TIER_BLACK) {
            fprintf(stderr, "[APPROVAL] challenge refused: proposal=%s "
                    "command is BLACK — not appliable at any tier\n",
                    proposal_id);
            return VIRP_ERR_TIER_VIOLATION;
        }
    }

    virp_approval_challenge_t ch;
    virp_error_t err = virp_approval_challenge(
            state->approval_dir,
            state->chain_enabled ? &state->chain : NULL,
            proposal_id, 0, &ch);
    if (err != VIRP_OK) {
        fprintf(stderr, "[APPROVAL] challenge rejected: proposal=%s code=%d "
                "(%s)\n", proposal_id, (int)err, virp_approval_err_name(err));
        return err;
    }

    char canon_hex[2 * VIRP_APPROVAL_CANON_SIZE + 1];
    hex_of(ch.canonical, VIRP_APPROVAL_CANON_SIZE, canon_hex);

    cJSON *o = cJSON_CreateObject();
    if (!o) return VIRP_ERR_BUFFER_TOO_SMALL;
    cJSON_AddStringToObject(o, "proposal_id", ch.proposal_id);
    cJSON_AddStringToObject(o, "canonical", canon_hex);
    cJSON_AddStringToObject(o, "device", ch.device);
    cJSON_AddStringToObject(o, "command", ch.command);
    cJSON_AddStringToObject(o, "command_hash", ch.command_hash);
    cJSON_AddStringToObject(o, "tier", ch.tier);
    cJSON_AddNumberToObject(o, "device_node_id", (double)ch.device_node_id);
    cJSON_AddNumberToObject(o, "approved_at_ns", (double)ch.approved_at_ns);
    cJSON_AddNumberToObject(o, "ttl_seconds", (double)ch.ttl_seconds);
    char *json = cJSON_PrintUnformatted(o);
    cJSON_Delete(o);
    if (!json) return VIRP_ERR_BUFFER_TOO_SMALL;

    fprintf(stderr, "[APPROVAL] challenge issued: proposal=%s device=%s "
            "tier=%s approved_at=%llu ttl=%u\n", ch.proposal_id, ch.device,
            ch.tier, (unsigned long long)ch.approved_at_ns, ch.ttl_seconds);

    err = virp_build_observation(out_buf, out_buf_len, out_len,
                                 state->node_id, onode_next_seq(state),
                                 VIRP_OBS_APPROVAL_CHALLENGE, VIRP_SCOPE_LOCAL,
                                 (const uint8_t *)json, (uint16_t)strlen(json),
                                 &state->okey);
    cJSON_free(json);
    return err;
}

/* APPROVAL_SUBMIT: verify the signature against the enrolled key, append
 * the APPROVAL chain entry (daemon-side), return an O-Key-signed result. */
static virp_error_t onode_approval_submit(onode_state_t *state,
                                          const char *proposal_id,
                                          const char *key_id,
                                          const char *sig_hex,
                                          uint8_t *out_buf, size_t out_buf_len,
                                          size_t *out_len)
{
    if (!state->approval_dir[0] || !state->approvers_loaded)
        return VIRP_ERR_KEY_NOT_LOADED;

    uint8_t sig[VIRP_APPROVER_SIG_SIZE];
    if (virp_hex_decode(sig_hex, sig, sizeof(sig)) != (int)sizeof(sig))
        return VIRP_ERR_APPROVAL_BAD_SIGNATURE;

    virp_approval_rec_t apr;
    virp_error_t err = virp_approval_submit(
            state->approval_dir, &state->approvers,
            state->chain_enabled ? &state->chain : NULL,
            proposal_id, key_id, sig, sizeof(sig), &apr);
    if (err != VIRP_OK && err != VIRP_APPROVAL_ALREADY_EXISTS) {
        fprintf(stderr, "[APPROVAL] submit rejected: proposal=%s key_id=%s "
                "code=%d (%s)\n", proposal_id, key_id, (int)err,
                virp_approval_err_name(err));
        return err;
    }

    if (err == VIRP_APPROVAL_ALREADY_EXISTS) {
        /* apr carries the approver OF RECORD (loaded from the canonical
         * persisted record), which may differ from the submitter that
         * lost the race — log both so the audit trail attributes the
         * winner and still records that this submission arrived. */
        fprintf(stderr, "[APPROVAL] submit idempotent: proposal=%s "
                "submitted_key=%s approver_of_record=%s operator=%s "
                "chain=%.16s\n", proposal_id, key_id, apr.approver_key_id,
                apr.operator[0] ? apr.operator : "(unknown)",
                apr.chain_entry_hash[0] ? apr.chain_entry_hash : "-");
    } else {
        fprintf(stderr, "[APPROVAL] submitted: proposal=%s key_id=%s "
                "operator=%s chain=%.16s\n", apr.proposal_id,
                apr.approver_key_id,
                apr.operator[0] ? apr.operator : "(unknown)",
                apr.chain_entry_hash[0] ? apr.chain_entry_hash : "-");
    }

    cJSON *o = cJSON_CreateObject();
    if (!o) return VIRP_ERR_BUFFER_TOO_SMALL;
    cJSON_AddStringToObject(o, "proposal_id", apr.proposal_id);
    cJSON_AddStringToObject(o, "approver_key_id", apr.approver_key_id);
    cJSON_AddStringToObject(o, "operator", apr.operator);
    cJSON_AddStringToObject(o, "chain_entry_hash", apr.chain_entry_hash);
    cJSON_AddNumberToObject(o, "approved_at_ns", (double)apr.approved_at_ns);
    cJSON_AddNumberToObject(o, "ttl_seconds", (double)apr.ttl_seconds);
    cJSON_AddBoolToObject(o, "already_approved",
                          err == VIRP_APPROVAL_ALREADY_EXISTS);
    char *json = cJSON_PrintUnformatted(o);
    cJSON_Delete(o);
    if (!json) return VIRP_ERR_BUFFER_TOO_SMALL;

    err = virp_build_observation(out_buf, out_buf_len, out_len,
                                 state->node_id, onode_next_seq(state),
                                 VIRP_OBS_APPROVAL_RESULT, VIRP_SCOPE_LOCAL,
                                 (const uint8_t *)json, (uint16_t)strlen(json),
                                 &state->okey);
    cJSON_free(json);
    return err;
}

/* Proposer identity for a PROPOSAL record: the active v2 session id if
 * one is bound, else a fixed marker for legacy v1 clients. */
static void approval_proposer_id(onode_state_t *state, int obs_version,
                                 char *out, size_t out_len)
{
    if (obs_version == 2) {
        pthread_mutex_lock(&state->session_mutex);
        if (state->ctx &&
            virp_session_require_active(state->ctx) == VIRP_OK) {
            int off = snprintf(out, out_len, "session:");
            /* snprintf returns the WOULD-BE length; if the prefix did not
             * fit, off already exceeds out_len and must not be used as an
             * offset. */
            if (off < 0 || (size_t)off >= out_len) {
                pthread_mutex_unlock(&state->session_mutex);
                return;
            }
            for (int i = 0; i < 8 && off + 2 < (int)out_len; i++) {
                int hw = snprintf(out + off, out_len - (size_t)off, "%02x",
                                  state->ctx->session.session_id[i]);
                if (hw < 0 || (size_t)hw >= out_len - (size_t)off)
                    break;
                off += hw;
            }
            pthread_mutex_unlock(&state->session_mutex);
            return;
        }
        pthread_mutex_unlock(&state->session_mutex);
    }
    snprintf(out, out_len, "unauthenticated-v1");
}

virp_error_t onode_execute_obs_ex(onode_state_t *state,
                                  const char *device_name,
                                  const char *command,
                                  int obs_version,
                                  const char *proposal_id,
                                  uid_t client_uid,
                                  uint8_t *out_buf, size_t out_buf_len,
                                  size_t *out_len)
{
    if (!state || !device_name || !command || !out_buf || !out_len)
        return VIRP_ERR_NULL_PTR;
    if (obs_version != 1 && obs_version != 2 && obs_version != 3)
        return VIRP_ERR_VERSION_MISMATCH;

    /*
     * v3 needs the observation-signing key. FAIL CLOSED, here, before
     * any device I/O: a caller who asked for an Ed25519-signed
     * observation must get one or an error — never a v1/v2 body they
     * did not ask for. The key is loaded once at startup
     * (onode_set_obskey) and read-only afterwards, so this check cannot
     * race the signing step below.
     */
    if (obs_version == 3 && !state->obskey_loaded)
        return VIRP_ERR_KEY_NOT_LOADED;

    /* ── Layer 1: single-command boundary ─────────────────────────────
     * Every classifier prefix-matches from index 0 while the drivers
     * send the WHOLE string to the device, so "show version\nreload"
     * classified GREEN on its first line and the reload reached the wire
     * ungated. Reject separator-carrying commands here, at the TOP:
     *
     *  - This is the one point BOTH request ingresses pass through.
     *    parse_batch_commands() is a second, independent parse that
     *    never touches parse_request(), so a check placed at either
     *    parser would miss the other; both converge here.
     *  - It precedes the v2 canonicalization probe below, so the signed
     *    command hash is never computed over a string we will refuse.
     *  - It precedes gate_classify(), so no classifier in any driver can
     *    tier a multi-command string in the first place.
     *
     * Batch items each arrive here on their own thread, so one bad item
     * yields its own signed rejection while siblings are still examined
     * individually — the per-item contract from af92763.
     *
     * The refusal is a HARD RETURN, not a gate decision. It is NOT
     * mediated by gate_tier_blocks and never reaches
     * gate_effective_mode, so a SHADOW-mode driver cannot log-and-
     * proceed past it — which matters because linux and wazuh run with
     * SHADOW overrides in production. Do not convert this into a
     * gate-tier verdict: SHADOW would then execute the command.
     * (test_onode.c pins this for both SHADOW forms.)
     *
     * The observation carries UNCLASSIFIED purely for audit honesty —
     * the command was never classified. That tier is not what blocks it.
     */
    {
        char why[160];
        if (virp_command_check_separators(command, why, sizeof(why)) != 0) {
            char err_msg[256];
            snprintf(err_msg, sizeof(err_msg),
                     "ERROR: multi-command / illegal separator rejected "
                     "for '%s': %s", device_name, why);
            log_error_obs(device_name, VIRP_TIER_UNCLASSIFIED, err_msg);
            return virp_build_observation_tiered(
                        out_buf, out_buf_len, out_len,
                        state->node_id, onode_next_seq(state),
                        VIRP_OBS_ERROR, VIRP_SCOPE_LOCAL,
                        VIRP_TIER_UNCLASSIFIED,
                        (const uint8_t *)err_msg, (uint16_t)strlen(err_msg),
                        &state->okey);
        }
    }

    /*
     * v2 and v3 require an ACTIVE session BEFORE any device I/O (v3 is
     * the v2 format plus an Ed25519 trailer — its HMAC trailer is still
     * keyed by the session). Checked again at signing time (the session
     * can idle out mid-command), but failing early avoids running a
     * command whose observation could never be delivered in the
     * requested form.
     */
    if (obs_version == 2 || obs_version == 3) {
        pthread_mutex_lock(&state->session_mutex);
        bool ok = state->ctx &&
                  virp_session_require_active(state->ctx) == VIRP_OK &&
                  state->ctx->session.session_key_valid;
        pthread_mutex_unlock(&state->session_mutex);
        if (!ok)
            return VIRP_ERR_SESSION_INVALID;

        /* The v2 header binds SHA-256 of the canonicalized command,
         * which virp_sign_observation_v2 canonicalizes into a 512-byte
         * buffer. Check that limit BEFORE any device I/O — otherwise
         * an over-long command would execute on the device and only
         * then fail signing, leaving a state change with no signed
         * observation of it. */
        char canon_probe[512];
        if (virp_canonicalize_command(command, canon_probe,
                                      sizeof(canon_probe)) < 0)
            return VIRP_ERR_INVALID_LENGTH;
    }

    /* Find device */
    int dev_idx = find_device(state, device_name);
    if (dev_idx < 0) {
        /* Device not found — signed ERROR observation. UNCLASSIFIED is
         * the honest tier: with no device there is no driver, so the
         * command was never classified. */
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "ERROR: device '%s' not found", device_name);
        log_error_obs(device_name, VIRP_TIER_UNCLASSIFIED, err_msg);
        return virp_build_observation_tiered(out_buf, out_buf_len, out_len,
                                      state->node_id, onode_next_seq(state),
                                      VIRP_OBS_ERROR, VIRP_SCOPE_LOCAL,
                                      VIRP_TIER_UNCLASSIFIED,
                                      (const uint8_t *)err_msg, (uint16_t)strlen(err_msg),
                                      &state->okey);
    }

    /*
     * Driver lookup and gate classification happen BEFORE any connection
     * attempt so every error observation below can carry the command's
     * true classified tier. (get_connection() also fails on a missing
     * driver, so hoisting the lookup changes no behavior.)
     */
    const virp_driver_t *drv = virp_driver_lookup(state->devices[dev_idx].vendor);
    if (!drv) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg),
                 "ERROR: no driver for '%s'", device_name);
        log_error_obs(device_name, VIRP_TIER_UNCLASSIFIED, err_msg);
        return virp_build_observation_tiered(out_buf, out_buf_len, out_len,
                                      state->devices[dev_idx].node_id,
                                      onode_next_seq(state),
                                      VIRP_OBS_ERROR, VIRP_SCOPE_LOCAL,
                                      VIRP_TIER_UNCLASSIFIED,
                                      (const uint8_t *)err_msg,
                                      (uint16_t)strlen(err_msg),
                                      &state->okey);
    }
    virp_trust_tier_t gate_tier = gate_classify(drv, command);

    /* Approval-apply state: set when a valid, consumed approval admits a
     * gate-blocked command; the post-execution paths then emit the
     * OUTCOME chain entry. */
    bool approved = false;
    virp_approval_rec_t apr;
    memset(&apr, 0, sizeof(apr));

    /* Gate decision, hoisted to function scope so the post-execution paths
     * can record what admitted this command in the gate_execution chain
     * entry. Both are set inside the gate block below, which is
     * unconditional and runs before anything can execute. */
    onode_gate_mode_t gate_mode = GATE_MODE_SHADOW;
    virp_trust_tier_t gate_eff_max = VIRP_TIER_UNCLASSIFIED;

    /*
     * Per-device execution lock — serializes all command execution on
     * this connection so that batch_execute threads targeting the same
     * device do not race on the libssh2 session.
     */
    pthread_mutex_lock(&state->exec_mutex[dev_idx]);

    /* L1: the device is deliberately NOT connected yet. The gate below
     * decides admit/refuse FIRST; only an admitted request connects (just
     * before drv->execute). An over-tier command under ENFORCE is now
     * refused with no connection attempt, no auth, no session allocation
     * and no connect audit noise — the classification alone decides it. */

    /* ── Tier-enforcement gate (Phase B/C) ────────────────────────────
     * Classify at the boundary, decide allow/block against the configured
     * max tier, and log. SHADOW logs and proceeds; ENFORCE hard-rejects
     * over-tier / unclassified commands before the driver runs. The
     * classified tier (computed above, before the connection attempt) is
     * function-scoped so the success observation below can be stamped
     * with it (Phase C truth-fix). */
    {
        onode_gate_mode_t mode = gate_effective_mode(state, drv->name);
        /* Effective ceiling = node-wide gate_max_tier, tightened by any
         * per-uid ceiling for the connecting socket client. A remote
         * requester capped at GREEN thus has YELLOW/RED blocked (and
         * therefore proposal-only) while local operators keep the
         * node-wide ceiling. client_uid == (uid_t)-1 (internal callers)
         * leaves gate_max_tier unchanged. */
        virp_trust_tier_t eff_max = onode_effective_max_tier(state, client_uid);
        bool block = gate_tier_blocks(gate_tier, eff_max);

        gate_mode = mode;
        gate_eff_max = eff_max;

        /* ENFORCE states what it did; only SHADOW speaks hypothetically.
         * The old unconditional "would-block"/"would-allow" wording made
         * an ENFORCE rejection read like a logged-but-executed change.
         * threshold= reports the EFFECTIVE ceiling (post per-uid tighten)
         * so the log shows what actually decided this connection. */
        fprintf(stderr,
                "[GATE] mode=%s device=%s driver=%s tier=%s threshold=%s "
                "uid=%ld decision=%s command=\"%s\"\n",
                mode == GATE_MODE_ENFORCE ? "ENFORCE" : "SHADOW",
                device_name, drv->name,
                gate_tier_name(gate_tier),
                gate_tier_name(eff_max),
                (client_uid == (uid_t)-1) ? -1L : (long)client_uid,
                mode == GATE_MODE_ENFORCE
                    ? (block ? "block" : "allow")
                    : (block ? "would-block" : "would-allow"),
                command);

        if (mode == GATE_MODE_ENFORCE && block &&
            proposal_id && proposal_id[0]) {
            /*
             * APPLY: a re-submission carrying an approval reference.
             * Verification order (each failure a distinct code):
             * signature → command_hash → device → TTL → single-use
             * consume (durable; persist failure fails closed). BLACK
             * stays unapprovable, and an unconfigured approval store
             * verifies nothing (fail closed).
             */
            /*
             * BLACK is unapprovable BY DESIGN and this check runs before
             * any signature work, so a classifier that returns BLACK
             * makes its commands permanently un-escalatable: the
             * propose→approve→apply path dead-ends for exactly the
             * commands most likely to need a human. Driver tables are
             * therefore expected to top out at RED (blocked, but
             * approvable). The linux/FRR table is pinned to that by
             * test_never_returns_black() in
             * tests/test_driver_linux_gate.c; any new table should carry
             * the same invariant test.
             */
            virp_error_t aerr;
            if (gate_tier == VIRP_TIER_BLACK)
                aerr = VIRP_ERR_TIER_VIOLATION;
            else if (!state->approval_dir[0] || !state->approvers_loaded)
                aerr = VIRP_ERR_KEY_NOT_LOADED;
            else
                aerr = virp_approval_verify_consume(state->approval_dir,
                                                    &state->approvers,
                                                    proposal_id,
                                                    device_name,
                                                    state->devices[dev_idx].node_id,
                                                    command,
                                                    onode_typed_profile(state, dev_idx),
                                                    0, &apr);
            if (aerr == VIRP_OK) {
                approved = true;
                const virp_approver_t *ent = virp_approver_registry_find_any(
                        &state->approvers, apr.approver_key_id);
                fprintf(stderr, "[GATE] approval verified: proposal=%s "
                        "device=%s tier=%s key_id=%s operator=%s — executing\n",
                        proposal_id, device_name,
                        gate_tier_name(gate_tier), apr.approver_key_id,
                        (ent && ent->operator[0]) ? ent->operator : "(unknown)");
                /* fall through: the approved command executes below */
            } else {
                pthread_mutex_unlock(&state->exec_mutex[dev_idx]);
                char err_msg[384];
                snprintf(err_msg, sizeof(err_msg),
                         "ERROR: apply rejected (%s, err=%d) for proposal "
                         "%s on '%s' (tier=%s max=%s)",
                         virp_approval_err_name(aerr), (int)aerr,
                         proposal_id, device_name,
                         gate_tier_name(gate_tier),
                         gate_tier_name(eff_max));
                fprintf(stderr, "[GATE] apply rejected: proposal=%s "
                        "device=%s code=%d (%s)\n",
                        proposal_id, device_name, (int)aerr,
                        virp_approval_err_name(aerr));
                log_error_obs(device_name, gate_tier, err_msg);
                return virp_build_observation_tiered(out_buf, out_buf_len,
                                              out_len,
                                              state->devices[dev_idx].node_id,
                                              onode_next_seq(state),
                                              VIRP_OBS_ERROR, VIRP_SCOPE_LOCAL,
                                              gate_obs_tier(gate_tier),
                                              (const uint8_t *)err_msg,
                                              (uint16_t)strlen(err_msg),
                                              &state->okey);
            }
        } else if (mode == GATE_MODE_ENFORCE && block) {
            pthread_mutex_unlock(&state->exec_mutex[dev_idx]);
            char err_msg[448];
            snprintf(err_msg, sizeof(err_msg),
                     "ERROR: tier gate blocked '%s' on '%s' "
                     "(tier=%s max=%s)",
                     command, device_name, gate_tier_name(gate_tier),
                     gate_tier_name(eff_max));

            /* Classifier-supplied instructive reason (optional hook):
             * appended before the proposal_id so the rejection payload
             * teaches the escalation path, not just the tier math. */
            if (drv->route_reason) {
                const char *why = drv->route_reason(command);
                if (why) {
                    size_t off = strlen(err_msg);
                    snprintf(err_msg + off, sizeof(err_msg) - off,
                             " reason: %s", why);
                }
            }

            /*
             * PROPOSE: file a signed proposal so a human can escalate
             * this exact command via `virp approve`. Best-effort — a
             * proposal failure never weakens the rejection — and never
             * offered for BLACK. The rejection payload carries the
             * proposal_id so the caller can capture it.
             */
            if (state->approval_dir[0] && gate_tier != VIRP_TIER_BLACK) {
                char proposer[80];
                approval_proposer_id(state, obs_version, proposer,
                                     sizeof(proposer));
                virp_proposal_rec_t prop;
                virp_error_t perr = virp_approval_propose(
                        state->approval_dir,
                        state->chain_enabled ? &state->chain : NULL,
                        proposer, device_name,
                        state->devices[dev_idx].node_id,
                        command,
                        onode_typed_profile(state, dev_idx),
                        proposer, gate_tier_name(gate_tier),
                        &prop);
                if (perr == VIRP_OK) {
                    size_t off = strlen(err_msg);
                    snprintf(err_msg + off, sizeof(err_msg) - off,
                             " proposal_id=%s", prop.proposal_id);
                    fprintf(stderr, "[GATE] proposal filed: proposal=%s "
                            "device=%s tier=%s chain=%.16s\n",
                            prop.proposal_id, device_name,
                            gate_tier_name(gate_tier),
                            prop.chain_entry_hash[0] ? prop.chain_entry_hash
                                                     : "-");
                } else {
                    fprintf(stderr, "[GATE] proposal filing failed: %s\n",
                            virp_error_str(perr));
                }
            }

            /* Phase C — rejection persistence: write a durable, HMAC-signed
             * entry to the trust chain via the same append path the AI
             * layer uses, so a refused command leaves an auditable record.
             * Best-effort: a chain failure must not alter the rejection.
             * DORMANT under SHADOW — this branch runs only in ENFORCE.
             * NOTE: virp_chain_append serializes writes with BEGIN
             * IMMEDIATE but shares prepared statements with the AI-path
             * chain_append handler; a dedicated chain mutex shared by both
             * paths is the proper hardening before high-concurrency enforce. */
            if (state->chain_enabled) {
                /*
                 * Reason RETENTION. The entry commits to sha256(body) as
                 * before, but the body is now STORED, so the reason is
                 * recoverable from the chain alone instead of only from
                 * the daemon journal. Before this, an evidence report
                 * could prove a block happened and commit to its reason
                 * but could not show the reason.
                 *
                 * Body is a structured object (schema gate_rejection/1):
                 * device, driver, command, classified tier, gate max
                 * tier, the classifier's matched rule when it supplied
                 * one, and the exact human-readable message — the same
                 * text the signed ERROR observation carries as its
                 * payload, so the chain body and the O-Key-signed
                 * observation agree by construction.
                 *
                 * Binding: the body is committed to by artifact_hash,
                 * which is itself covered by the entry's chain HMAC. The
                 * body is HMAC-bound through the entry, not directly
                 * O-Key-signed; the O-Key-signed copy of the same text
                 * is the ERROR observation returned to the caller.
                 *
                 * RETENTION SENSITIVITY (reviewed 2026-07-30): a
                 * classification reason is metadata — tiers, rule names,
                 * device and driver names — and carries no credential.
                 * The one field that can carry caller-supplied content is
                 * `command`, and a blocked write attempt can legitimately
                 * contain a secret the caller typed (e.g. an attempted
                 * "username x secret y"). That text is NOT newly exposed
                 * by this change: it already goes to the journal, is
                 * already the payload of the signed ERROR observation
                 * returned to the caller, and was already hashed into
                 * this entry. What does change is durability and reach —
                 * chain.db is permanent where the journal rotates, and it
                 * is group-readable under /var/lib/virp (0750 virp:virp),
                 * so group `virp` members can read attempted command
                 * text. Retained deliberately: an audit record of a
                 * refused command that omits the command is not an audit
                 * record. If a deployment cannot accept that, scrub at
                 * the caller — never here, where scrubbing would break
                 * the observation/chain agreement above.
                 */
                char session_id[96];
                snprintf(session_id, sizeof(session_id),
                         "gate-enforce:%s", device_name);

                const char *matched = drv->route_reason
                                    ? drv->route_reason(command) : NULL;

                /* cJSON does the escaping: command text is arbitrary and
                 * must never be pasted into JSON by hand. */
                char *body = NULL;
                cJSON *o = cJSON_CreateObject();
                if (o) {
                    cJSON_AddStringToObject(o, "schema", "gate_rejection/1");
                    cJSON_AddStringToObject(o, "device", device_name);
                    cJSON_AddStringToObject(o, "driver", drv->name);
                    cJSON_AddStringToObject(o, "command", command);
                    cJSON_AddStringToObject(o, "classified_tier",
                                            gate_tier_name(gate_tier));
                    /* gate_max_tier is the NODE-WIDE ceiling; on its own it
                     * misreads a per-uid refusal (a YELLOW-classified command
                     * refused under a GREEN per-uid ceiling looks like it
                     * should have passed a YELLOW node-wide max). Record the
                     * ceiling that ACTUALLY fired (gate_eff_max) and where it
                     * came from, so the chain body explains the decision by
                     * itself. */
                    cJSON_AddStringToObject(o, "gate_max_tier",
                                            gate_tier_name(state->gate_max_tier));
                    cJSON_AddStringToObject(o, "effective_max_tier",
                                            gate_tier_name(gate_eff_max));
                    cJSON_AddStringToObject(o, "ceiling_source",
                                            onode_ceiling_source(state, client_uid));
                    if (matched)
                        cJSON_AddStringToObject(o, "matched_rule", matched);
                    else
                        cJSON_AddNullToObject(o, "matched_rule");
                    cJSON_AddStringToObject(o, "message", err_msg);
                    cJSON_AddBoolToObject(o, "executed", false);
                    body = cJSON_PrintUnformatted(o);
                    cJSON_Delete(o);
                }

                /* Commit to the body actually stored. If the body could
                 * not be built, fall back to the historical
                 * commit-to-message behaviour rather than losing the
                 * entry — a rejection must always be recorded. */
                char artifact_hash[65];
                const char *commit_src = body ? body : err_msg;
                gate_sha256_hex(commit_src, strlen(commit_src), artifact_hash);
                char artifact_id[64];
                snprintf(artifact_id, sizeof(artifact_id),
                         "gatereject-%.16s", artifact_hash);

                /* Entry and body are one transaction now: a stored
                 * rejection always has its reason recoverable, and a
                 * body-store failure fails the whole append (logged
                 * below) instead of stranding a commitment. The
                 * body==NULL fallback keeps the historical entry-only
                 * append — a rejection must always be recorded even
                 * when its body could not be built. */
                virp_chain_entry_t ce;
                virp_error_t cerr = virp_chain_append_with_artifact(
                                        &state->chain, session_id,
                                        "gate_rejection", artifact_id,
                                        artifact_hash, body, &ce);
                if (cerr == VIRP_OK) {
                    if (!body)
                        fprintf(stderr, "[GATE] rejection reason body could "
                                "not be built; entry %s retains only the "
                                "commitment\n", artifact_id);
                    fprintf(stderr, "[GATE] rejection persisted: session=%s "
                            "seq=%lld hash=%.16s\n", session_id,
                            (long long)ce.sequence, ce.chain_entry_hash);
                } else {
                    fprintf(stderr, "[GATE] rejection chain append+store "
                            "failed: %s\n", virp_error_str(cerr));
                }

                if (body) free(body);
            }

            log_error_obs(device_name, gate_tier, err_msg);
            return virp_build_observation_tiered(out_buf, out_buf_len, out_len,
                                          state->devices[dev_idx].node_id,
                                          onode_next_seq(state),
                                          VIRP_OBS_ERROR, VIRP_SCOPE_LOCAL,
                                          gate_obs_tier(gate_tier),
                                          (const uint8_t *)err_msg,
                                          (uint16_t)strlen(err_msg),
                                          &state->okey);
        }
    }

    /* Admitted by the gate above — allowed, an approved apply, or a
     * SHADOW would-block that proceeds. ONLY NOW connect (L1): the gate
     * decision above never touched the device, so a refused request cost
     * nothing on the wire. */
    virp_conn_t *conn = get_connection(state, dev_idx);
    if (!conn) {
        pthread_mutex_unlock(&state->exec_mutex[dev_idx]);
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg),
                 "ERROR: cannot connect to '%s'", device_name);
        log_error_obs(device_name, gate_tier, err_msg);
        return virp_build_observation_tiered(out_buf, out_buf_len, out_len,
                                      state->devices[dev_idx].node_id,
                                      onode_next_seq(state),
                                      VIRP_OBS_ERROR, VIRP_SCOPE_LOCAL,
                                      gate_obs_tier(gate_tier),
                                      (const uint8_t *)err_msg,
                                      (uint16_t)strlen(err_msg),
                                      &state->okey);
    }

    virp_exec_result_t result;
    memset(&result, 0, sizeof(result));   /* no_dispatch=false unless the
                                             driver proves otherwise */
    VIRP_FI("pre_exec");
    virp_error_t err = drv->execute(conn, command, &result);
    VIRP_FI("post_exec");
    if (err != VIRP_OK) {
        drop_connection(state, dev_idx);
        pthread_mutex_unlock(&state->exec_mutex[dev_idx]);
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg),
                 "ERROR: driver execute failed on '%s': %s",
                 device_name, virp_error_str(err));
        /* Executed-but-errored: no result to report, and no proof the
         * command never reached the device. Chain it rather than leave a
         * gap. result=NULL — the driver told us nothing. */
        if (!approved)
            gate_emit_execution(state, device_name, drv, command, gate_tier,
                                gate_eff_max, gate_mode, client_uid,
                                NULL, err_msg);
        if (approved)
            approval_emit_outcome(state, proposal_id, &apr,
                                  device_name, false);
        log_error_obs(device_name, gate_tier, err_msg);
        return virp_build_observation_tiered(out_buf, out_buf_len, out_len,
                                      state->devices[dev_idx].node_id,
                                      onode_next_seq(state),
                                      VIRP_OBS_ERROR, VIRP_SCOPE_LOCAL,
                                      gate_obs_tier(gate_tier),
                                      (const uint8_t *)err_msg,
                                      (uint16_t)strlen(err_msg),
                                      &state->okey);
    }

    /* Retry once with a fresh connection, but ONLY when the driver proved
     * the command was never dispatched (result.no_dispatch). Nothing
     * reached the device, so a second execute is a first execution, not a
     * repeat. Without that proof, absence of a response is not absence of
     * a side effect, and this block used to re-execute generically:
     * authorized once, executed twice. The unprovable case is handled
     * below as a typed OUTCOME_UNKNOWN instead.
     *
     * The old `output_len == 0` conjunct is GONE and must not come back:
     * the linux driver seeds its output buffer with a "<host>$ <cmd>\n"
     * prefix before reading, so that test was always false and silently
     * disabled this branch for that driver (TRANSCRIPT-05). Buffer
     * contents say nothing about whether bytes were dispatched. */
    if (!result.success && result.no_dispatch) {
        drop_connection(state, dev_idx);
        conn = get_connection(state, dev_idx);
        if (conn) {
            memset(&result, 0, sizeof(result));
            err = drv->execute(conn, command, &result);
            if (err != VIRP_OK) {
                drop_connection(state, dev_idx);
                pthread_mutex_unlock(&state->exec_mutex[dev_idx]);
                char err_msg[256];
                snprintf(err_msg, sizeof(err_msg),
                         "ERROR: driver execute failed on '%s' (retry): %s",
                         device_name, virp_error_str(err));
                /* One entry per admitted action, not per dispatch attempt:
                 * the first attempt proved non-dispatch, so this retry IS
                 * the execution and this is its only record. */
                if (!approved)
                    gate_emit_execution(state, device_name, drv, command,
                                        gate_tier, gate_eff_max, gate_mode,
                                        client_uid, NULL, err_msg);
                if (approved)
                    approval_emit_outcome(state, proposal_id, &apr,
                                          device_name, false);
                log_error_obs(device_name, gate_tier, err_msg);
                return virp_build_observation_tiered(
                    out_buf, out_buf_len, out_len,
                    state->devices[dev_idx].node_id,
                    onode_next_seq(state),
                    VIRP_OBS_ERROR, VIRP_SCOPE_LOCAL,
                    gate_obs_tier(gate_tier),
                    (const uint8_t *)err_msg,
                    (uint16_t)strlen(err_msg),
                    &state->okey);
            }
        }
    }

    pthread_mutex_unlock(&state->exec_mutex[dev_idx]);

    /*
     * Failure with no output and NO proof of non-dispatch: the command
     * may have reached and executed on the device (SSH write completed
     * but the response was lost; REST request timed out after send;
     * output exceeded the evidence limit). Re-executing here is the
     * authorized-once-executed-twice bug; claiming executed=no is a
     * lie. Report the typed UNKNOWN. The connection is dropped — its
     * state is unknowable too. Approval outcome stays the existing
     * binary failure record (a consumed approval cannot be replayed to
     * "try again"); expressing UNKNOWN in the outcome artifact itself
     * is EXECUTION_INTENT territory, deferred with Part B.
     */
    /* A driver that classifies its termination (linux) states UNKNOWN
     * directly. The output_len test in the second clause is the LEGACY path
     * for drivers not yet converted to the classifier — it is deliberately
     * NOT part of the new decision, and must never be reintroduced into it:
     * for the linux driver it was always false, which is precisely how this
     * branch came to be dead code. Converting the remaining drivers retires
     * that clause. */
    if (result.disposition == VIRP_DISPOSITION_EXECUTED_UNKNOWN ||
        (result.disposition == VIRP_DISPOSITION_UNSET &&
         !result.success && result.output_len == 0 && !result.no_dispatch)) {
        pthread_mutex_lock(&state->exec_mutex[dev_idx]);
        drop_connection(state, dev_idx);
        pthread_mutex_unlock(&state->exec_mutex[dev_idx]);
        char err_msg[sizeof(result.error_msg) + 160];
        snprintf(err_msg, sizeof(err_msg),
                 "ERROR: outcome UNKNOWN on '%s': %s — no response after "
                 "possible dispatch; not retried (command may have "
                 "executed)",
                 device_name,
                 result.error_msg[0] ? result.error_msg
                                     : virp_error_str(VIRP_ERR_OUTCOME_UNKNOWN));
        /* The command may well have run — that is what UNKNOWN means. An
         * unknown outcome is the last thing that should be missing from
         * the ledger. */
        if (!approved)
            gate_emit_execution(state, device_name, drv, command, gate_tier,
                                gate_eff_max, gate_mode, client_uid,
                                &result, err_msg);
        if (approved)
            approval_emit_outcome(state, proposal_id, &apr,
                                  device_name, false);
        fprintf(stderr, "[ERROR-OBS] device=%s tier=%s executed=unknown "
                "disposition=%s reason=\"%s\"\n", device_name,
                gate_tier_name(gate_tier),
                virp_disposition_str(result.disposition), err_msg);
        return virp_build_observation_tiered(out_buf, out_buf_len, out_len,
                                      state->devices[dev_idx].node_id,
                                      onode_next_seq(state),
                                      VIRP_OBS_ERROR, VIRP_SCOPE_LOCAL,
                                      gate_obs_tier(gate_tier),
                                      (const uint8_t *)err_msg,
                                      (uint16_t)strlen(err_msg),
                                      &state->okey);
    }

    /*
     * Driver soft-failure with no output: the driver refused the command
     * before any device I/O (VIRP_OK + success=false + error_msg — the
     * shape REST drivers like Wazuh use for invalid or BLACK-tier
     * endpoints). Nothing executed (no_dispatch proven — the unproven
     * case returned above as OUTCOME_UNKNOWN), so this must be a signed
     * ERROR observation carrying the command's true tier — never the
     * DEVICE_OUTPUT / v2 session-bound constructor used for executed
     * output, which downstream renders as a logged change.
     */
    if (!result.success && result.output_len == 0 && result.error_msg[0]) {
        char err_msg[sizeof(result.error_msg) + 96];
        snprintf(err_msg, sizeof(err_msg),
                 "ERROR: driver refused '%s': %s",
                 device_name, result.error_msg);
        /* Recorded even though nothing ran: the gate ADMITTED this action,
         * and "admitted then refused by the driver" is a distinct fact
         * from "never admitted". no_dispatch is proven here, so the entry
         * says executed=false rather than claiming an execution. */
        if (!approved)
            gate_emit_execution(state, device_name, drv, command, gate_tier,
                                gate_eff_max, gate_mode, client_uid,
                                &result, err_msg);
        if (approved)
            approval_emit_outcome(state, proposal_id, &apr,
                                  device_name, false);
        log_error_obs(device_name, gate_tier, err_msg);
        return virp_build_observation_tiered(out_buf, out_buf_len, out_len,
                                      state->devices[dev_idx].node_id,
                                      onode_next_seq(state),
                                      VIRP_OBS_ERROR, VIRP_SCOPE_LOCAL,
                                      gate_obs_tier(gate_tier),
                                      (const uint8_t *)err_msg,
                                      (uint16_t)strlen(err_msg),
                                      &state->okey);
    }

    /* What the device's termination actually told us, recorded before the
     * observation is built so the log and the signed artifact cannot drift. */
    fprintf(stderr, "[EXEC] device=%s disposition=%s success=%s exit=%d "
            "exit_trusted=%s truncated=%s reason=\"%s\"\n",
            device_name, virp_disposition_str(result.disposition),
            result.success ? "true" : "false", result.exit_code,
            result.exit_code_trusted ? "yes" : "no",
            result.output_truncated ? "yes" : "no",
            result.error_msg[0] ? result.error_msg : "-");

    /* SIGN-ORDERING: the device has returned and the chain entry is
     * written HERE — before the observation is built, signed and framed,
     * and therefore before anything is sent back to the caller. A dropped
     * send, a signing failure, or a dead v2 session must never be able to
     * leave an executed action with no ledger entry; the only orderings
     * that guarantee that put the append first. */
    if (!approved)
        gate_emit_execution(state, device_name, drv, command, gate_tier,
                            gate_eff_max, gate_mode, client_uid,
                            &result, NULL);

    const uint8_t *obs_data = (const uint8_t *)result.output;
    uint16_t data_len = (result.output_len > 65530) ?
                         65530 : (uint16_t)result.output_len;

    /* Phase C truth-fix: stamp the observation with the command's real
     * gate-classified tier (clamped to a transmittable tier) instead of a
     * blanket GREEN. show system admin → RED; get system status → GREEN. */
    if (obs_version == 2 || obs_version == 3) {
        /*
         * v2/v3 success path: session-bound observation signed with the
         * HKDF session key; v3 additionally carries the O-Node's
         * Ed25519 signature over header || payload || hmac
         * (virp_build_observation_ed25519 — the library's own builder,
         * not a refactor of it). seq_num is per-session monotonic
         * (session.last_seq under session_mutex), which is what the
         * verifier's replay high-water store checks against. If the
         * session died while the command ran, fail — never downgrade
         * to master-key signing on a v2/v3 request, and never serve a
         * v3 request an unsigned v2 body.
         */
        pthread_mutex_lock(&state->session_mutex);
        if (!state->ctx ||
            virp_session_require_active(state->ctx) != VIRP_OK ||
            !state->ctx->session.session_key_valid) {
            err = VIRP_ERR_SESSION_INVALID;
        } else if (obs_version == 3 && !state->obskey_loaded) {
            /* Pre-flight already refused this; kept so the signing
             * step can never fall through to v2 if the two ever drift. */
            err = VIRP_ERR_KEY_NOT_LOADED;
        } else {
            /* Truncate like the v1 path does rather than erroring:
             * total message (88 hdr + payload + 32 hmac [+ 64 ed25519])
             * must fit in VIRP_MAX_MESSAGE_SIZE. */
            size_t trailer = VIRP_OBS_V2_SIG_SIZE +
                             (obs_version == 3 ? VIRP_OBS_ED25519_SIG_SIZE
                                               : 0);
            if ((size_t)data_len > VIRP_MAX_MESSAGE_SIZE -
                                   VIRP_OBS_V2_HEADER_SIZE - trailer)
                data_len = (uint16_t)(VIRP_MAX_MESSAGE_SIZE -
                                      VIRP_OBS_V2_HEADER_SIZE - trailer);
            uint64_t seq = ++state->ctx->session.last_seq;
            /*
             * The command hash binds the approved object to the executed
             * one. For a TYPED-OPERATION driver that binding must be over
             * the exact validated octets, not the whitespace-collapsed
             * canonical form — otherwise a spelling the typed parser
             * REFUSES hashes identically to one it accepts. The profile
             * is a static driver declaration; nothing here inspects the
             * command text to decide. NULL = historic CLI hashing.
             */
            const char *typed_profile = onode_typed_profile(state, dev_idx);

            if (obs_version == 3)
                err = virp_build_observation_ed25519(state->ctx,
                                     &state->obskey,
                                     (uint64_t)state->devices[dev_idx].node_id,
                                     state->devices[dev_idx].device_id,
                                     gate_obs_tier(gate_tier), seq, command,
                                     typed_profile,
                                     obs_data, data_len,
                                     out_buf, out_buf_len, out_len);
            else
                err = virp_build_observation_v2(state->ctx,
                                     (uint64_t)state->devices[dev_idx].node_id,
                                     state->devices[dev_idx].device_id,
                                     gate_obs_tier(gate_tier), seq, command,
                                     typed_profile,
                                     obs_data, data_len,
                                     out_buf, out_buf_len, out_len);
        }
        pthread_mutex_unlock(&state->session_mutex);
    } else {
        err = virp_build_observation_tiered(out_buf, out_buf_len, out_len,
                                 state->devices[dev_idx].node_id,
                                 onode_next_seq(state),
                                 VIRP_OBS_DEVICE_OUTPUT,
                                 VIRP_SCOPE_LOCAL,
                                 gate_obs_tier(gate_tier),
                                 obs_data, data_len,
                                 &state->okey);
    }

    /* Approved apply reached execution: link PROPOSAL + APPROVAL to the
     * outcome, whatever the device reported. */
    VIRP_FI("pre_outcome");
    if (approved)
        approval_emit_outcome(state, proposal_id, &apr,
                              device_name, result.success);

    if (err == VIRP_OK) {
        pthread_mutex_lock(&state->state_mutex);
        state->observations_sent++;
        pthread_mutex_unlock(&state->state_mutex);
    }

    return err;
}

virp_error_t onode_heartbeat(onode_state_t *state,
                             uint8_t *out_buf, size_t out_buf_len,
                             size_t *out_len)
{
    if (!state || !out_buf || !out_len)
        return VIRP_ERR_NULL_PTR;

    uint32_t uptime = (uint32_t)(time(NULL) - state->uptime_start);

    return virp_build_heartbeat(out_buf, out_buf_len, out_len,
                                state->node_id, onode_next_seq(state),
                                uptime, true, true,
                                (uint16_t)state->observations_sent,
                                0,  /* R-Node tracks proposals */
                                &state->okey);
}

/* =========================================================================
 * List Devices — returns device inventory as observation
 * ========================================================================= */

static virp_error_t onode_list_devices(onode_state_t *state,
                                       uint8_t *out_buf, size_t out_buf_len,
                                       size_t *out_len)
{
    /*
     * Truncation-safe accumulation. `offset += snprintf(...)` advances by
     * the WOULD-BE length, so a long row could push offset past
     * sizeof(listing); `offset` is then passed as the observation payload
     * length below, which would read past the buffer. The old loop guard
     * (offset < sizeof - 100) was thinner than a worst-case row: hostname
     * and host are 64 bytes each, so a row can reach ~152 bytes.
     */
    char listing[VIRP_OUTPUT_MAX];
    size_t offset = 0;

    int hw = snprintf(listing, sizeof(listing),
                       "VIRP O-Node Device Inventory (%d devices)\n"
                       "%-16s %-16s %-12s %-8s\n"
                       "-----------------------------------------------------\n",
                       state->device_count,
                       "Hostname", "Host", "Vendor", "NodeID");
    if (hw < 0 || (size_t)hw >= sizeof(listing))
        return VIRP_ERR_BUFFER_TOO_SMALL;
    offset = (size_t)hw;

    for (int i = 0; i < state->device_count && offset < sizeof(listing); i++) {
        const char *vendor_str = "unknown";
        switch (state->devices[i].vendor) {
        case VIRP_VENDOR_CISCO_IOS: vendor_str = "cisco_ios"; break;
        case VIRP_VENDOR_CISCO_IOSXE: vendor_str = "cisco_iosxe"; break;
        case VIRP_VENDOR_FORTINET:  vendor_str = "fortinet"; break;
        case VIRP_VENDOR_LINUX:     vendor_str = "linux"; break;
        case VIRP_VENDOR_JUNIPER:   vendor_str = "juniper"; break;
        case VIRP_VENDOR_PALOALTO:  vendor_str = "paloalto"; break;
        case VIRP_VENDOR_WINDOWS:   vendor_str = "windows"; break;
        case VIRP_VENDOR_PROXMOX:   vendor_str = "proxmox"; break;
        case VIRP_VENDOR_CISCO_ASA: vendor_str = "cisco_asa"; break;
        case VIRP_VENDOR_MOCK:      vendor_str = "mock"; break;
        default: break;
        }

        int rw = snprintf(listing + offset, sizeof(listing) - offset,
                           "%-16s %-16s %-12s %08x\n",
                           state->devices[i].hostname,
                           state->devices[i].host,
                           vendor_str,
                           state->devices[i].node_id);
        if (rw < 0 || (size_t)rw >= sizeof(listing) - offset)
            break;                 /* row truncated — stop, keep offset sane */
        offset += (size_t)rw;
    }

    return virp_build_observation(out_buf, out_buf_len, out_len,
                                  state->node_id, onode_next_seq(state),
                                  VIRP_OBS_RESOURCE_STATE, VIRP_SCOPE_LOCAL,
                                  (const uint8_t *)listing, (uint16_t)offset,
                                  &state->okey);
}

/*
 * list_fleet (Item 8): fleet ENUMERATION only — device names and their
 * connection status. Deliberately narrower than list_devices: no host
 * addresses, no node ids, no vendor detail, no config bodies. This is
 * the read a restricted federated principal keeps, so its content is
 * pinned by test to never quietly widen.
 */
static virp_error_t onode_list_fleet(onode_state_t *state,
                                     uint8_t *out_buf, size_t out_buf_len,
                                     size_t *out_len)
{
    char listing[VIRP_OUTPUT_MAX];
    size_t offset = 0;

    int hw = snprintf(listing, sizeof(listing),
                      "VIRP Fleet (%d devices)\n"
                      "%-24s %s\n"
                      "----------------------------------------\n",
                      state->device_count, "Name", "Status");
    if (hw < 0 || (size_t)hw >= sizeof(listing))
        return VIRP_ERR_BUFFER_TOO_SMALL;
    offset = (size_t)hw;

    for (int i = 0; i < state->device_count && offset < sizeof(listing); i++) {
        const char *status;
        if (!state->devices[i].enabled) {
            status = "disabled";
        } else {
            pthread_mutex_lock(&state->conn_mutex);
            status = state->connections[i] ? "connected" : "unconnected";
            pthread_mutex_unlock(&state->conn_mutex);
        }

        int rw = snprintf(listing + offset, sizeof(listing) - offset,
                          "%-24s %s\n",
                          state->devices[i].hostname, status);
        if (rw < 0 || (size_t)rw >= sizeof(listing) - offset)
            break;                 /* row truncated — stop, keep offset sane */
        offset += (size_t)rw;
    }

    return virp_build_observation(out_buf, out_buf_len, out_len,
                                  state->node_id, onode_next_seq(state),
                                  VIRP_OBS_RESOURCE_STATE, VIRP_SCOPE_LOCAL,
                                  (const uint8_t *)listing, (uint16_t)offset,
                                  &state->okey);
}

/* =========================================================================
 * Batch Parallel Execution (pthread-based)
 *
 * Each device gets its own thread. Connections are per-device indexed,
 * so threads never share connection state. The state_mutex protects
 * seq_num and observations_sent.
 * ========================================================================= */

typedef struct {
    onode_state_t   *state;
    char            device[64];
    char            command[1024];
    int             obs_version;    /* 1 = legacy O-Key, 2 = session-bound */
    uid_t           client_uid;     /* connecting peer, for per-uid ceiling */
    uint8_t         *resp_buf;      /* heap-allocated, VIRP_MAX_MESSAGE_SIZE */
    size_t          resp_len;
    virp_error_t    err;
} batch_thread_arg_t;

static void *batch_execute_thread(void *arg)
{
    batch_thread_arg_t *bta = (batch_thread_arg_t *)arg;
    bta->resp_len = 0;
    /* Call _ex directly (not onode_execute_obs) so the connecting uid
     * reaches the gate on the batch fan-out: these run on child threads
     * that do NOT inherit the parent, which is exactly why the uid is a
     * struct field and not a thread-local. proposal_id is not carried on
     * the batch path (batch APPLY is not offered). */
    bta->err = onode_execute_obs_ex(bta->state, bta->device, bta->command,
                                    bta->obs_version, NULL, bta->client_uid,
                                    bta->resp_buf, VIRP_MAX_MESSAGE_SIZE,
                                    &bta->resp_len);
    return NULL;
}

/*
 * Parse batch commands from JSON "commands" array.
 * Returns count of commands parsed (0 on error/empty).
 */
static int parse_batch_commands(const char *json,
                                 batch_thread_arg_t *args,
                                 int max_cmds)
{
    /* Same ingress rule as the single path — the batch array is exactly
     * where a smuggled NUL would be cheapest to hide. */
    if (json_has_nul_escape(json)) {
        fprintf(stderr, "[O-Node] batch contains an encoded NUL "
                        "(\\u0000) — refusing the whole batch\n");
        return 0;
    }
    cJSON *root = cJSON_Parse(json);
    if (!root) return 0;
    if (!cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return 0;
    }

    cJSON *commands = cJSON_GetObjectItemCaseSensitive(root, "commands");
    if (!cJSON_IsArray(commands)) {
        cJSON_Delete(root);
        return 0;
    }

    int count = 0;
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, commands) {
        if (count >= max_cmds) break;
        if (!cJSON_IsObject(item)) continue;

        /* Approval applies are single-command by design. Refuse the
         * whole batch rather than silently dropping the field (the
         * unknown-field standard from the obs_version fix). */
        if (cJSON_GetObjectItemCaseSensitive(item, "proposal_id")) {
            cJSON_Delete(root);
            return 0;
        }

        cJSON *dev = cJSON_GetObjectItemCaseSensitive(item, "device");
        cJSON *cmd = cJSON_GetObjectItemCaseSensitive(item, "command");

        if (cJSON_IsString(dev) && dev->valuestring &&
            cJSON_IsString(cmd) && cmd->valuestring) {
            snprintf(args[count].device, sizeof(args[count].device),
                     "%s", dev->valuestring);
            snprintf(args[count].command, sizeof(args[count].command),
                     "%s", cmd->valuestring);
            count++;
        }
    }

    cJSON_Delete(root);
    return count;
}

/* =========================================================================
 * Client Request Handler
 * ========================================================================= */

/* Map a single hex character to its 4-bit value, or -1 if invalid. */
static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* =========================================================================
 * Autopilot hard exclusions — non-negotiable device blocklist
 *
 * 10.0.10.1 (the edge firewall) and 10.0.10.10 must NEVER appear in a
 * device config this daemon loads. The check is a startup assertion in
 * every config loader: a config carrying either address is refused
 * outright — no skip-and-continue, the daemon does not start.
 *
 * Matching is boundary-aware over the raw config text so it catches the
 * address anywhere (host fields, comments, spare keys) without false-
 * positives on neighbors: an occurrence counts only when the preceding
 * character is not [0-9.] and the following character is not a digit,
 * so "10.0.10.12" and "10.0.10.100" do NOT trip the "10.0.10.1" /
 * "10.0.10.10" rules.
 * ========================================================================= */

static const char *const ONODE_BLOCKED_ADDRS[] = {
    "10.0.10.1",
    "10.0.10.10",
};

const char *virp_config_blocked_address(const char *text)
{
    if (!text) return NULL;

    for (size_t i = 0;
         i < sizeof(ONODE_BLOCKED_ADDRS) / sizeof(ONODE_BLOCKED_ADDRS[0]);
         i++) {
        const char *addr = ONODE_BLOCKED_ADDRS[i];
        size_t alen = strlen(addr);
        for (const char *p = strstr(text, addr); p;
             p = strstr(p + 1, addr)) {
            char prev = (p == text) ? '\0' : p[-1];
            char next = p[alen];
            bool prev_extends = (prev >= '0' && prev <= '9') || prev == '.';
            bool next_extends = (next >= '0' && next <= '9');
            if (!prev_extends && !next_extends)
                return addr;
        }
    }
    return NULL;
}

/* File variant for the config loaders: reads up to 1 MiB of the config
 * and scans it. An unreadable file returns NULL — the loader's own
 * open/parse error handling covers that case. */
const char *virp_config_file_blocked(const char *path)
{
    if (!path) return NULL;
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    static const size_t MAX_CFG = 1024 * 1024;
    char *buf = malloc(MAX_CFG + 1);
    if (!buf) { fclose(f); return NULL; }

    size_t n = fread(buf, 1, MAX_CFG, f);
    fclose(f);
    buf[n] = '\0';

    const char *blocked = virp_config_blocked_address(buf);
    free(buf);
    return blocked;   /* points at a static table entry, or NULL */
}

/* Decode hex string to bytes. Returns number of bytes written, or -1 on error.
 * Rejects any non-[0-9a-fA-F] character (no whitespace, signs, or 0x prefixes). */
int virp_hex_decode(const char *hex, uint8_t *out, size_t out_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > out_len)
        return -1;
    for (size_t i = 0; i < hex_len; i += 2) {
        int hi = hex_nibble(hex[i]);
        int lo = hex_nibble(hex[i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(hex_len / 2);
}

/* Encode bytes to lowercase hex. buf must hold 2*len+1 bytes. */
static void hex_encode(char *buf, size_t buf_size, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        snprintf(buf + i * 2, buf_size - i * 2, "%02x", data[i]);
    buf[len * 2] = '\0';
}

/* =========================================================================
 * Socket Framing (v2)
 *
 * Wire format:
 *   [4 bytes: big-endian payload length (covers payload only, NOT the prefix)]
 *   [1 byte:  VIRP_FRAME_VERSION (0x02)]
 *   [N bytes: request payload (JSON)]
 *
 * The length prefix is payload-only. A 100-byte JSON request has
 * length = 101 (1 version byte + 100 payload bytes), and 105 bytes
 * on the wire (4 prefix + 101 frame).
 *
 * v1 detection: if the first byte is non-zero (e.g. '{' = 0x7B from
 * raw JSON), this is a v1 unframed client. The server responds with
 * a raw 4-byte VIRP_ERR_PROTOCOL_VERSION and closes.
 * ========================================================================= */

/*
 * Read exactly `len` bytes from fd into buf.
 * Handles partial reads, distinguishes EAGAIN/EINTR from EOF.
 * Returns 0 on success, -1 on EOF or fatal error.
 */
static int recv_exact(int fd, void *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, (uint8_t *)buf + got, len - got, 0);
        if (n > 0) {
            got += (size_t)n;
        } else if (n == 0) {
            /* EOF — peer closed */
            return -1;
        } else {
            /* n < 0: check errno */
            if (errno == EINTR)
                continue;   /* signal interrupted — retry */
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return -1;  /* timeout or non-blocking — treat as failure */
            return -1;      /* other error */
        }
    }
    return 0;
}

/*
 * Send exactly `len` bytes to fd — symmetric counterpart to recv_exact().
 *
 * SOCK_STREAM permits partial writes even on Unix domain sockets (most
 * visibly when a signal lands mid-send), and a partially written 4-byte
 * length prefix permanently desynchronizes framing for the connection.
 * So: loop until every byte is out, retry on EINTR.
 *
 * EAGAIN/EWOULDBLOCK is fatal by design. Client fds here are blocking
 * (only SO_RCVTIMEO is set), so EAGAIN can only appear if someone later
 * configures SO_SNDTIMEO — and a frame cannot be resumed after a
 * mid-frame timeout. On a hypothetical non-blocking fd, retrying
 * without poll() would spin. Either way the framing on this connection
 * is unrecoverable: return -1 and let the caller treat it as dead.
 *
 * MSG_NOSIGNAL on every daemon send: a client that closes before
 * reading its response would otherwise raise SIGPIPE, whose default
 * action kills the whole daemon. Both mains also SIG_IGN SIGPIPE; the
 * per-send flag keeps the guarantee even if a future entry path
 * forgets (send returns -1/EPIPE instead and we report failure — the
 * peer is gone and the caller closes the fd).
 *
 * Returns 0 on success, -1 on failure. On failure the connection must
 * be closed, never written to again: any bytes already sent are a torn
 * frame. Non-static so tests/test_onode.c can drive it directly over a
 * socketpair.
 */
int send_all(int fd, const void *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, (const uint8_t *)buf + sent, len - sent,
                         MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && errno == EINTR)
                continue;   /* signal interrupted — retry */
            return -1;      /* EAGAIN, EPIPE, 0-byte write: dead */
        }
        sent += (size_t)n;
    }
    return 0;
}

/*
 * Send a framed response: [4-byte big-endian length][payload].
 * Length covers the payload only, not the 4-byte prefix itself.
 *
 * Returns 0 on success, -1 on failure. On failure the connection is
 * dead (see send_all) — callers must not attempt further sends on it;
 * every handle_client path closes the fd before returning.
 *
 * Non-static so tests/test_onode.c can drive the framing path itself
 * under forced short writes — same precedent as send_all above.
 */
int send_framed(int fd, const void *buf, size_t len)
{
    uint32_t net_len = htonl((uint32_t)len);
    if (send_all(fd, &net_len, 4) < 0)
        return -1;
    if (len > 0 && send_all(fd, buf, len) < 0)
        return -1;
    return 0;
}

/*
 * Send a framed 4-byte error code. Same failure contract as send_framed.
 */
static int send_framed_error(int fd, virp_error_t err)
{
    uint32_t err_code = htonl((uint32_t)err);
    return send_framed(fd, &err_code, 4);
}

/*
 * Is this exactly a SHA-256 digest in hex — 64 chars, hex only?
 *
 * sign_intent and sign_outcome exist to witness a digest the CALLER
 * already computed. Their contract has always been "64 hex chars", but
 * it lived only in a comment: the handlers checked that req.command was
 * non-empty and then HMAC'd whatever was there with the O-Key.
 * req.command is char[1024], so that was a signing oracle — a caller
 * could obtain an O-Key-authenticated, GREEN-tier observation over up
 * to 1023 bytes of its own choosing, which is precisely the "text that
 * looks like an observation vs. an actual observation" distinction the
 * protocol exists to make unforgeable.
 *
 * Enforcing the digest shape removes the attacker's choice of content:
 * a 64-hex string is a commitment to a preimage, not a message. Note
 * this deliberately does NOT try to prove the digest corresponds to any
 * real intent — the O-Node cannot know that. It only guarantees the
 * signed bytes carry no attacker-authored text.
 *
 * Non-static so tests/test_onode.c can assert the predicate directly in
 * addition to driving both handlers over the socket.
 */
bool onode_is_sha256_hex(const char *s)
{
    if (!s) return false;
    return strlen(s) == 64 &&
           strspn(s, "0123456789abcdefABCDEF") == 64;
}

/*
 * SO_PEERCRED accept-path gate.
 *
 * Checks the connected peer's UID against state->socket_allowed_uids.
 * On success returns true and writes cred info to *out_uid / *out_pid
 * for logging. On failure returns false; the caller must close the fd.
 */
static bool peer_uid_allowed(onode_state_t *state, int client_fd,
                             uid_t *out_uid, pid_t *out_pid)
{
    struct ucred cred;
    socklen_t len = sizeof(cred);
    memset(&cred, 0, sizeof(cred));
    if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0) {
        /* If we cannot read creds, fail closed — do not leak capability. */
        perror("[O-Node] getsockopt SO_PEERCRED");
        if (out_uid) *out_uid = (uid_t)-1;
        if (out_pid) *out_pid = 0;
        return false;
    }
    if (out_uid) *out_uid = cred.uid;
    if (out_pid) *out_pid = cred.pid;

    for (size_t i = 0; i < state->socket_allowed_uids_count; i++) {
        if (state->socket_allowed_uids[i] == cred.uid)
            return true;
    }
    return false;
}

/*
 * GATE 3 — observation signature binding, fail-closed, all three wire
 * formats.
 *
 * Before this gate, artifact_type="observation" accepted ANY bytes that
 * hashed to their declared commitment. GATE 2 binds hash-to-body; it
 * says nothing about who produced the body. A socket client could hand
 * the daemon a fabricated device output, and the entry it got back
 * carried a K_chain HMAC indistinguishable from a daemon-minted one.
 * That is the "CHAIN_APPEND is not a signing oracle" property finished:
 * GATE 1 reserved the type namespace, GATE 2 bound the bytes to the
 * commitment, and GATE 3 binds the bytes to a signing key.
 *
 * Dispatch is on byte 0 of the DECODED body and is explicit, never
 * heuristic. An unknown version is refused rather than guessed at.
 *
 *   v1  — HMAC under the O-Key. The daemon always holds it, and every
 *         observation in the production chain today is v1.
 *   v2  — HMAC under a derived SESSION key. The daemon holds exactly one
 *         session at a time, so the message's own session_id must match
 *         the active session; anything else cannot be checked and is
 *         refused. Signature-only: replay/freshness/command binding are
 *         an accepting endpoint's rules, and re-applying replay
 *         rejection here would refuse the very message being registered.
 *   v3  — Ed25519 under the O-Node's observation key. Verification needs
 *         only the PUBLIC half, but the daemon must have the keypair
 *         loaded to know which key to trust; with none loaded a v3 body
 *         is refused, not recorded unverified.
 *
 * WHAT THIS GATE DOES NOT CLOSE: a commitment-only append (no body)
 * cannot be signature-checked, because there are no bytes to check.
 * Those stay legal — they are 3.8% of the live chain, the deliberate
 * path for observations past the 8192-byte artifact field — and they
 * are honestly graded: every reader reports an entry with no stored
 * body as UNVERIFIABLE, never as a passing signature. A caller can
 * still register an arbitrary hash; what it cannot do is obtain an
 * entry that any verifier will report as authentic.
 */

/*
 * Extract a fed_outcome's "observation_sha256" into out_hex.
 *
 * Deliberately a narrow scanner, not a JSON parser: the only thing
 * GATE 4 needs is one 64-hex-character string under one known key, and
 * pulling a parser onto the append path to get it would be a far larger
 * surface than the question justifies. Anything that is not a quoted
 * 64-char lowercase-hex value — key absent, JSON null, wrong length,
 * non-hex byte — returns false, and the caller treats false as a
 * refusal. Fail-closed: a body this cannot read is a body whose citation
 * cannot be checked, which is the case the gate exists to stop.
 *
 * Scans the literal body bytes. fed_outcome bodies are plain JSON (the
 * base64: form is for signed wire messages), so no decode step is needed
 * and none is done — a decoder here could disagree with the one GATE 2
 * hashed with, and then the field checked would not be the field stored.
 */
static bool fed_outcome_observation_hash(const char *body, char out_hex[65])
{
    static const char KEY[] = "\"observation_sha256\"";
    const char *p = strstr(body, KEY);
    if (!p) return false;
    p += sizeof(KEY) - 1;

    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != ':') return false;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != '"') return false;   /* null, or anything not a string */
    p++;

    for (int i = 0; i < 64; i++) {
        char c = p[i];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hex) return false;
        out_hex[i] = c;
    }
    if (p[64] != '"') return false;  /* longer than 64 — not a SHA-256 hex */
    out_hex[64] = '\0';
    return true;
}

/*
 * WHAT artifact_hash COMMITS TO — decided, not incidental (F2 follow-up).
 *
 * The commitment is over the FULL submitted message bytes, not over the
 * canonical signed span. Every client computes it that way
 * (autopilot/virp_autopilot.py sha256(raw_obs), and the same in
 * virp_evidence.py / virp_config_backup.py / virp-tool), GATE 2
 * recomputes it that way, and this gate verifies THOSE bytes.
 *
 * That is only safe because the full message is not malleable, which
 * is exactly what commit 61a92e9b bought. Before it, a v3 message's 32
 * HMAC bytes sat outside the Ed25519 signed span, so one attested
 * observation had unlimited valid byte strings and therefore unlimited
 * distinct artifact_hashes. Now the signed span is
 * header || payload || hmac, so the ONLY region of a v3 message outside
 * the signature is the 64-byte signature itself — and that is pinned
 * too: libsodium refuses a non-canonical S, and the byte-by-byte sweep
 * in tests/test_obs_ed25519_forge.c walks the signature bytes as well
 * as the signed span. v1 and v2 have deterministic HMAC trailers and
 * were never malleable.
 *
 * Consequence to hold on to: hash-over-full-message is load-bearing on
 * that non-malleability. Any future format that puts an unsigned or
 * attacker-writable region inside the message must either sign it or
 * move the commitment to the canonical span.
 */
static virp_error_t chain_append_verify_observation(
    onode_state_t *state, const char *artifact_content, const char **why)
{
    /* Per-call, NOT static: this runs on concurrent connection-worker
     * threads, and a shared buffer let one request's bytes be verified
     * against another's decode (external review 2026-08-17). 64KB is
     * fine on the default worker stack. */
    uint8_t raw[VIRP_MAX_MESSAGE_SIZE];
    size_t raw_len = 0;

    virp_error_t err = virp_chain_artifact_bytes(artifact_content, raw,
                                                 sizeof(raw), &raw_len);
    if (err != VIRP_OK) { *why = "body does not decode"; return err; }
    if (raw_len < 1) { *why = "empty body"; return VIRP_ERR_INVALID_LENGTH; }

    switch (raw[0]) {
    case VIRP_VERSION: {          /* v1 */
        virp_header_t hdr;
        err = virp_validate_message(raw, raw_len, &state->okey, &hdr);

        /*
         * ROTATION GRACE WINDOW. The current key is always tried first;
         * only its failure reaches here. An observation minted before a
         * rotation and registered after it is signed under the previous
         * key, and without this it would be refused and lost — no client
         * retries a registration.
         *
         * Bounded three ways: the key must have been explicitly loaded,
         * the deadline must not have passed, and it is verify-only —
         * this is the sole read of prev_okey in the daemon.
         */
        if (err != VIRP_OK && state->prev_okey_loaded) {
            struct timespec now;
            clock_gettime(CLOCK_REALTIME, &now);
            uint64_t now_ns = (uint64_t)now.tv_sec * 1000000000ULL +
                              (uint64_t)now.tv_nsec;
            if (now_ns < state->prev_okey_deadline_ns) {
                virp_error_t perr = virp_validate_message(raw, raw_len,
                                                          &state->prev_okey,
                                                          &hdr);
                if (perr == VIRP_OK) {
                    state->prev_okey_accepts++;
                    fprintf(stderr, "[O-Node] chain_append: observation "
                            "verified under the PREVIOUS O-Key (rotation "
                            "grace window, %u accepted so far; %llu s of "
                            "window left). This is expected only while "
                            "in-flight observations from before a rotation "
                            "drain.\n",
                            state->prev_okey_accepts,
                            (unsigned long long)
                              ((state->prev_okey_deadline_ns - now_ns)
                               / 1000000000ULL));
                    err = VIRP_OK;
                }
            }
        }

        if (err != VIRP_OK) { *why = "v1 O-Key signature invalid"; return err; }
        if (hdr.type != VIRP_MSG_OBSERVATION) {
            *why = "v1 message is not an OBSERVATION";
            return VIRP_ERR_INVALID_TYPE;
        }
        return VIRP_OK;
    }
    case VIRP_VERSION_2: {
        virp_obs_header_v2_t vh;
        if (!state->ctx || virp_session_state(state->ctx) != VIRP_SESSION_ACTIVE
            || !state->ctx->session.session_key_valid) {
            *why = "v2 body but no active session key to verify it under";
            return VIRP_ERR_SESSION_INVALID;
        }
        /* The message must belong to the session we actually hold. */
        if (raw_len >= VIRP_OBS_V2_HEADER_SIZE &&
            !virp_consttime_eq(raw + 28, state->ctx->session.session_id, 16)) {
            *why = "v2 body belongs to a different session";
            return VIRP_ERR_SESSION_INVALID;
        }
        err = virp_verify_observation_v2_signature(
                  state->ctx->session.session_key, raw, raw_len, &vh);
        if (err != VIRP_OK) { *why = "v2 session-HMAC invalid"; return err; }
        return VIRP_OK;
    }
    case VIRP_VERSION_3: {
        if (!state->obskey_loaded) {
            *why = "v3 body but no observation-signing key is loaded";
            return VIRP_ERR_KEY_NOT_LOADED;
        }
        err = virp_verify_observation_ed25519(state->obskey.public_key,
                                              raw, raw_len, NULL, NULL, NULL);
        if (err != VIRP_OK) { *why = "v3 Ed25519 signature invalid"; return err; }
        return VIRP_OK;
    }
    default:
        *why = "unknown observation wire version";
        return VIRP_ERR_VERSION_MISMATCH;
    }
}

/*
 * Per-uid action-allowlist decision for a SOCKET request. Returns true if
 * the request MUST be refused (the caller then sends a typed error and
 * closes — zero dispatch). Non-static so the fail-open regression can
 * drive it directly. Two fail-CLOSED refusal reasons:
 *
 *   1. UNKNOWN IDENTITY — client_uid == (uid_t)-1. The daemon has no peer
 *      credential for this socket. This must NEVER fall through to
 *      node-wide policy: the earlier bug re-read SO_PEERCRED in the worker
 *      and, on a failed read, set (uid_t)-1, which is absent from the
 *      per-uid map and so simply SKIPPED it — handing the node-wide
 *      ceiling and the full action switch to an unidentified caller. The
 *      accept path validates a real uid and it is now threaded in, so this
 *      cannot arise in normal flow; if it ever does, unknown identity
 *      means NO action.
 *   2. ACTION NOT ALLOWED — a uid present in socket_uid_action_allow may
 *      request only its listed actions. A uid ABSENT from the map is
 *      unrestricted (existing principals are unchanged).
 */
bool onode_uid_request_refused(const onode_state_t *state,
                               uid_t client_uid, onode_action_t action)
{
    if (!state)
        return true;
    if (client_uid == (uid_t)-1)
        return true;                    /* unknown identity — no action */
    for (size_t i = 0; i < state->uid_action_count; i++) {
        if (state->uid_action_uids[i] != client_uid)
            continue;
        for (size_t k = 0; k < state->uid_action_set_counts[i]; k++)
            if (state->uid_action_sets[i][k] == action)
                return false;           /* listed — allowed */
        return true;                    /* in map, action not listed — refuse */
    }
    return false;                       /* uid not in map — unrestricted */
}

static void handle_client(onode_state_t *state, int client_fd,
                          uid_t client_uid)
{
    char recv_buf[ONODE_MAX_REQUEST_SIZE];
    uint8_t resp_buf[VIRP_MAX_MESSAGE_SIZE];
    size_t resp_len = 0;

    /* Set receive timeout */
    struct timeval tv = { .tv_sec = ONODE_RECV_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* client_uid is the peer uid the ACCEPT loop validated via SO_PEERCRED
     * (peer_uid_allowed) and threaded in through worker_arg. There is
     * deliberately NO second SO_PEERCRED read here: the previous code
     * re-read it and, on a failed read, fell back to (uid_t)-1 — which is
     * absent from socket_uid_action_allow and so SKIPPED the per-uid map,
     * handing the request the node-wide ceiling and the full action switch.
     * That was fail-OPEN relative to per-uid controls, not fail-closed as
     * its comment claimed. With the uid threaded there is no read to fail;
     * and an unknown identity (client_uid == (uid_t)-1) is refused by
     * onode_uid_request_refused() below rather than defaulting to node-wide
     * policy. Carried explicitly into every execute path, including the
     * batch fan-out. */

    /* ── v2 framed receive ───────────────────────────────────────────
     * Read 4-byte big-endian length prefix. If the first byte is
     * non-zero, the client is sending raw JSON (v1) — reject cleanly. */
    uint8_t len_buf[4];
    if (recv_exact(client_fd, len_buf, 4) < 0) {
        close(client_fd);
        return;
    }

    if (len_buf[0] != 0x00) {
        /* v1 client: first byte is part of JSON (e.g. '{' = 0x7B).
         * Send unframed error so the v1 client can read it. */
        uint32_t err_code = htonl((uint32_t)VIRP_ERR_PROTOCOL_VERSION);
        /* send_all carries MSG_NOSIGNAL: this send fires before the
         * client is trusted — a peer that connects and instantly closes
         * must not SIGPIPE the daemon. Failure needs no handling beyond
         * the close below; the courtesy error just didn't arrive. */
        (void)send_all(client_fd, &err_code, 4);
        close(client_fd);
        return;
    }

    uint32_t frame_len = ((uint32_t)len_buf[0] << 24) |
                         ((uint32_t)len_buf[1] << 16) |
                         ((uint32_t)len_buf[2] <<  8) |
                         ((uint32_t)len_buf[3]);

    if (frame_len < 2) {
        /* Too small — need at least the version byte + 1 payload byte. */
        send_framed_error(client_fd, VIRP_ERR_INVALID_LENGTH);
        close(client_fd);
        return;
    }
    if (frame_len > sizeof(recv_buf) - 1) {
        /*
         * Reject oversize frames with MESSAGE_TOO_LARGE so clients can
         * distinguish "you sent junk" from "your payload won't fit".
         * Bound check happens before we read a single payload byte.
         */
        send_framed_error(client_fd, VIRP_ERR_MESSAGE_TOO_LARGE);
        close(client_fd);
        return;
    }

    /* Read exactly frame_len bytes */
    char frame_buf[ONODE_MAX_REQUEST_SIZE];
    if (recv_exact(client_fd, frame_buf, frame_len) < 0) {
        close(client_fd);
        return;
    }

    /* Check frame version byte */
    if ((uint8_t)frame_buf[0] != VIRP_FRAME_VERSION) {
        send_framed_error(client_fd, VIRP_ERR_PROTOCOL_VERSION);
        close(client_fd);
        return;
    }

    /* Extract JSON payload (skip version byte) */
    size_t json_len = frame_len - 1;
    memcpy(recv_buf, frame_buf + 1, json_len);
    recv_buf[json_len] = '\0';

    /* Parse request */
    onode_request_t req;
    if (!parse_request(recv_buf, &req)) {
        /* Bad request — send error code */
        send_framed_error(client_fd, VIRP_ERR_INVALID_TYPE);
        close(client_fd);
        return;
    }

    virp_error_t err;

    /*
     * Per-uid action allowlist (Item 8) — checked ONCE, here, before the
     * dispatch switch, via onode_uid_request_refused(). It refuses an
     * unknown identity (uid == (uid_t)-1) and a uid whose
     * socket_uid_action_allow set does not list req.action; a uid absent
     * from the map takes the switch exactly as before. The refusal is a
     * typed policy error and the daemon carries on. Zero dispatch: the
     * action switch below never runs for a refused request.
     */
    if (onode_uid_request_refused(state, client_uid, req.action)) {
        fprintf(stderr, "[O-Node] POLICY REFUSAL: uid %ld action '%s' "
                "refused — unknown identity or not in the uid's "
                "socket_uid_action_allow set\n",
                (client_uid == (uid_t)-1) ? -1L : (long)client_uid,
                onode_action_name(req.action));
        send_framed_error(client_fd, VIRP_ERR_ACTION_FORBIDDEN);
        close(client_fd);
        return;
    }

    switch (req.action) {
    case ONODE_ACTION_EXECUTE:
        if (req.device[0] == '\0' || req.command[0] == '\0') {
            send_framed_error(client_fd, VIRP_ERR_NULL_PTR);
            break;
        }
        err = onode_execute_obs_ex(state, req.device, req.command,
                                req.obs_version,
                                req.proposal_id[0] ? req.proposal_id : NULL,
                                client_uid,
                                resp_buf, sizeof(resp_buf), &resp_len);
        if (err == VIRP_OK && resp_len > 0)
            send_framed(client_fd, resp_buf, resp_len);
        else {
            send_framed_error(client_fd, err);
        }
        break;

    case ONODE_ACTION_HEALTH:
        if (req.device[0] == '\0') {
            send_framed_error(client_fd, VIRP_ERR_NULL_PTR);
            break;
        }
        /* Health check — execute a simple command */
        err = onode_execute_obs(state, req.device, "show version",
                                req.obs_version,
                                resp_buf, sizeof(resp_buf), &resp_len);
        if (err == VIRP_OK && resp_len > 0)
            send_framed(client_fd, resp_buf, resp_len);
        else {
            send_framed_error(client_fd, err);
        }
        break;

    case ONODE_ACTION_HEARTBEAT:
        err = onode_heartbeat(state, resp_buf, sizeof(resp_buf), &resp_len);
        if (err == VIRP_OK && resp_len > 0)
            send_framed(client_fd, resp_buf, resp_len);
        break;

    case ONODE_ACTION_LIST:
        err = onode_list_devices(state, resp_buf, sizeof(resp_buf), &resp_len);
        if (err == VIRP_OK && resp_len > 0)
            send_framed(client_fd, resp_buf, resp_len);
        break;

    case ONODE_ACTION_LIST_FLEET:
        err = onode_list_fleet(state, resp_buf, sizeof(resp_buf), &resp_len);
        if (err == VIRP_OK && resp_len > 0)
            send_framed(client_fd, resp_buf, resp_len);
        break;

    case ONODE_ACTION_SIGN_INTENT:
        if (req.command[0] == '\0') {
            send_framed_error(client_fd, VIRP_ERR_NULL_PTR);
            break;
        }
        /*
         * ENFORCE the 64-hex contract before signing (audit §4.1).
         * Documented since the handler was written, checked only from
         * here on: without it this is a signing oracle over up to 1023
         * caller-chosen bytes.
         */
        if (!onode_is_sha256_hex(req.command)) {
            fprintf(stderr, "[O-Node] sign_intent rejected: command is not "
                            "a 64-char SHA-256 hex digest (len=%zu)\n",
                    strlen(req.command));
            send_framed_error(client_fd, VIRP_ERR_INVALID_LENGTH);
            break;
        }
        /* req.command contains SHA256 hex of intent JSON (64 chars) */
        err = virp_build_observation(resp_buf, sizeof(resp_buf), &resp_len,
                                      state->node_id, onode_next_seq(state),
                                      VIRP_OBS_INTENT_SIGNED, VIRP_SCOPE_LOCAL,
                                      (const uint8_t *)req.command,
                                      (uint16_t)strlen(req.command),
                                      &state->okey);
        if (err == VIRP_OK && resp_len > 0) {
            if (send_framed(client_fd, resp_buf, resp_len) == 0)
                onode_inc_observations(state);
        } else {
            send_framed_error(client_fd, err);
        }
        break;

    case ONODE_ACTION_SIGN_OUTCOME:
        if (req.command[0] == '\0') {
            send_framed_error(client_fd, VIRP_ERR_NULL_PTR);
            break;
        }
        /* Same oracle, same enforcement — see SIGN_INTENT above (§4.1). */
        if (!onode_is_sha256_hex(req.command)) {
            fprintf(stderr, "[O-Node] sign_outcome rejected: command is not "
                            "a 64-char SHA-256 hex digest (len=%zu)\n",
                    strlen(req.command));
            send_framed_error(client_fd, VIRP_ERR_INVALID_LENGTH);
            break;
        }
        /* req.command contains SHA256 hex of outcome JSON (64 chars) */
        err = virp_build_observation(resp_buf, sizeof(resp_buf), &resp_len,
                                      state->node_id, onode_next_seq(state),
                                      VIRP_OBS_OUTCOME_SIGNED, VIRP_SCOPE_LOCAL,
                                      (const uint8_t *)req.command,
                                      (uint16_t)strlen(req.command),
                                      &state->okey);
        if (err == VIRP_OK && resp_len > 0) {
            if (send_framed(client_fd, resp_buf, resp_len) == 0)
                onode_inc_observations(state);
        } else {
            send_framed_error(client_fd, err);
        }
        break;

    case ONODE_ACTION_CHAIN_APPEND:
        if (!state->chain_enabled) {
            send_framed_error(client_fd, VIRP_ERR_CHAIN_DB);
            break;
        }
        /*
         * Item 8 type-narrowing: a uid in the action allowlist map is
         * a restricted federated principal — its chain_append reach is
         * the three federation types and NOTHING else. Even types every
         * other client may submit (observation, evidence_item, …) are
         * refused here; the action allowlist above already admitted the
         * chain_append ACTION, this guard narrows the TYPE. Uids absent
         * from the map are untouched.
         *
         * fed_observation was added 2026-08-16. The original narrowing
         * admitted only fed_request/fed_outcome, which cut the middle
         * append out of the bridge's three-step protocol (request →
         * body → outcome): the daemon refused the signed observation
         * while still accepting the outcome whose observation_sha256
         * named it, so from 2026-08-11 17:44 UTC every federated read
         * recorded a pointer to a body that was never stored. Naming
         * the body fed_observation rather than readmitting the reserved
         * "observation" keeps Item 8's actual point — a restricted
         * principal cannot submit a daemon-minted semantic type — while
         * letting the evidence land. GATE 3 below verifies its
         * signature, so the name is a namespace, not a waiver.
         */
        {
            bool uid_restricted = false;
            for (size_t i = 0; i < state->uid_action_count; i++) {
                if (state->uid_action_uids[i] == client_uid) {
                    uid_restricted = true;
                    break;
                }
            }
            if (uid_restricted &&
                strcmp(req.artifact_type, "fed_request") != 0 &&
                strcmp(req.artifact_type, "fed_observation") != 0 &&
                strcmp(req.artifact_type, "fed_outcome") != 0) {
                fprintf(stderr, "[O-Node] POLICY REFUSAL: uid %u "
                        "chain_append artifact_type '%s' — a restricted "
                        "principal may append only fed_request/"
                        "fed_observation/fed_outcome (session=%s id=%s)\n",
                        (unsigned)client_uid, req.artifact_type,
                        req.session_id, req.artifact_id);
                send_framed_error(client_fd, VIRP_ERR_ACTION_FORBIDDEN);
                break;
            }
        }
        if (req.session_id[0] == '\0' || req.artifact_type[0] == '\0' ||
            req.artifact_id[0] == '\0' || req.artifact_hash[0] == '\0') {
            send_framed_error(client_fd, VIRP_ERR_NULL_PTR);
            break;
        }
        /*
         * CHAIN_APPEND is not a signing oracle (adversarial audit
         * 2026-08-06). Everything below this point gets a K_chain HMAC,
         * so a caller holding no key could otherwise induce an
         * authenticated entry a reader cannot tell from a daemon-minted
         * one. Two gates, both fail-closed, both on the EXTERNAL path
         * only — internal callers reach the chain writer directly and
         * mint their own hashes from bodies they built.
         */

        /* GATE 1 — type namespace. Daemon-minted semantic types are
         * refused outright, and unknown types are refused rather than
         * recorded as if they meant something. */
        if (virp_chain_type_is_daemon_reserved(req.artifact_type)) {
            fprintf(stderr, "[O-Node] chain_append REJECTED: artifact_type "
                    "'%s' is daemon-generated and may not be submitted by a "
                    "socket client (session=%s id=%s)\n",
                    req.artifact_type, req.session_id, req.artifact_id);
            send_framed_error(client_fd, VIRP_ERR_INVALID_TYPE);
            break;
        }
        if (!virp_chain_type_is_external_allowed(req.artifact_type)) {
            fprintf(stderr, "[O-Node] chain_append REJECTED: unknown "
                    "artifact_type '%s' (session=%s id=%s)\n",
                    req.artifact_type, req.session_id, req.artifact_id);
            send_framed_error(client_fd, VIRP_ERR_INVALID_TYPE);
            break;
        }

        /* GATE 2 — body binding. When a body is submitted the daemon
         * recomputes SHA-256 over the exact received bytes and refuses a
         * declared hash that does not match, constant-time.
         *
         * The INDIRECT types are the one exception and are NOT a hole
         * left open for convenience: their artifact_hash commits to a
         * signed observation the chain does not retain (the autopilot
         * comparator and chainwalk register the verdict JSON as the body
         * while committing to the signed message), so sha256(body) can
         * never match by design. They still must supply a non-empty body,
         * and the verifier grades them UNVERIFIABLE rather than passing
         * them silently. With GATE 1 above reserving every semantic type,
         * the exception is exactly two non-semantic type names wide.
         *
         * DEFERRED: making the indirection explicit as a commitment_mode
         * field inside the HMAC'd canonical object would let both modes
         * be verified instead of one being UNVERIFIABLE. That changes the
         * canonical form, so it belongs with the provenance field in a
         * chain-format change window. */
        if (req.artifact_content[0] != '\0') {
            if (virp_chain_type_is_indirect(req.artifact_type)) {
                /* body present is all that can be required here */
            } else {
                char computed[65];
                virp_error_t derr = virp_chain_artifact_digest(
                                        req.artifact_content, computed);
                if (derr != VIRP_OK) {
                    fprintf(stderr, "[O-Node] chain_append REJECTED: "
                            "artifact_content is not decodable (session=%s "
                            "id=%s)\n", req.session_id, req.artifact_id);
                    send_framed_error(client_fd, derr);
                    break;
                }
                if (strlen(req.artifact_hash) != 64 ||
                    virp_consttime_eq(computed, req.artifact_hash, 64) != 1) {
                    fprintf(stderr, "[O-Node] chain_append REJECTED: declared "
                            "artifact_hash does not match sha256 of the "
                            "submitted body (session=%s id=%s type=%s)\n",
                            req.session_id, req.artifact_id,
                            req.artifact_type);
                    send_framed_error(client_fd, VIRP_ERR_CHAIN_BROKEN);
                    break;
                }

                /* GATE 3 — an "observation" must actually be a signed
                 * observation. Runs only once GATE 2 has proved the body
                 * is the one the commitment names, so what gets verified
                 * is exactly what gets recorded.
                 *
                 * fed_observation is held to the identical standard. It
                 * carries the same signed wire message under a name a
                 * restricted principal is allowed to use; if it could
                 * skip this gate, the rename would have converted a
                 * verified type into an unverified one and handed the
                 * bridge a way to store arbitrary bytes as evidence. */
                if (strcmp(req.artifact_type, "observation") == 0 ||
                    strcmp(req.artifact_type, "fed_observation") == 0) {
                    const char *why = "unspecified";
                    virp_error_t verr = chain_append_verify_observation(
                                            state, req.artifact_content, &why);
                    if (verr != VIRP_OK) {
                        fprintf(stderr, "[O-Node] chain_append REJECTED: "
                                "observation body failed signature "
                                "verification — %s (session=%s id=%s err=%s)\n",
                                why, req.session_id, req.artifact_id,
                                virp_error_str(verr));
                        send_framed_error(client_fd, verr);
                        break;
                    }
                }
            }
        } else if (virp_chain_type_is_indirect(req.artifact_type)) {
            fprintf(stderr, "[O-Node] chain_append REJECTED: artifact_type "
                    "'%s' commits indirectly and must carry a body "
                    "(session=%s id=%s)\n",
                    req.artifact_type, req.session_id, req.artifact_id);
            send_framed_error(client_fd, VIRP_ERR_NULL_PTR);
            break;
        }

        /* GATE 4 — a fed_outcome may not cite evidence the chain cannot
         * produce. The outcome's observation_sha256 is the single link
         * from "this command ran and here is what came back" to the
         * signed bytes that prove it; an outcome whose cited body is not
         * in artifacts is an unbacked claim that still reads, to every
         * downstream consumer, exactly like a backed one.
         *
         * This is the fail-closed half of the 2026-08-16 fix. The Item 8
         * narrowing above silently removed the bridge's ability to store
         * that body while leaving its ability to cite it intact, and the
         * mismatch ran for five days because nothing on the write path
         * checked. Refusing here means the same class of breakage stops
         * the outcome instead of recording a dangling pointer.
         *
         * ORDERING CONTRACT: the body must be appended BEFORE the
         * outcome that names it. That is already the bridge's protocol
         * (fed_request → fed_observation → fed_outcome); this gate makes
         * it enforced rather than assumed. A bridge that reversed the
         * two would now be told so on the second append.
         *
         * Scoped to fed_outcome. Other types are unaffected, and an
         * outcome with no body at all is refused too: an outcome that
         * cites nothing is the unbacked claim in its purest form (16
         * such rows exist on the live chain, all inside the window). */
        if (strcmp(req.artifact_type, "fed_outcome") == 0) {
            char cited[65];
            if (req.artifact_content[0] == '\0' ||
                !fed_outcome_observation_hash(req.artifact_content, cited)) {
                fprintf(stderr, "[O-Node] chain_append REJECTED: fed_outcome "
                        "carries no readable observation_sha256 — an outcome "
                        "must cite the signed body it reports on "
                        "(session=%s id=%s)\n",
                        req.session_id, req.artifact_id);
                send_framed_error(client_fd, VIRP_ERR_ACTION_FORBIDDEN);
                break;
            }
            bool body_stored = false;
            virp_error_t cerr = virp_chain_artifact_body_exists(
                                    &state->chain, cited, &body_stored);
            if (cerr != VIRP_OK) {
                fprintf(stderr, "[O-Node] chain_append REJECTED: could not "
                        "check whether fed_outcome's cited observation %s is "
                        "stored (session=%s id=%s err=%s)\n",
                        cited, req.session_id, req.artifact_id,
                        virp_error_str(cerr));
                send_framed_error(client_fd, cerr);
                break;
            }
            if (!body_stored) {
                /* The cited body is not in artifacts. That is LEGITIMATE for
                 * an oversized observation: a GREEN output past the daemon's
                 * 8192-byte inline field is chained commitment-only (the
                 * bridge / autopilot omits artifact_content). It is only an
                 * UNBACKED claim if no observation entry commits to the cited
                 * hash at all. If one does, the outcome is backed by the
                 * chain and the un-retained body is graded UNVERIFIABLE (not
                 * PASS) by every reader — an honest record, not a dangling
                 * pointer. (2026-08-18 regression: requiring the body here
                 * left oversized GREEN observations' outcomes unappendable —
                 * correlations 42b7b9dc / c5373129.) */
                bool committed = false;
                virp_error_t eerr = virp_chain_entry_commits_to(
                                        &state->chain, cited, &committed);
                if (eerr != VIRP_OK) {
                    fprintf(stderr, "[O-Node] chain_append REJECTED: could "
                            "not check whether the chain commits to "
                            "fed_outcome's cited observation %s (session=%s "
                            "id=%s err=%s)\n", cited, req.session_id,
                            req.artifact_id, virp_error_str(eerr));
                    send_framed_error(client_fd, eerr);
                    break;
                }
                if (!committed) {
                    fprintf(stderr, "[O-Node] chain_append REJECTED: "
                            "fed_outcome cites observation %s, which no chain "
                            "entry commits to — append the fed_observation "
                            "before the outcome that names it (session=%s "
                            "id=%s)\n",
                            cited, req.session_id, req.artifact_id);
                    send_framed_error(client_fd, VIRP_ERR_ACTION_FORBIDDEN);
                    break;
                }
                /* commitment-only observation, backed by the chain: accept */
            }
        }

        /* GATE 5 — federation retry idempotency — is NOT checked here.
         * It used to be: a virp_chain_artifact_id_conflict() probe ran
         * at this point, but a probe outside the append transaction is
         * check-then-act — two concurrent submissions of the same
         * correlation id with different bytes could both pass it and
         * both store (F4, external review 2026-08-17). The enforcing
         * query now runs inside chain_append_locked's own BEGIN
         * IMMEDIATE, and the append below returns
         * VIRP_ERR_DUPLICATE_MISMATCH — distinct from -18 (the
         * submission disagreeing with itself) and -50 (policy) — for a
         * federation id reused with different bytes. */
        {
            /* Entry and (optional) raw content commit in one transaction.
             * A content-store failure now fails the whole request with a
             * typed error instead of acking an entry whose committed body
             * was silently dropped. Content-less appends remain valid:
             * commitment-only is a caller choice, not a failure mode. */
            virp_chain_entry_t chain_entry;
            err = virp_chain_append_with_artifact(&state->chain,
                                     req.session_id,
                                     req.artifact_type, req.artifact_id,
                                     req.artifact_hash,
                                     req.artifact_content[0] != '\0'
                                         ? req.artifact_content : NULL,
                                     &chain_entry);
            if (err != VIRP_OK) {
                if (err == VIRP_ERR_DUPLICATE_MISMATCH)
                    fprintf(stderr, "[O-Node] chain_append REJECTED: "
                            "federation artifact_id '%s' is already stored "
                            "with a different body hash — a retry must "
                            "resend identical bytes, or mint a new "
                            "correlation (session=%s type=%s)\n",
                            req.artifact_id, req.session_id,
                            req.artifact_type);
                send_framed_error(client_fd, err);
                break;
            }
            /* JSON-encode the chain entry as observation payload */
            char json_buf[2048];
            int jlen = snprintf(json_buf, sizeof(json_buf),
                "{\"chain_entry_hash\":\"%s\","
                "\"previous_entry_hash\":\"%s\","
                "\"sequence\":%lld,"
                "\"session_id\":\"%s\","
                "\"signer_node_id\":%u,"
                "\"signer_org_id\":\"%s\"}",
                chain_entry.chain_entry_hash,
                chain_entry.previous_entry_hash,
                (long long)chain_entry.sequence,
                chain_entry.session_id,
                chain_entry.signer_node_id,
                chain_entry.signer_org_id);
            err = virp_build_observation(resp_buf, sizeof(resp_buf), &resp_len,
                                          state->node_id, onode_next_seq(state),
                                          VIRP_OBS_CHAIN_ENTRY, VIRP_SCOPE_LOCAL,
                                          (const uint8_t *)json_buf, (uint16_t)jlen,
                                          &state->okey);
            if (err == VIRP_OK && resp_len > 0) {
                if (send_framed(client_fd, resp_buf, resp_len) == 0)
                    onode_inc_observations(state);
            } else {
                send_framed_error(client_fd, err);
            }
        }
        break;

    case ONODE_ACTION_CHAIN_VERIFY:
        if (!state->chain_enabled) {
            send_framed_error(client_fd, VIRP_ERR_CHAIN_DB);
            break;
        }
        if (req.session_id[0] == '\0') {
            send_framed_error(client_fd, VIRP_ERR_NULL_PTR);
            break;
        }
        {
            virp_chain_verify_result_t vresult;
            err = virp_chain_verify(&state->chain, req.session_id,
                                     req.from_sequence, req.to_sequence,
                                     &vresult);
            if (err != VIRP_OK) {
                send_framed_error(client_fd, err);
                break;
            }
            char json_buf[1024];
            int jlen = snprintf(json_buf, sizeof(json_buf),
                "{\"entries_checked\":%lld,"
                "\"first_broken\":%lld,"
                "\"from_sequence\":%lld,"
                "\"to_sequence\":%lld,"
                "\"valid\":%s}",
                (long long)vresult.entries_checked,
                (long long)vresult.first_broken,
                (long long)vresult.from_sequence,
                (long long)vresult.to_sequence,
                vresult.valid ? "true" : "false");
            err = virp_build_observation(resp_buf, sizeof(resp_buf), &resp_len,
                                          state->node_id, onode_next_seq(state),
                                          VIRP_OBS_CHAIN_VERIFY, VIRP_SCOPE_LOCAL,
                                          (const uint8_t *)json_buf, (uint16_t)jlen,
                                          &state->okey);
            if (err == VIRP_OK && resp_len > 0) {
                if (send_framed(client_fd, resp_buf, resp_len) == 0)
                    onode_inc_observations(state);
            } else {
                send_framed_error(client_fd, err);
            }
        }
        break;

    case ONODE_ACTION_CHAIN_VERIFY_SESSION:
        /* Whole-session verification against the signed head record.
         * Unlike CHAIN_VERIFY, the caller supplies NO range — the range
         * comes from the authenticated head, so a caller cannot be fooled
         * by deriving max sequence from the same (possibly truncated)
         * database it is auditing. Same response obs type as CHAIN_VERIFY
         * so existing consumers parse it unchanged; adds error_detail
         * because the failure mode (truncated vs missing head vs forged
         * head) is the point of the check. */
        if (!state->chain_enabled) {
            send_framed_error(client_fd, VIRP_ERR_CHAIN_DB);
            break;
        }
        if (req.session_id[0] == '\0') {
            send_framed_error(client_fd, VIRP_ERR_NULL_PTR);
            break;
        }
        {
            virp_chain_verify_result_t vresult;
            err = virp_chain_verify_session(&state->chain, req.session_id,
                                            &vresult);
            if (err != VIRP_OK) {
                send_framed_error(client_fd, err);
                break;
            }
            /* error_detail is daemon-generated prose (fixed format strings,
             * numbers, session ids validated at ingress) — no quotes or
             * control bytes reach it, so direct embedding is safe. */
            char json_buf[1024];
            int jlen = snprintf(json_buf, sizeof(json_buf),
                "{\"entries_checked\":%lld,"
                "\"error_detail\":\"%s\","
                "\"first_broken\":%lld,"
                "\"from_sequence\":%lld,"
                "\"to_sequence\":%lld,"
                "\"valid\":%s}",
                (long long)vresult.entries_checked,
                vresult.error_detail,
                (long long)vresult.first_broken,
                (long long)vresult.from_sequence,
                (long long)vresult.to_sequence,
                vresult.valid ? "true" : "false");
            err = virp_build_observation(resp_buf, sizeof(resp_buf), &resp_len,
                                          state->node_id, onode_next_seq(state),
                                          VIRP_OBS_CHAIN_VERIFY, VIRP_SCOPE_LOCAL,
                                          (const uint8_t *)json_buf, (uint16_t)jlen,
                                          &state->okey);
            if (err == VIRP_OK && resp_len > 0) {
                if (send_framed(client_fd, resp_buf, resp_len) == 0)
                    onode_inc_observations(state);
            } else {
                send_framed_error(client_fd, err);
            }
        }
        break;

    case ONODE_ACTION_INTENT_STORE:
        if (!state->chain_enabled) {
            send_framed_error(client_fd, VIRP_ERR_CHAIN_DB);
            break;
        }
        if (req.intent_id[0] == '\0' || req.intent_hash[0] == '\0' ||
            req.intent_json[0] == '\0') {
            send_framed_error(client_fd, VIRP_ERR_NULL_PTR);
            break;
        }
        {
            virp_intent_entry_t ie;
            memset(&ie, 0, sizeof(ie));
            snprintf(ie.intent_id, sizeof(ie.intent_id), "%s", req.intent_id);
            snprintf(ie.intent_hash, sizeof(ie.intent_hash), "%s", req.intent_hash);
            snprintf(ie.intent_json, sizeof(ie.intent_json), "%s", req.intent_json);
            snprintf(ie.confidence, sizeof(ie.confidence), "%s", req.confidence);
            ie.expires_at_ns = req.expires_at_ns;
            ie.max_commands = req.max_commands;
            snprintf(ie.proposed_actions, sizeof(ie.proposed_actions), "%s",
                     req.proposed_actions);
            snprintf(ie.constraints, sizeof(ie.constraints), "%s",
                     req.constraints);

            /* Sequence for the observation response */
            uint32_t seq = onode_next_seq(state);
            ie.signature_seq = seq;

            /* HMAC + timestamps computed inside virp_chain_intent_store */
            err = virp_chain_intent_store(&state->chain, &ie);
            if (err != VIRP_OK) {
                send_framed_error(client_fd, err);
                break;
            }
            /* Store intent content as artifact */
            if (ie.intent_json[0] != '\0') {
                virp_chain_artifact_store(&state->chain,
                    ie.intent_id, "intent",
                    ie.intent_json, ie.intent_hash,
                    req.session_id[0] != '\0' ? req.session_id : "intent");
            }

            char json_buf[512];
            int jlen = snprintf(json_buf, sizeof(json_buf),
                "{\"commands_executed\":%d,"
                "\"intent_id\":\"%s\","
                "\"max_commands\":%d,"
                "\"signature_hmac\":\"%s\","
                "\"signature_seq\":%lld,"
                "\"signature_timestamp_ns\":%lld}",
                ie.commands_executed,
                ie.intent_id,
                ie.max_commands,
                ie.signature_hmac,
                (long long)ie.signature_seq,
                (long long)ie.signature_timestamp_ns);
            err = virp_build_observation(resp_buf, sizeof(resp_buf), &resp_len,
                                          state->node_id, seq,
                                          VIRP_OBS_INTENT_STORED, VIRP_SCOPE_LOCAL,
                                          (const uint8_t *)json_buf, (uint16_t)jlen,
                                          &state->okey);
            if (err == VIRP_OK && resp_len > 0) {
                if (send_framed(client_fd, resp_buf, resp_len) == 0)
                    onode_inc_observations(state);
            } else {
                send_framed_error(client_fd, err);
            }
        }
        break;

    case ONODE_ACTION_INTENT_GET:
        if (!state->chain_enabled) {
            send_framed_error(client_fd, VIRP_ERR_CHAIN_DB);
            break;
        }
        if (req.intent_id[0] == '\0') {
            send_framed_error(client_fd, VIRP_ERR_NULL_PTR);
            break;
        }
        {
            virp_intent_entry_t ie;
            err = virp_chain_intent_get(&state->chain, req.intent_id, &ie);
            if (err != VIRP_OK) {
                send_framed_error(client_fd, err);
                break;
            }

            /* Return full intent data as JSON */
            char json_buf[6144];
            int jlen = snprintf(json_buf, sizeof(json_buf),
                "{\"commands_executed\":%d,"
                "\"confidence\":\"%s\","
                "\"constraints\":%s,"
                "\"created_at_ns\":%lld,"
                "\"expires_at_ns\":%lld,"
                "\"intent_hash\":\"%s\","
                "\"intent_id\":\"%s\","
                "\"intent_json\":%s,"
                "\"max_commands\":%d,"
                "\"proposed_actions\":%s,"
                "\"signature_hmac\":\"%s\","
                "\"signature_seq\":%lld,"
                "\"signature_timestamp_ns\":%lld}",
                ie.commands_executed,
                ie.confidence,
                ie.constraints,
                (long long)ie.created_at_ns,
                (long long)ie.expires_at_ns,
                ie.intent_hash,
                ie.intent_id,
                ie.intent_json,
                ie.max_commands,
                ie.proposed_actions,
                ie.signature_hmac,
                (long long)ie.signature_seq,
                (long long)ie.signature_timestamp_ns);
            /* Clamp payload to uint16 max */
            if (jlen > 65535) jlen = 65535;
            err = virp_build_observation(resp_buf, sizeof(resp_buf), &resp_len,
                                          state->node_id, onode_next_seq(state),
                                          VIRP_OBS_INTENT_FETCHED, VIRP_SCOPE_LOCAL,
                                          (const uint8_t *)json_buf, (uint16_t)jlen,
                                          &state->okey);
            if (err == VIRP_OK && resp_len > 0) {
                if (send_framed(client_fd, resp_buf, resp_len) == 0)
                    onode_inc_observations(state);
            } else {
                send_framed_error(client_fd, err);
            }
        }
        break;

    case ONODE_ACTION_INTENT_EXECUTE:
        if (!state->chain_enabled) {
            send_framed_error(client_fd, VIRP_ERR_CHAIN_DB);
            break;
        }
        if (req.intent_id[0] == '\0') {
            send_framed_error(client_fd, VIRP_ERR_NULL_PTR);
            break;
        }
        {
            virp_intent_entry_t ie;
            err = virp_chain_intent_execute(&state->chain, req.intent_id, &ie);
            if (err != VIRP_OK) {
                send_framed_error(client_fd, err);
                break;
            }

            char json_buf[512];
            int jlen = snprintf(json_buf, sizeof(json_buf),
                "{\"commands_executed\":%d,"
                "\"intent_id\":\"%s\","
                "\"max_commands\":%d}",
                ie.commands_executed,
                ie.intent_id,
                ie.max_commands);
            err = virp_build_observation(resp_buf, sizeof(resp_buf), &resp_len,
                                          state->node_id, onode_next_seq(state),
                                          VIRP_OBS_INTENT_EXECUTED, VIRP_SCOPE_LOCAL,
                                          (const uint8_t *)json_buf, (uint16_t)jlen,
                                          &state->okey);
            if (err == VIRP_OK && resp_len > 0) {
                if (send_framed(client_fd, resp_buf, resp_len) == 0)
                    onode_inc_observations(state);
            } else {
                send_framed_error(client_fd, err);
            }
        }
        break;

    case ONODE_ACTION_BATCH_EXECUTE: {
        /* Parse batch commands from JSON array */
        batch_thread_arg_t args[ONODE_MAX_BATCH];
        memset(args, 0, sizeof(args));

        int cmd_count = parse_batch_commands(recv_buf, args, ONODE_MAX_BATCH);
        if (cmd_count <= 0) {
            send_framed_error(client_fd, VIRP_ERR_NULL_PTR);
            break;
        }

        /*
         * Multiple batch items may target the same device. The per-device
         * exec_mutex in onode_execute serializes access to the shared
         * connection, so this is safe. Commands to different devices run
         * in parallel; commands to the same device run sequentially.
         */

        /* Allocate per-thread response buffers */
        bool alloc_ok = true;
        for (int i = 0; i < cmd_count; i++) {
            args[i].state = state;
            /* Top-level obs_version applies to every batch item — a
             * batch that asked for session binding must never be
             * silently served master-key v1 observations. */
            args[i].obs_version = req.obs_version;
            /* Same connecting uid for every item in this batch — one
             * connection, one peer — so per-uid ceilings apply to batch
             * items exactly as they do to a single execute. */
            args[i].client_uid = client_uid;
            args[i].resp_buf = malloc(VIRP_MAX_MESSAGE_SIZE);
            if (!args[i].resp_buf) { alloc_ok = false; break; }
        }
        if (!alloc_ok) {
            for (int i = 0; i < cmd_count; i++)
                free(args[i].resp_buf);
            send_framed_error(client_fd, VIRP_ERR_NULL_PTR);
            break;
        }

        /* Launch one thread per device */
        pthread_t threads[ONODE_MAX_BATCH];
        for (int i = 0; i < cmd_count; i++)
            pthread_create(&threads[i], NULL, batch_execute_thread, &args[i]);

        /* Wait for all threads to complete */
        for (int i = 0; i < cmd_count; i++)
            pthread_join(threads[i], NULL);

        /* Accumulate batch response into a buffer, then send as one frame.
         * Format: 4-byte count, then per-result (4-byte len + data). */
        {
            size_t batch_cap = 4; /* count */
            for (int i = 0; i < cmd_count; i++)
                batch_cap += 4 + (args[i].err == VIRP_OK ? args[i].resp_len : 4);
            uint8_t *batch_buf = malloc(batch_cap);
            if (!batch_buf) {
                send_framed_error(client_fd, VIRP_ERR_NULL_PTR);
                for (int i = 0; i < cmd_count; i++)
                    free(args[i].resp_buf);
                break;
            }
            size_t off = 0;
            uint32_t net_count = htonl((uint32_t)cmd_count);
            memcpy(batch_buf + off, &net_count, 4); off += 4;
            for (int i = 0; i < cmd_count; i++) {
                if (args[i].err == VIRP_OK && args[i].resp_len > 0) {
                    uint32_t net_len = htonl((uint32_t)args[i].resp_len);
                    memcpy(batch_buf + off, &net_len, 4); off += 4;
                    memcpy(batch_buf + off, args[i].resp_buf, args[i].resp_len);
                    off += args[i].resp_len;
                } else {
                    uint32_t net_len = htonl(4);
                    memcpy(batch_buf + off, &net_len, 4); off += 4;
                    uint32_t err_code = htonl((uint32_t)args[i].err);
                    memcpy(batch_buf + off, &err_code, 4); off += 4;
                }
            }
            send_framed(client_fd, batch_buf, off);
            free(batch_buf);
        }

        /* Cleanup */
        for (int i = 0; i < cmd_count; i++)
            free(args[i].resp_buf);

        break;
    }

    case ONODE_ACTION_VALIDATE_TURN: {
        /*
         * Response validator (CT 211 side).
         *
         * Request JSON shape:
         *   {
         *     "action": "validate_turn",
         *     "session_id": "...",          // fallback if manifest unparseable
         *     "prose": "...",
         *     "manifest": { ...sidecar... }
         *   }
         *
         * The manifest is a nested JSON object, not a string. We
         * re-parse recv_buf here because it doesn't fit the flat
         * onode_request_t schema — same approach as batch_execute.
         *
         * Response is a signed VIRP OBSERVATION with VIRP_OBS_VALIDATION_DECISION
         * and a JSON payload describing the decision. The O-Key signature on
         * the observation is the trust boundary: CT 210 cannot forge a PASS.
         */
        if (!state->chain_enabled) {
            send_framed_error(client_fd, VIRP_ERR_CHAIN_DB);
            break;
        }

        cJSON *root = cJSON_Parse(recv_buf);
        if (!root || !cJSON_IsObject(root)) {
            if (root) cJSON_Delete(root);
            send_framed_error(client_fd, VIRP_ERR_INVALID_TYPE);
            break;
        }

        cJSON *mani  = cJSON_GetObjectItemCaseSensitive(root, "manifest");
        cJSON *prose = cJSON_GetObjectItemCaseSensitive(root, "prose");

        char *mani_json = NULL;
        size_t mani_len = 0;
        if (cJSON_IsObject(mani)) {
            mani_json = cJSON_PrintUnformatted(mani);
            if (mani_json) mani_len = strlen(mani_json);
        }

        const char *prose_str = cJSON_IsString(prose) ? prose->valuestring : "";
        size_t prose_len = strlen(prose_str);

        const char *fallback_sid = (req.session_id[0] != '\0')
                                   ? req.session_id : "unknown";

        validator_result_t vr;
        virp_error_t verr = validator_run_turn(&state->chain,
                                                mani_json, mani_len,
                                                prose_str, prose_len,
                                                fallback_sid, &vr);
        if (mani_json) free(mani_json);
        cJSON_Delete(root);

        if (verr != VIRP_OK) {
            send_framed_error(client_fd, verr);
            break;
        }

        /*
         * Build JSON payload: up to VALIDATOR_MAX_ASSERTIONS per-assertion
         * objects plus the envelope.
         *
         * Sized from the cap rather than a fixed 8KB. When
         * VALIDATOR_MAX_ASSERTIONS rose from 32 to 1024, the old 8KB
         * buffer stopped fitting a full-size manifest (~45 bytes per
         * assertion, so ~46KB): the guarded loop below would have failed
         * a maximal turn with BUFFER_TOO_SMALL — safely, but it would
         * have failed — which is exactly the full-topology case the
         * raised cap exists to allow.
         */
        #define VALIDATE_JSON_ENVELOPE 512
        #define VALIDATE_JSON_PER_ASSERTION 64
        char json_buf[VALIDATE_JSON_ENVELOPE +
                      VALIDATOR_MAX_ASSERTIONS * VALIDATE_JSON_PER_ASSERTION];
        int joff = snprintf(json_buf, sizeof(json_buf),
            "{\"decision\":\"%s\","
            "\"turn_violation\":%d,"
            "\"chain_sequence\":%lld,"
            "\"chain_entry_hash\":\"%s\","
            "\"artifact_hash\":\"%s\","
            "\"assertions\":[",
            validator_decision_str(vr.decision),
            (int)vr.turn_violation,
            (long long)vr.chain_sequence,
            vr.chain_entry_hash,
            vr.artifact_hash);

        for (size_t i = 0; i < vr.per_assertion_count; i++) {
            int jw = snprintf(json_buf + joff, sizeof(json_buf) - (size_t)joff,
                "%s{\"decision\":\"%s\",\"violation\":%d}",
                (i == 0) ? "" : ",",
                validator_decision_str(vr.per_assertion[i].decision),
                (int)vr.per_assertion[i].violation);
            if (jw < 0 || (size_t)jw >= sizeof(json_buf) - (size_t)joff) {
                send_framed_error(client_fd, VIRP_ERR_BUFFER_TOO_SMALL);
                goto validate_turn_done;
            }
            joff += jw;
        }
        {
            int tw = snprintf(json_buf + joff, sizeof(json_buf) - (size_t)joff,
                              "]}");
            if (tw < 0 || (size_t)tw >= sizeof(json_buf) - (size_t)joff) {
                send_framed_error(client_fd, VIRP_ERR_BUFFER_TOO_SMALL);
                goto validate_turn_done;
            }
            joff += tw;
        }

        err = virp_build_observation(resp_buf, sizeof(resp_buf), &resp_len,
                                      state->node_id, onode_next_seq(state),
                                      VIRP_OBS_VALIDATION_DECISION, VIRP_SCOPE_LOCAL,
                                      (const uint8_t *)json_buf, (uint16_t)joff,
                                      &state->okey);
        if (err == VIRP_OK && resp_len > 0) {
            if (send_framed(client_fd, resp_buf, resp_len) == 0)
                onode_inc_observations(state);
        } else {
            send_framed_error(client_fd, err);
        }

    validate_turn_done:
        break;
    }

    case ONODE_ACTION_APPROVAL_CHALLENGE:
        if (req.proposal_id[0] == '\0') {
            send_framed_error(client_fd, VIRP_ERR_NULL_PTR);
            break;
        }
        err = onode_approval_challenge(state, req.proposal_id,
                                       resp_buf, sizeof(resp_buf), &resp_len);
        if (err == VIRP_OK && resp_len > 0) {
            if (send_framed(client_fd, resp_buf, resp_len) == 0)
                onode_inc_observations(state);
        } else {
            send_framed_error(client_fd, err);
        }
        break;

    case ONODE_ACTION_APPROVAL_SUBMIT:
        if (req.proposal_id[0] == '\0' || req.signature[0] == '\0' ||
            req.key_id[0] == '\0') {
            send_framed_error(client_fd, VIRP_ERR_NULL_PTR);
            break;
        }
        err = onode_approval_submit(state, req.proposal_id, req.key_id,
                                    req.signature,
                                    resp_buf, sizeof(resp_buf), &resp_len);
        if (err == VIRP_OK && resp_len > 0) {
            if (send_framed(client_fd, resp_buf, resp_len) == 0)
                onode_inc_observations(state);
        } else {
            send_framed_error(client_fd, err);
        }
        break;

    case ONODE_ACTION_SESSION_HELLO: {
        if (req.client_id[0] == '\0') {
            send_framed_error(client_fd, VIRP_ERR_NULL_PTR);
            break;
        }

        /* Build SESSION_HELLO from request fields */
        virp_session_hello_t hello;
        memset(&hello, 0, sizeof(hello));
        hello.msg_type = VIRP_MSG_SESSION_HELLO;
        snprintf(hello.client_id, sizeof(hello.client_id), "%s", req.client_id);

        /* Parse versions: comma-separated string e.g. "2,1" */
        if (req.versions[0]) {
            char vtmp[32];
            snprintf(vtmp, sizeof(vtmp), "%s", req.versions);
            char *saveptr = NULL;
            char *tok = strtok_r(vtmp, ",", &saveptr);
            while (tok && hello.version_count < VIRP_MAX_VERSIONS) {
                hello.versions[hello.version_count++] = (uint8_t)atoi(tok);
                tok = strtok_r(NULL, ",", &saveptr);
            }
        } else {
            hello.versions[0] = 2;
            hello.versions[1] = 1;
            hello.version_count = 2;
        }

        /* Parse algorithms: comma-separated string */
        if (req.algorithms[0]) {
            char atmp[32];
            snprintf(atmp, sizeof(atmp), "%s", req.algorithms);
            char *saveptr = NULL;
            char *tok = strtok_r(atmp, ",", &saveptr);
            while (tok && hello.algorithm_count < VIRP_MAX_ALGORITHMS) {
                hello.algorithms[hello.algorithm_count++] = (uint8_t)atoi(tok);
                tok = strtok_r(NULL, ",", &saveptr);
            }
        } else {
            hello.algorithms[0] = VIRP_ALG_HMAC_SHA256;
            hello.algorithm_count = 1;
        }

        hello.supported_channels = (uint32_t)req.supported_channels;

        /* Parse client_nonce from hex (8 bytes = 16 hex chars) */
        if (req.client_nonce[0]) {
            virp_hex_decode(req.client_nonce, hello.client_nonce, 8);
        }

        {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            hello.timestamp_ns =
                (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
        }

        /* Process handshake — serialized: only one handshake may drive
         * the shared ctx at a time. */
        virp_session_hello_ack_t ack;
        pthread_mutex_lock(&state->session_mutex);
        err = virp_handle_hello(state->ctx, &hello, &ack);
        pthread_mutex_unlock(&state->session_mutex);
        if (err != VIRP_OK) {
            send_framed_error(client_fd, err);
            break;
        }

        /* Return HELLO_ACK as JSON */
        char sid_hex[33], cn_hex[17], sn_hex[17];
        hex_encode(sid_hex, sizeof(sid_hex), ack.session_id, 16);
        hex_encode(cn_hex, sizeof(cn_hex), ack.client_nonce, 8);
        hex_encode(sn_hex, sizeof(sn_hex), ack.server_nonce, 8);

        char json_resp[1024];
        int jlen = snprintf(json_resp, sizeof(json_resp),
            "{\"msg_type\":%u,"
            "\"server_id\":\"%s\","
            "\"selected_version\":%u,"
            "\"selected_algorithm\":%u,"
            "\"accepted_channels\":%u,"
            "\"session_id\":\"%s\","
            "\"client_nonce\":\"%s\","
            "\"server_nonce\":\"%s\"}",
            ack.msg_type, ack.server_id,
            ack.selected_version, ack.selected_algorithm,
            ack.accepted_channels,
            sid_hex, cn_hex, sn_hex);

        send_framed(client_fd, json_resp, (size_t)jlen);
        break;
    }

    case ONODE_ACTION_SESSION_BIND: {
        /* Build SESSION_BIND from request fields */
        virp_session_bind_t bind_msg;
        memset(&bind_msg, 0, sizeof(bind_msg));
        bind_msg.msg_type = VIRP_MSG_SESSION_BIND;

        snprintf(bind_msg.client_id, sizeof(bind_msg.client_id),
                 "%s", req.client_id);

        /* session_id from hex (reuse req.session_id, 16 bytes = 32 hex) */
        if (req.session_id[0]) {
            virp_hex_decode(req.session_id, bind_msg.session_id, 16);
        }

        if (req.client_nonce[0])
            virp_hex_decode(req.client_nonce, bind_msg.client_nonce, 8);
        if (req.server_nonce[0])
            virp_hex_decode(req.server_nonce, bind_msg.server_nonce, 8);

        {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            bind_msg.timestamp_ns =
                (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
        }

        /* BIND + derive_key must happen atomically against ctx so a
         * concurrent HELLO on another worker can't observe a half-
         * bound session. */
        pthread_mutex_lock(&state->session_mutex);
        err = virp_handle_session_bind(state->ctx, &bind_msg);
        if (err == VIRP_OK) {
            err = virp_session_derive_key(state->ctx, state->okey.key.key);
        }
        pthread_mutex_unlock(&state->session_mutex);
        if (err != VIRP_OK) {
            fprintf(stderr, "[O-Node] session bind/derive failed: %d\n",
                    (int)err);
            send_framed_error(client_fd, err);
            break;
        }

        const char *ok_resp = "{\"status\":\"bound\",\"active\":true}";
        send_framed(client_fd, ok_resp, strlen(ok_resp));
        break;
    }

    case ONODE_ACTION_SESSION_CLOSE:
        pthread_mutex_lock(&state->session_mutex);
        virp_handle_session_close(state->ctx);
        pthread_mutex_unlock(&state->session_mutex);
        fprintf(stderr, "[O-Node] Session closed by client\n");
        {
            const char *close_resp = "{\"status\":\"closed\"}";
            send_framed(client_fd, close_resp, strlen(close_resp));
        }
        break;

    case ONODE_ACTION_SHUTDOWN:
        fprintf(stderr, "[O-Node] Shutdown requested\n");
        onode_shutdown(state);
        break;
    }

    close(client_fd);
}

/* =========================================================================
 * Auto-Reconnect Watchdog
 *
 * Background thread that periodically checks all device connections.
 * If a connection is NULL (dropped or never established) and the device
 * is enabled, it attempts to reconnect with exponential backoff:
 *   5s → 10s → 30s → 60s (max)
 *
 * If an existing connection fails health_check(), it drops and reconnects.
 * This means sessions recover without a full service restart.
 * ========================================================================= */

static int next_backoff(int current)
{
    if (current <= 5)  return 10;
    if (current <= 10) return 30;
    return ONODE_RECONNECT_BACKOFF_MAX;
}

/*
 * Attempt to connect a single device. Called by the watchdog for both
 * initial startup connections and reconnections after drops.
 * Caller must NOT hold conn_mutex.
 */
static void watchdog_try_connect(onode_state_t *state, int dev_idx,
                                 const virp_driver_t *drv, bool is_initial)
{
    const virp_device_t *dev = &state->devices[dev_idx];
    onode_reconnect_t *ri = &state->reconnect[dev_idx];

    if (is_initial) {
        fprintf(stderr, "[Watchdog] Connecting: %s (%s)\n",
                dev->hostname, dev->host);
    } else {
        fprintf(stderr, "[Watchdog] Reconnecting: %s (attempt %d, backoff was %ds)\n",
                dev->hostname, ri->consecutive_fails + 1, ri->backoff_sec);
    }

    /* connect() may block — runs outside the lock */
    virp_conn_t *new_conn = drv->connect(dev);

    pthread_mutex_lock(&state->conn_mutex);
    ri->reconnecting = false;

    /* Another thread may have connected while we were blocked */
    if (state->connections[dev_idx]) {
        pthread_mutex_unlock(&state->conn_mutex);
        if (new_conn)
            drv->disconnect(new_conn);
        return;
    }

    if (new_conn) {
        state->connections[dev_idx] = new_conn;
        ri->backoff_sec = 0;
        ri->consecutive_fails = 0;
        ri->last_success = time(NULL);
        pthread_mutex_unlock(&state->conn_mutex);

        pthread_mutex_lock(&state->state_mutex);
        if (!is_initial)
            state->reconnects++;
        pthread_mutex_unlock(&state->state_mutex);

        fprintf(stderr, "[Watchdog] Connected: %s\n", dev->hostname);
    } else {
        ri->consecutive_fails++;
        ri->last_attempt = time(NULL);
        ri->backoff_sec = (ri->backoff_sec == 0)
            ? ONODE_RECONNECT_BACKOFF_INIT
            : next_backoff(ri->backoff_sec);
        pthread_mutex_unlock(&state->conn_mutex);

        fprintf(stderr, "[Watchdog] Failed: %s — retrying in %ds\n",
                dev->hostname, ri->backoff_sec);
    }
}

/* Defined below (near connection_worker); used by both non-main threads. */
static void block_shutdown_signals(void);

static void *watchdog_thread_fn(void *arg)
{
    onode_state_t *state = (onode_state_t *)arg;

    /* Shutdown signals go to the main thread only (prompt clean exit). */
    block_shutdown_signals();

    /* Count enabled devices for logging */
    int enabled = 0;
    for (int i = 0; i < state->device_count; i++)
        if (state->devices[i].enabled) enabled++;

    fprintf(stderr, "[Watchdog] Started — connecting %d enabled devices\n", enabled);

    /* ---- Initial connect pass: reach every enabled device ---- */
    for (int i = 0; i < state->device_count; i++) {
        if (!state->watchdog_running) goto done;
        if (!state->devices[i].enabled) continue;

        const virp_driver_t *drv = virp_driver_lookup(state->devices[i].vendor);
        if (!drv) {
            fprintf(stderr, "[Watchdog] No driver for: %s (vendor=%d) — skipping\n",
                    state->devices[i].hostname, state->devices[i].vendor);
            continue;
        }

        pthread_mutex_lock(&state->conn_mutex);
        bool already = (state->connections[i] != NULL);
        if (!already) {
            state->reconnect[i].reconnecting = true;
            state->reconnect[i].last_attempt = time(NULL);
        }
        pthread_mutex_unlock(&state->conn_mutex);

        if (already) continue;

        watchdog_try_connect(state, i, drv, true);
    }

    /* Log initial pass summary */
    {
        int up = 0;
        for (int i = 0; i < state->device_count; i++)
            if (state->devices[i].enabled && state->connections[i]) up++;
        fprintf(stderr, "[Watchdog] Initial pass complete: connected=%d/%d\n", up, enabled);
    }

    /* ---- Steady-state loop: health checks + reconnects ---- */
    while (state->watchdog_running) {
        sleep(ONODE_WATCHDOG_INTERVAL_SEC);
        if (!state->watchdog_running) break;

        time_t now = time(NULL);

        for (int i = 0; i < state->device_count; i++) {
            if (!state->devices[i].enabled)
                continue;

            const virp_driver_t *drv = virp_driver_lookup(state->devices[i].vendor);
            if (!drv) continue;  /* logged in initial pass */

            pthread_mutex_lock(&state->conn_mutex);

            onode_reconnect_t *ri = &state->reconnect[i];
            virp_conn_t *conn = state->connections[i];

            /* Skip if another thread is already reconnecting this device */
            if (ri->reconnecting) {
                pthread_mutex_unlock(&state->conn_mutex);
                continue;
            }

            /* Case 1: Connection exists — probe with health_check.
             *
             * LOCK ORDER: exec_mutex[i] → conn_mutex, never the reverse.
             * The probe drives the same SSH channel as drv->execute, so
             * it must run under exec_mutex[i] — conn_mutex protects only
             * the slot pointer, not the channel. An unserialized probe
             * interleaves with an in-flight command: its bytes land in
             * that command's SIGNED observation, and concurrent channel
             * operations on one libssh2 session are a data race.
             * Acquiring exec_mutex while holding conn_mutex is the
             * forbidden direction (it would invert against the execute
             * path, which takes exec_mutex[i] and then conn_mutex inside
             * get_connection/drop_connection), so release conn_mutex
             * first and re-validate the slot after the gap.
             */
            if (conn && drv->health_check) {
                pthread_mutex_unlock(&state->conn_mutex);

                /* Serialize against any in-flight onode_execute. */
                pthread_mutex_lock(&state->exec_mutex[i]);

                /* The connection may have been dropped (and freed) by an
                 * execute-path drop_connection while we waited. */
                pthread_mutex_lock(&state->conn_mutex);
                conn = state->connections[i];
                bool probe_skip = (conn == NULL) || ri->reconnecting;
                pthread_mutex_unlock(&state->conn_mutex);
                if (probe_skip) {
                    pthread_mutex_unlock(&state->exec_mutex[i]);
                    continue;
                }

                virp_error_t hc = drv->health_check(conn);
                if (hc != VIRP_OK) {
                    fprintf(stderr, "[Watchdog] Health check failed: %s — dropping\n",
                            state->devices[i].hostname);
                    /* Null the slot and arm reconnect under conn_mutex
                     * (nesting conn under exec is the allowed direction),
                     * then tear down while still holding exec_mutex[i] so
                     * no execute can race the free. */
                    pthread_mutex_lock(&state->conn_mutex);
                    virp_conn_t *stale = state->connections[i];
                    state->connections[i] = NULL;
                    ri->reconnecting = true;
                    ri->last_attempt = now;
                    if (ri->backoff_sec == 0)
                        ri->backoff_sec = ONODE_RECONNECT_BACKOFF_INIT;
                    pthread_mutex_unlock(&state->conn_mutex);

                    if (stale)
                        drv->disconnect(stale);
                    pthread_mutex_unlock(&state->exec_mutex[i]);

                    pthread_mutex_lock(&state->conn_mutex);
                    ri->reconnecting = false;
                    pthread_mutex_unlock(&state->conn_mutex);
                } else {
                    pthread_mutex_unlock(&state->exec_mutex[i]);
                }
                continue;
            }

            /* Case 2: No connection — attempt reconnect if backoff has elapsed */
            if (!conn) {
                if (ri->backoff_sec > 0 && (now - ri->last_attempt) < ri->backoff_sec) {
                    pthread_mutex_unlock(&state->conn_mutex);
                    continue;  /* Not time yet */
                }

                ri->reconnecting = true;
                ri->last_attempt = now;
                pthread_mutex_unlock(&state->conn_mutex);

                watchdog_try_connect(state, i, drv, false);
                continue;
            }

            pthread_mutex_unlock(&state->conn_mutex);
        }
    }

done:
    fprintf(stderr, "[Watchdog] Stopped\n");
    return NULL;
}

/*
 * Start the watchdog thread against an initialized state. Split out of
 * onode_start() so tests can exercise watchdog behavior (health-check
 * probes, reconnects) without binding a socket or entering the accept
 * loop. onode_destroy() stops and joins the thread.
 */
virp_error_t onode_watchdog_start(onode_state_t *state)
{
    if (!state)
        return VIRP_ERR_NULL_PTR;
    state->watchdog_running = true;
    if (pthread_create(&state->watchdog_thread, NULL,
                       watchdog_thread_fn, state) != 0) {
        state->watchdog_running = false;
        return VIRP_ERR_KEY_NOT_LOADED;
    }
    return VIRP_OK;
}

/* =========================================================================
 * Connection Worker Pool
 *
 * Each accepted fd is dispatched to its own detached pthread running
 * connection_worker(). A counting semaphore (state->worker_sem) caps
 * live workers at ONODE_MAX_WORKERS; the accept loop reserves a slot
 * with sem_trywait() before spawning and the worker releases it on
 * completion. This keeps the accept loop lock-free and non-blocking
 * even when individual connections spend seconds in SSH I/O.
 * ========================================================================= */

typedef struct {
    onode_state_t *state;
    int            client_fd;
    uid_t          client_uid;  /* peer uid validated at accept, threaded to
                                   handle_client so it never re-reads (and
                                   never has a second SO_PEERCRED read to
                                   fail open on) */
    int            slot;        /* index into state->worker_fds, -1 if none */
} worker_arg_t;

/*
 * Block SIGINT/SIGTERM in the calling (non-main) thread so those signals
 * are always delivered to the MAIN thread, whose select() loop then wakes
 * immediately (EINTR) and begins a clean drain. Without this, a SIGTERM
 * landing on a worker or the watchdog leaves the main select() blocked
 * until its 30s heartbeat timeout — the intermittent "SIGKILLed on restart"
 * behavior, which under concurrent load can exceed the stop timeout and
 * lose in-flight audit (chain) writes.
 */
static void block_shutdown_signals(void)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
}

static void *connection_worker(void *raw_arg)
{
    block_shutdown_signals();

    worker_arg_t *arg = (worker_arg_t *)raw_arg;
    onode_state_t *state = arg->state;
    int fd = arg->client_fd;
    int slot = arg->slot;
    uid_t client_uid = arg->client_uid;
    free(arg);

    /* handle_client() closes the fd on every return path. */
    handle_client(state, fd, client_uid);

    /* Clear the drain-registration slot (closing our dup of the client
     * fd), release the worker slot, and update the live counter. The
     * broadcast is the shutdown barrier: onode_start()'s drain waits on
     * workers_cv for the count to reach zero before onode_destroy()
     * may tear down state this thread was using. */
    pthread_mutex_lock(&state->state_mutex);
    if (slot >= 0 && state->worker_fds[slot] >= 0) {
        close(state->worker_fds[slot]);
        state->worker_fds[slot] = -1;
    }
    if (state->workers_live > 0)
        state->workers_live--;
    if (state->workers_live == 0)
        pthread_cond_broadcast(&state->workers_cv);
    pthread_mutex_unlock(&state->state_mutex);
    sem_post(&state->worker_sem);

    return NULL;
}

/* =========================================================================
 * Lifecycle
 * ========================================================================= */

virp_error_t onode_init(onode_state_t *state,
                        uint32_t node_id,
                        const char *okey_path,
                        const char *socket_path)
{
    if (!state)
        return VIRP_ERR_NULL_PTR;

    memset(state, 0, sizeof(*state));
    state->node_id = node_id;
    state->seq_num = 0;
    state->listen_fd = -1;
    state->running = false;

    /* Tier-enforcement gate default posture: ENFORCE — hard-reject
     * over-tier and UNCLASSIFIED commands. This is the intended v1
     * default: an absent or garbled config must fail CLOSED, not fall
     * back to observe-only. Drivers with no classifier (linux, wazuh,
     * proxmox) yield UNCLASSIFIED for everything and are therefore
     * blocked under this default; deployments that need them must opt
     * them into shadow explicitly via gate_modes in devices.json.
     * Config (gate_default_mode / gate_modes / gate_max_tier) may
     * override via the PROD loader (load_gate_config in
     * virp_onode_prod.c) before onode_start(); the dev loader in
     * virp_onode_main.c parses no gate keys, so the dev binary always
     * runs the compiled-in ENFORCE default. */
    state->gate_default_mode = GATE_MODE_ENFORCE;
    state->gate_overrides_count = 0;
    state->gate_max_tier = VIRP_TIER_YELLOW;
    state->uptime_start = (uint32_t)time(NULL);
    state->watchdog_running = false;
    pthread_mutex_init(&state->state_mutex, NULL);
    pthread_mutex_init(&state->conn_mutex, NULL);
    pthread_mutex_init(&state->session_mutex, NULL);
    for (int i = 0; i < ONODE_MAX_DEVICES; i++)
        pthread_mutex_init(&state->exec_mutex[i], NULL);

    /* Worker pool semaphore. Initialized to ONODE_MAX_WORKERS; each
     * accepted connection takes one unit and the worker thread
     * returns it on completion. */
    if (sem_init(&state->worker_sem, 0, ONODE_MAX_WORKERS) == 0) {
        state->worker_sem_inited = true;
    } else {
        perror("[O-Node] sem_init");
        state->worker_sem_inited = false;
    }
    state->workers_live = 0;
    state->workers_rejected = 0;
    state->drain_failed = false;
    for (int i = 0; i < ONODE_MAX_WORKERS; i++)
        state->worker_fds[i] = -1;
    /* Monotonic clock for the drain barrier's timedwait — a wall-clock
     * jump during shutdown must not stretch or collapse the timeout. */
    {
        pthread_condattr_t cvattr;
        pthread_condattr_init(&cvattr);
        pthread_condattr_setclock(&cvattr, CLOCK_MONOTONIC);
        pthread_cond_init(&state->workers_cv, &cvattr);
        pthread_condattr_destroy(&cvattr);
    }

    /* Socket path */
    if (socket_path)
        snprintf(state->socket_path, sizeof(state->socket_path), "%s", socket_path);
    else
        snprintf(state->socket_path, sizeof(state->socket_path), "%s", ONODE_SOCKET_PATH);

    /* Load or generate O-Key */
    virp_error_t err;
    if (okey_path) {
        err = virp_key_load_file(&state->okey, VIRP_KEY_TYPE_OKEY, okey_path);
        if (err != VIRP_OK) {
            fprintf(stderr, "[O-Node] Failed to load O-Key from %s: %s\n",
                    okey_path, virp_error_str(err));
            return err;
        }
        fprintf(stderr, "[O-Node] Loaded O-Key from %s\n", okey_path);
    } else {
        err = virp_key_generate(&state->okey, VIRP_KEY_TYPE_OKEY);
        if (err != VIRP_OK)
            return err;
        fprintf(stderr, "[O-Node] Generated new O-Key\n");
    }

    fprintf(stderr, "[O-Node] Fingerprint: ");
    for (int i = 0; i < VIRP_HMAC_SIZE; i++)
        fprintf(stderr, "%02x", state->okey.fingerprint[i]);
    fprintf(stderr, "\n");

    return VIRP_OK;
}

virp_error_t onode_add_device(onode_state_t *state,
                              const virp_device_t *device)
{
    if (!state || !device)
        return VIRP_ERR_NULL_PTR;

    if (state->device_count >= ONODE_MAX_DEVICES)
        return VIRP_ERR_MESSAGE_TOO_LARGE;

    memcpy(&state->devices[state->device_count], device, sizeof(*device));

    /* Single choke point for device identity: any device that arrives
     * without an explicit device_id gets the deterministic
     * SHA-256(hostname) derivation, so v2 observations never carry a
     * zero device_id regardless of which loader added the device. */
    if (state->devices[state->device_count].device_id == 0)
        state->devices[state->device_count].device_id =
            virp_device_id_from_hostname(device->hostname);

    /* node_id must be a unique, explicit, NON-ZERO identity. It is what
     * virp_approval_verify_consume actually binds an approval to: apply
     * grants when the request's device_node_id matches the SIGNED node_id
     * in the approval record; the hostname in that record is NOT signed.
     * node_id 0 ("absent", from a missing/empty/unparseable config value)
     * was previously exempt from the uniqueness check below — so two
     * node_id-0 devices could coexist, and an attacker able to edit the
     * approval store could rewrite the unsigned hostname A->B (both
     * node_id 0) and have A's approval execute on B, the signature still
     * valid because it covers node_id 0 either way. Reject node_id 0 at
     * load, fail closed, so the signed node_id is always a real unique
     * device identity. (No current device uses node_id 0 — every device
     * is assigned hex-of-IP — so this only forbids a future misconfig.) */
    if (state->devices[state->device_count].node_id == 0) {
        fprintf(stderr, "[O-Node] FATAL: device '%s' has node_id 0 "
                "(reserved 'absent' value from a missing/empty/unparseable "
                "config field). Every device must carry a unique NON-ZERO "
                "node_id — the approval binding depends on it.\n",
                device->hostname);
        return VIRP_ERR_DUPLICATE_DEVICE;
    }

    /* Identity uniqueness, same choke point (checked AFTER derivation so
     * an explicit device_id colliding with another device's derived one
     * is caught too). hostname routes requests, node_id routes wire
     * messages and binds approvals, device_id binds v2 observations —
     * a duplicate in any of them makes one device's evidence readable
     * as another's. Fail closed, naming both devices. */
    {
        const virp_device_t *nd = &state->devices[state->device_count];
        for (int i = 0; i < state->device_count; i++) {
            const virp_device_t *ed = &state->devices[i];
            const char *field = NULL;
            if (strcmp(ed->hostname, nd->hostname) == 0)
                field = "hostname";
            else if (ed->node_id == nd->node_id)
                field = "node_id";   /* node_id 0 already rejected above,
                                        so this is plain uniqueness */
            else if (ed->device_id == nd->device_id)
                field = "device_id";
            if (field) {
                fprintf(stderr, "[O-Node] FATAL: duplicate %s — device "
                        "'%s' (node_id=0x%08x device_id=0x%016llx) "
                        "collides with already-loaded '%s' (node_id=0x%08x "
                        "device_id=0x%016llx)\n", field,
                        nd->hostname, nd->node_id,
                        (unsigned long long)nd->device_id,
                        ed->hostname, ed->node_id,
                        (unsigned long long)ed->device_id);
                return VIRP_ERR_DUPLICATE_DEVICE;
            }
        }
    }

    state->connections[state->device_count] = NULL;
    state->device_count++;

    fprintf(stderr, "[O-Node] Added device: %s (%s) node_id=0x%08x\n",
            device->hostname, device->host, device->node_id);

    return VIRP_OK;
}

virp_error_t onode_set_previous_okey(onode_state_t *state,
                                     const char *path,
                                     uint32_t window_seconds)
{
    if (!state || !path)
        return VIRP_ERR_NULL_PTR;

    /* An unbounded window is not a grace period, it is a second live
     * key that never expires. Refuse rather than quietly pick a value. */
    if (window_seconds == 0) {
        fprintf(stderr, "[O-Node] previous O-Key refused: a grace window "
                        "of 0 seconds is meaningless; give a bounded "
                        "window or do not load a previous key\n");
        return VIRP_ERR_INVALID_LENGTH;
    }

    /* Same custody gate as the live key: no symlinks, no group/world
     * bits, right owner, exact size. A previous key is still a key. */
    virp_error_t err = virp_key_load_file(&state->prev_okey,
                                          VIRP_KEY_TYPE_OKEY, path);
    if (err != VIRP_OK) {
        fprintf(stderr, "[O-Node] Failed to load previous O-Key from %s: "
                "%s\n", path, virp_error_str(err));
        return err;
    }

    /* Refusing an identical key is not pedantry: it means the operator
     * pointed both flags at the same file and believes they have a
     * rotation window they do not have. */
    if (virp_consttime_eq(state->prev_okey.fingerprint,
                          state->okey.fingerprint, VIRP_HMAC_SIZE)) {
        fprintf(stderr, "[O-Node] previous O-Key refused: it is the SAME "
                        "key as the live one (identical fingerprint) — "
                        "there is nothing to grant grace to\n");
        memset(&state->prev_okey, 0, sizeof(state->prev_okey));
        return VIRP_ERR_INVALID_LENGTH;
    }

    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    state->prev_okey_deadline_ns =
        (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec +
        (uint64_t)window_seconds * 1000000000ULL;
    state->prev_okey_loaded = true;
    state->prev_okey_accepts = 0;

    fprintf(stderr, "[O-Node] Rotation grace window OPEN for %u s: "
            "observations signed under the previous O-Key (fingerprint ",
            window_seconds);
    for (int i = 0; i < 4; i++)
        fprintf(stderr, "%02x", state->prev_okey.fingerprint[i]);
    fprintf(stderr, "...) will still register. VERIFY-ONLY — it can never "
            "sign. If you rotated because that key was COMPROMISED, stop "
            "the daemon and restart without this option.\n");
    return VIRP_OK;
}

virp_error_t onode_set_obskey(onode_state_t *state, const char *path)
{
    if (!state || !path)
        return VIRP_ERR_NULL_PTR;

    /* One key per node, loaded once. A second load is an operator
     * error (two -O flags, or a retry after a partial start), not a
     * rotation mechanism — refuse rather than silently swap the key
     * every observation since startup was signed under. */
    if (state->obskey_loaded) {
        fprintf(stderr, "[O-Node] observation-signing key refused: one is "
                        "already loaded (key_id ");
        for (int i = 0; i < VIRP_OBSKEY_KEYID_SIZE; i++)
            fprintf(stderr, "%02x", state->obskey.key_id[i]);
        fprintf(stderr, ") — rotation is a restart, not a reload\n");
        return VIRP_ERR_KEY_NOT_LOADED;
    }

    /* Custody gate lives in virp_obskey_load: regular file, no symlink,
     * no group/world bits, owner == euid (or root), exactly 64 bytes.
     * It opens exactly `path` — no default, no search, nothing
     * generated. Each refusal prints its own specific reason. */
    virp_error_t err = virp_obskey_load(&state->obskey, path);
    if (err != VIRP_OK) {
        fprintf(stderr, "[O-Node] Failed to load observation-signing key "
                        "from %s: %s\n", path, virp_error_str(err));
        memset(&state->obskey, 0, sizeof(state->obskey));
        state->obskey_loaded = false;
        return err;
    }
    state->obskey_loaded = true;

    fprintf(stderr, "[O-Node] Loaded Ed25519 observation-signing key from "
                    "%s (key_id ", path);
    for (int i = 0; i < VIRP_OBSKEY_KEYID_SIZE; i++)
        fprintf(stderr, "%02x", state->obskey.key_id[i]);
    fprintf(stderr, "): v3 observations ENABLED — execute/health/batch with "
                    "obs_version 3 are Ed25519-signed and chain_append "
                    "verifies v3 bodies under the public half. v1/v2 "
                    "unchanged.\n");
    return VIRP_OK;
}

virp_error_t onode_set_allowed_uids(onode_state_t *state,
                                    const uid_t *uids, size_t count)
{
    if (!state || (!uids && count > 0))
        return VIRP_ERR_NULL_PTR;
    if (count > ONODE_MAX_ALLOWED_UIDS)
        return VIRP_ERR_MESSAGE_TOO_LARGE;
    for (size_t i = 0; i < count; i++)
        state->socket_allowed_uids[i] = uids[i];
    state->socket_allowed_uids_count = count;
    return VIRP_OK;
}

virp_error_t onode_set_uid_ceilings(onode_state_t *state,
                                    const uid_t *uids,
                                    const virp_trust_tier_t *tiers,
                                    size_t count)
{
    if (!state || (count > 0 && (!uids || !tiers)))
        return VIRP_ERR_NULL_PTR;
    if (count > ONODE_MAX_ALLOWED_UIDS)
        return VIRP_ERR_MESSAGE_TOO_LARGE;
    for (size_t i = 0; i < count; i++) {
        /* A ceiling entry for a uid NOT on the allowlist can never take
         * effect (the connection is refused at accept), and a BLACK
         * "ceiling" would forbid everything — reject both as config
         * errors rather than store a rule that misleads an auditor. */
        if (tiers[i] != VIRP_TIER_GREEN &&
            tiers[i] != VIRP_TIER_YELLOW &&
            tiers[i] != VIRP_TIER_RED)
            return VIRP_ERR_INVALID_TYPE;
        state->uid_ceiling_uids[i]  = uids[i];
        state->uid_ceiling_tiers[i] = tiers[i];
    }
    state->uid_ceiling_count = count;
    return VIRP_OK;
}

virp_error_t onode_set_uid_actions(onode_state_t *state, uid_t uid,
                                   const onode_action_t *actions,
                                   size_t count)
{
    if (!state || (count > 0 && !actions))
        return VIRP_ERR_NULL_PTR;
    if (count > ONODE_MAX_UID_ACTIONS)
        return VIRP_ERR_MESSAGE_TOO_LARGE;
    for (size_t i = 0; i < count; i++) {
        /* Only actions the wire can name — an unknown value would be a
         * rule nobody can match, misleading an auditor. */
        if (strcmp(onode_action_name(actions[i]), "unknown") == 0)
            return VIRP_ERR_INVALID_TYPE;
    }

    /* Replace an existing entry for this uid, else append. */
    ssize_t idx = -1;
    for (size_t i = 0; i < state->uid_action_count; i++)
        if (state->uid_action_uids[i] == uid) { idx = (ssize_t)i; break; }
    if (idx < 0) {
        if (state->uid_action_count >= ONODE_MAX_ALLOWED_UIDS)
            return VIRP_ERR_MESSAGE_TOO_LARGE;
        idx = (ssize_t)state->uid_action_count++;
        state->uid_action_uids[idx] = uid;
    }
    for (size_t i = 0; i < count; i++)
        state->uid_action_sets[idx][i] = actions[i];
    state->uid_action_set_counts[idx] = count;   /* 0 = deny-all */
    return VIRP_OK;
}

void onode_clear_uid_actions(onode_state_t *state)
{
    if (!state) return;
    state->uid_action_count = 0;
}

virp_error_t onode_start(onode_state_t *state)
{
    if (!state)
        return VIRP_ERR_NULL_PTR;

    /*
     * Ensure parent directory exists with 0700 owned by the current
     * effective UID. /run/virp is the canonical location; /tmp/-style
     * paths are still accepted (parent is '/' — skipped). Failure is
     * logged but non-fatal so bind() gets a chance to produce the
     * clearer error if the path really is unwritable.
     */
    const char *last_slash = strrchr(state->socket_path, '/');
    if (last_slash && last_slash != state->socket_path) {
        char dir[128];
        size_t n = (size_t)(last_slash - state->socket_path);
        if (n >= sizeof(dir)) n = sizeof(dir) - 1;
        memcpy(dir, state->socket_path, n);
        dir[n] = '\0';
        if (mkdir(dir, 0700) < 0 && errno != EEXIST) {
            fprintf(stderr, "[O-Node] mkdir %s: %s (continuing)\n",
                    dir, strerror(errno));
        } else if (errno != EEXIST) {
            /* Newly created — tighten owner/mode in case umask relaxed it. */
            chmod(dir, 0700);
        }
    }

    /*
     * If no allowlist was configured, default to the daemon's own
     * effective UID only. This keeps the socket closed to every other
     * local user unless an operator opts a UID in via the config.
     */
    if (state->socket_allowed_uids_count == 0) {
        state->socket_allowed_uids[0] = geteuid();
        state->socket_allowed_uids_count = 1;
        fprintf(stderr,
                "[O-Node] socket_allowed_uids: <default> = [%u] (daemon UID)\n",
                (unsigned)geteuid());
    } else {
        fprintf(stderr, "[O-Node] socket_allowed_uids:");
        for (size_t i = 0; i < state->socket_allowed_uids_count; i++)
            fprintf(stderr, " %u", (unsigned)state->socket_allowed_uids[i]);
        fprintf(stderr, "\n");
    }

    if (state->uid_ceiling_count > 0) {
        fprintf(stderr, "[O-Node] per-uid tier ceilings:");
        for (size_t i = 0; i < state->uid_ceiling_count; i++)
            fprintf(stderr, " %u=%s", (unsigned)state->uid_ceiling_uids[i],
                    gate_tier_name(state->uid_ceiling_tiers[i]));
        fprintf(stderr, " (node-wide ceiling = %s)\n",
                gate_tier_name(state->gate_max_tier));
    }

    /* Remove stale socket */
    unlink(state->socket_path);

    /* Create Unix domain socket */
    state->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (state->listen_fd < 0) {
        perror("[O-Node] socket");
        return VIRP_ERR_KEY_NOT_LOADED;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", state->socket_path);

    /*
     * Tighten umask so bind() creates the socket 0660 atomically — no
     * window where a world-accessible node exists on disk before chmod
     * runs. The chmod below is retained as belt-and-suspenders in case
     * the filesystem or a platform quirk ignores umask for AF_UNIX.
     */
    mode_t prev_umask = umask(0117);
    int bind_rc = bind(state->listen_fd, (struct sockaddr *)&addr, sizeof(addr));
    int bind_errno = errno;
    umask(prev_umask);
    if (bind_rc < 0) {
        errno = bind_errno;
        perror("[O-Node] bind");
        close(state->listen_fd);
        return VIRP_ERR_KEY_NOT_LOADED;
    }

    /* Belt-and-suspenders: force 0660 in case umask didn't apply. */
    chmod(state->socket_path, 0660);

    if (listen(state->listen_fd, ONODE_LISTEN_BACKLOG) < 0) {
        perror("[O-Node] listen");
        close(state->listen_fd);
        return VIRP_ERR_KEY_NOT_LOADED;
    }

    fprintf(stderr, "[O-Node] Listening on %s\n", state->socket_path);
    fprintf(stderr, "[O-Node] Node ID: 0x%08x\n", state->node_id);
    fprintf(stderr, "[O-Node] Devices: %d\n", state->device_count);
    fprintf(stderr, "[O-Node] Ready.\n\n");

    state->running = true;

    /* Start auto-reconnect watchdog thread */
    if (onode_watchdog_start(state) != VIRP_OK)
        perror("[O-Node] Failed to start watchdog thread");

    /* Event loop */
    while (state->running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(state->listen_fd, &readfds);

        /* Timeout for periodic heartbeat */
        struct timeval tv = { .tv_sec = ONODE_HEARTBEAT_SEC, .tv_usec = 0 };

        int ready = select(state->listen_fd + 1, &readfds, NULL, NULL, &tv);

        if (ready < 0) {
            if (errno == EINTR) continue;  /* Signal interrupted */
            perror("[O-Node] select");
            break;
        }

        if (ready == 0) {
            /* Timeout — periodic heartbeat (logged, not sent anywhere yet) */
            uint8_t hb_buf[256];
            size_t hb_len;
            if (onode_heartbeat(state, hb_buf, sizeof(hb_buf), &hb_len) == VIRP_OK) {
                uint32_t uptime = (uint32_t)(time(NULL) - state->uptime_start);
                int conn_up = 0, conn_total = 0;
                for (int ci = 0; ci < state->device_count; ci++) {
                    if (state->devices[ci].enabled) {
                        conn_total++;
                        if (state->connections[ci]) conn_up++;
                    }
                }
                fprintf(stderr, "[O-Node] Heartbeat: uptime=%us obs=%u seq=%u connected=%d/%d reconnects=%u\n",
                        uptime, state->observations_sent, state->seq_num,
                        conn_up, conn_total, state->reconnects);
            }
            continue;
        }

        if (FD_ISSET(state->listen_fd, &readfds)) {
            int client_fd = accept(state->listen_fd, NULL, NULL);
            if (client_fd < 0) {
                perror("[O-Node] accept");
                continue;
            }
            uid_t peer_uid = (uid_t)-1;
            pid_t peer_pid = 0;
            if (!peer_uid_allowed(state, client_fd, &peer_uid, &peer_pid)) {
                fprintf(stderr,
                        "[O-Node] REJECTED connection: peer uid=%u pid=%d "
                        "not in socket_allowed_uids\n",
                        (unsigned)peer_uid, (int)peer_pid);
                close(client_fd);
                continue;
            }

            /*
             * Reserve a worker slot. sem_trywait never blocks — if the
             * pool is full we reject immediately rather than letting
             * slow SSH sessions pile up behind the accept loop.
             */
            if (sem_trywait(&state->worker_sem) != 0) {
                pthread_mutex_lock(&state->state_mutex);
                state->workers_rejected++;
                uint32_t rej = state->workers_rejected;
                pthread_mutex_unlock(&state->state_mutex);
                fprintf(stderr,
                        "[O-Node] worker pool saturated (max=%d) — "
                        "closing peer uid=%u pid=%d (total rejected=%u)\n",
                        ONODE_MAX_WORKERS,
                        (unsigned)peer_uid, (int)peer_pid, rej);
                close(client_fd);
                continue;
            }

            worker_arg_t *arg = (worker_arg_t *)malloc(sizeof(*arg));
            if (!arg) {
                /* malloc failure: return the slot and drop the client. */
                sem_post(&state->worker_sem);
                fprintf(stderr, "[O-Node] worker_arg alloc failed — dropping\n");
                close(client_fd);
                continue;
            }
            arg->state = state;
            arg->client_fd = client_fd;
            arg->client_uid = peer_uid;   /* validated above; threaded so the
                                             worker needs no second cred read */

            /* Register a dup() of the client fd so the shutdown drain
             * can shutdown(SHUT_RDWR) the socket and unblock this
             * worker if it is mid-recv/send at drain time. The dup is
             * closed by the worker after it clears the slot, so the fd
             * number cannot be recycled while a drain might target it.
             * A failed dup just means this worker can't be unblocked
             * early — the drain timeout still bounds it.
             *
             * workers_live is incremented BEFORE pthread_create: the
             * worker's exit-side decrement must never be able to run
             * before the increment, or the drain barrier would wait a
             * full timeout on a phantom worker. */
            arg->slot = -1;
            int reg_fd = dup(client_fd);
            pthread_mutex_lock(&state->state_mutex);
            if (reg_fd >= 0) {
                for (int s = 0; s < ONODE_MAX_WORKERS; s++) {
                    if (state->worker_fds[s] < 0) {
                        state->worker_fds[s] = reg_fd;
                        arg->slot = s;
                        break;
                    }
                }
                if (arg->slot < 0)  /* can't happen: sem caps live workers */
                    close(reg_fd);
            }
            state->workers_live++;
            pthread_mutex_unlock(&state->state_mutex);

            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

            pthread_t tid;
            int rc = pthread_create(&tid, &attr, connection_worker, arg);
            pthread_attr_destroy(&attr);
            if (rc != 0) {
                /* Thread creation failed: undo counter, slot, sem, arg. */
                pthread_mutex_lock(&state->state_mutex);
                if (arg->slot >= 0 && state->worker_fds[arg->slot] >= 0) {
                    close(state->worker_fds[arg->slot]);
                    state->worker_fds[arg->slot] = -1;
                }
                if (state->workers_live > 0)
                    state->workers_live--;
                if (state->workers_live == 0)
                    pthread_cond_broadcast(&state->workers_cv);
                pthread_mutex_unlock(&state->state_mutex);
                sem_post(&state->worker_sem);
                free(arg);
                fprintf(stderr, "[O-Node] pthread_create failed: %s\n",
                        strerror(rc));
                close(client_fd);
                continue;
            }
        }
    }

    fprintf(stderr, "[O-Node] Shutting down...\n");

    /*
     * Drain the worker pool — a real barrier, not timeout-and-hope.
     *
     * 1. shutdown(SHUT_RDWR) every live worker's client socket (via the
     *    registered dups) so a worker blocked in recv/send on its
     *    client unblocks immediately. SSH I/O has its own 10-15s
     *    timeouts, so nothing in handle_client blocks unboundedly.
     * 2. Wait on workers_cv for workers_live to reach zero. Each
     *    in-flight request still finishes its execute AND its chain
     *    (audit) write before teardown, so a restart cannot truncate a
     *    durable record.
     * 3. ONODE_DRAIN_TIMEOUT_SEC is the last resort for a genuinely
     *    wedged worker — comfortably inside systemd's 90s stop window.
     *    If it fires, mark drain_failed: onode_destroy() must then LEAK
     *    the shared state (mutexes, connections, chain, keys) rather
     *    than free it under a live thread.
     */
    pthread_mutex_lock(&state->state_mutex);
    for (int s = 0; s < ONODE_MAX_WORKERS; s++) {
        if (state->worker_fds[s] >= 0)
            shutdown(state->worker_fds[s], SHUT_RDWR);
    }
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += ONODE_DRAIN_TIMEOUT_SEC;
    int wrc = 0;
    while (state->workers_live > 0 && wrc != ETIMEDOUT)
        wrc = pthread_cond_timedwait(&state->workers_cv,
                                     &state->state_mutex, &deadline);
    uint32_t live_final = state->workers_live;
    pthread_mutex_unlock(&state->state_mutex);
    if (live_final > 0) {
        state->drain_failed = true;
        fprintf(stderr,
                "[O-Node] DRAIN TIMEOUT after %ds — %u worker(s) still "
                "live. Shared state (mutexes, connections, chain, keys) "
                "will be LEAKED, not destroyed, to avoid freeing it "
                "under a live thread.\n",
                ONODE_DRAIN_TIMEOUT_SEC, live_final);
    }

    return VIRP_OK;
}

void onode_shutdown(onode_state_t *state)
{
    if (!state) return;
    state->running = false;
    state->watchdog_running = false;
}

void onode_destroy(onode_state_t *state)
{
    if (!state) return;

    /* Stop watchdog thread */
    state->watchdog_running = false;
    if (state->watchdog_thread)
        pthread_join(state->watchdog_thread, NULL);

    /*
     * Shutdown barrier check. onode_start()'s drain waits on workers_cv
     * for workers_live to reach zero; only if its hard timeout fired
     * can workers still be live here. A live worker may be inside
     * handle_client holding exec_mutex, signing with okey, or writing
     * the chain — destroying any of that under it is use-after-destroy.
     * In that case leak everything except the listen socket: the
     * process is exiting, the OS reclaims memory, and a leak cannot
     * corrupt the chain db the way freeing under a live writer can.
     */
    pthread_mutex_lock(&state->state_mutex);
    uint32_t live = state->workers_live;
    pthread_mutex_unlock(&state->state_mutex);
    if (state->drain_failed || live > 0) {
        fprintf(stderr,
                "[O-Node] REFUSING TEARDOWN — %u worker(s) still live "
                "after drain timeout. Leaking mutexes, connections, "
                "chain state, and key state; listen socket closed so a "
                "restart can bind. THIS IS A BUG IN A WORKER: it should "
                "never outlive the drain.\n",
                live);
        if (state->listen_fd >= 0) {
            close(state->listen_fd);
            unlink(state->socket_path);
        }
        return;
    }

    /*
     * Close all device connections. The listen socket has already been
     * closed by onode_shutdown()'s `running=false`, so no new client
     * requests will arrive; any in-flight onode_execute runs to
     * completion under exec_mutex[i]. Take exec_mutex[i] here too so
     * we can't race the final call to drv->execute.
     */
    for (int i = 0; i < state->device_count; i++) {
        pthread_mutex_lock(&state->exec_mutex[i]);
        if (state->connections[i]) {
            const virp_driver_t *drv = virp_driver_lookup(state->devices[i].vendor);
            if (drv)
                drv->disconnect(state->connections[i]);
            state->connections[i] = NULL;
        }
        pthread_mutex_unlock(&state->exec_mutex[i]);
    }

    /* Close listen socket */
    if (state->listen_fd >= 0) {
        close(state->listen_fd);
        unlink(state->socket_path);
    }

    /* Destroy trust chain */
    if (state->chain_enabled)
        virp_chain_destroy(&state->chain);

    /* Zeroize + munlock the observation-signing secret, if one was
     * loaded. Done after the device connections and listen socket are
     * gone so no worker can be mid-signature. */
    if (state->obskey_loaded) {
        virp_obskey_destroy(&state->obskey);
        state->obskey_loaded = false;
    }

    /* Wipe device passwords from inventory */
    for (int i = 0; i < state->device_count; i++) {
        OPENSSL_cleanse(state->devices[i].password,
                        sizeof(state->devices[i].password));
        OPENSSL_cleanse(state->devices[i].enable_password,
                        sizeof(state->devices[i].enable_password));
        OPENSSL_cleanse(state->devices[i].api_token,
                        sizeof(state->devices[i].api_token));
    }

    /* Destroy mutexes, drain condvar, and worker semaphore */
    pthread_cond_destroy(&state->workers_cv);
    pthread_mutex_destroy(&state->state_mutex);
    pthread_mutex_destroy(&state->conn_mutex);
    pthread_mutex_destroy(&state->session_mutex);
    for (int i = 0; i < state->device_count; i++)
        pthread_mutex_destroy(&state->exec_mutex[i]);
    if (state->worker_sem_inited) {
        sem_destroy(&state->worker_sem);
        state->worker_sem_inited = false;
    }

    /* Destroy the O-Key — zero it out */
    virp_key_destroy(&state->okey);

    fprintf(stderr, "[O-Node] Destroyed. %u observations signed, %u reconnects.\n",
            state->observations_sent, state->reconnects);
}

/* =========================================================================
 * Fuzz entry point
 *
 * Thin wrapper around parse_request() for fuzz harnesses. Accepts
 * arbitrary bytes of length n, copies them into a NUL-terminated
 * buffer, and invokes the parser. Contract: MUST NOT crash regardless
 * of input. Return value semantics mirror parse_request (true = parsed
 * into req, false = rejected). Defined alongside the parser so callers
 * don't need access to onode_request_t internals.
 * ========================================================================= */
bool onode_parse_request_fuzz(const uint8_t *data, size_t n)
{
    /* Refuse absurdly large inputs — parse_request itself would cap,
     * but this keeps the fuzzer from spending time on the same path. */
    if (n > ONODE_MAX_REQUEST_SIZE) return false;

    char *buf = (char *)malloc(n + 1);
    if (!buf) return false;
    if (n > 0) memcpy(buf, data, n);
    buf[n] = '\0';

    onode_request_t req;
    bool ok = parse_request(buf, &req);
    free(buf);
    return ok;
}
