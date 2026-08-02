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
    int32_t         obs_version;            /* 1 = legacy O-Key, 2 = session-bound */
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

    if (strcmp(action_str, "execute") == 0)
        req->action = ONODE_ACTION_EXECUTE;
    else if (strcmp(action_str, "health") == 0)
        req->action = ONODE_ACTION_HEALTH;
    else if (strcmp(action_str, "heartbeat") == 0)
        req->action = ONODE_ACTION_HEARTBEAT;
    else if (strcmp(action_str, "list_devices") == 0)
        req->action = ONODE_ACTION_LIST;
    else if (strcmp(action_str, "sign_intent") == 0)
        req->action = ONODE_ACTION_SIGN_INTENT;
    else if (strcmp(action_str, "sign_outcome") == 0)
        req->action = ONODE_ACTION_SIGN_OUTCOME;
    else if (strcmp(action_str, "chain_append") == 0)
        req->action = ONODE_ACTION_CHAIN_APPEND;
    else if (strcmp(action_str, "chain_verify") == 0)
        req->action = ONODE_ACTION_CHAIN_VERIFY;
    else if (strcmp(action_str, "chain_verify_session") == 0)
        req->action = ONODE_ACTION_CHAIN_VERIFY_SESSION;
    else if (strcmp(action_str, "intent_store") == 0)
        req->action = ONODE_ACTION_INTENT_STORE;
    else if (strcmp(action_str, "intent_get") == 0)
        req->action = ONODE_ACTION_INTENT_GET;
    else if (strcmp(action_str, "intent_execute") == 0)
        req->action = ONODE_ACTION_INTENT_EXECUTE;
    else if (strcmp(action_str, "batch_execute") == 0)
        req->action = ONODE_ACTION_BATCH_EXECUTE;
    else if (strcmp(action_str, "validate_turn") == 0)
        req->action = ONODE_ACTION_VALIDATE_TURN;
    else if (strcmp(action_str, "approval_challenge") == 0)
        req->action = ONODE_ACTION_APPROVAL_CHALLENGE;
    else if (strcmp(action_str, "approval_submit") == 0)
        req->action = ONODE_ACTION_APPROVAL_SUBMIT;
    else if (strcmp(action_str, "session_hello") == 0)
        req->action = ONODE_ACTION_SESSION_HELLO;
    else if (strcmp(action_str, "session_bind") == 0)
        req->action = ONODE_ACTION_SESSION_BIND;
    else if (strcmp(action_str, "session_close") == 0)
        req->action = ONODE_ACTION_SESSION_CLOSE;
    else if (strcmp(action_str, "shutdown") == 0)
        req->action = ONODE_ACTION_SHUTDOWN;
    else {
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
     * master-key signing, the compatibility default). Only 1 and 2 are
     * meaningful; anything else present-but-invalid rejects the request
     * so a client typo cannot silently downgrade to v1.
     */
    req->obs_version = 1;
    {
        uint64_t v = 0;
        if (json_extract_u64_bounded(root, "obs_version", 2, &v)) {
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

    virp_chain_entry_t ce;
    virp_error_t cerr = virp_chain_append(&state->chain, chain_session,
                                          "outcome", artifact_id,
                                          artifact_hash, &ce);
    if (cerr == VIRP_OK) {
        virp_chain_artifact_store(&state->chain, artifact_id, "outcome",
                                  content, artifact_hash, chain_session);
        fprintf(stderr, "[GATE] outcome persisted: proposal=%s seq=%lld "
                "hash=%.16s success=%s\n", proposal_id,
                (long long)ce.sequence, ce.chain_entry_hash,
                success ? "true" : "false");
    } else {
        fprintf(stderr, "[GATE] outcome chain_append failed: %s\n",
                virp_error_str(cerr));
    }
}

virp_error_t onode_execute(onode_state_t *state,
                           const char *device_name,
                           const char *command,
                           uint8_t *out_buf, size_t out_buf_len,
                           size_t *out_len)
{
    return onode_execute_obs_ex(state, device_name, command, 1, NULL,
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
                                NULL, out_buf, out_buf_len, out_len);
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
    if (err != VIRP_OK) {
        fprintf(stderr, "[APPROVAL] submit rejected: proposal=%s key_id=%s "
                "code=%d (%s)\n", proposal_id, key_id, (int)err,
                virp_approval_err_name(err));
        return err;
    }

    fprintf(stderr, "[APPROVAL] submitted: proposal=%s key_id=%s operator=%s "
            "chain=%.16s\n", apr.proposal_id, apr.approver_key_id,
            apr.operator[0] ? apr.operator : "(unknown)",
            apr.chain_entry_hash[0] ? apr.chain_entry_hash : "-");

    cJSON *o = cJSON_CreateObject();
    if (!o) return VIRP_ERR_BUFFER_TOO_SMALL;
    cJSON_AddStringToObject(o, "proposal_id", apr.proposal_id);
    cJSON_AddStringToObject(o, "approver_key_id", apr.approver_key_id);
    cJSON_AddStringToObject(o, "operator", apr.operator);
    cJSON_AddStringToObject(o, "chain_entry_hash", apr.chain_entry_hash);
    cJSON_AddNumberToObject(o, "approved_at_ns", (double)apr.approved_at_ns);
    cJSON_AddNumberToObject(o, "ttl_seconds", (double)apr.ttl_seconds);
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
                                  uint8_t *out_buf, size_t out_buf_len,
                                  size_t *out_len)
{
    if (!state || !device_name || !command || !out_buf || !out_len)
        return VIRP_ERR_NULL_PTR;
    if (obs_version != 1 && obs_version != 2)
        return VIRP_ERR_VERSION_MISMATCH;

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
     * v2 requires an ACTIVE session BEFORE any device I/O. Checked
     * again at signing time (the session can idle out mid-command),
     * but failing early avoids running a command whose observation
     * could never be delivered in the requested form.
     */
    if (obs_version == 2) {
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

    /*
     * Per-device execution lock — serializes all command execution on
     * this connection so that batch_execute threads targeting the same
     * device do not race on the libssh2 session.
     */
    pthread_mutex_lock(&state->exec_mutex[dev_idx]);

    /* Get or create connection */
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
                                      (const uint8_t *)err_msg, (uint16_t)strlen(err_msg),
                                      &state->okey);
    }

    /* ── Tier-enforcement gate (Phase B/C) ────────────────────────────
     * Classify at the boundary, decide allow/block against the configured
     * max tier, and log. SHADOW logs and proceeds; ENFORCE hard-rejects
     * over-tier / unclassified commands before the driver runs. The
     * classified tier (computed above, before the connection attempt) is
     * function-scoped so the success observation below can be stamped
     * with it (Phase C truth-fix). */
    {
        onode_gate_mode_t mode = gate_effective_mode(state, drv->name);
        bool block = gate_tier_blocks(gate_tier, state->gate_max_tier);

        /* ENFORCE states what it did; only SHADOW speaks hypothetically.
         * The old unconditional "would-block"/"would-allow" wording made
         * an ENFORCE rejection read like a logged-but-executed change. */
        fprintf(stderr,
                "[GATE] mode=%s device=%s driver=%s tier=%s threshold=%s "
                "decision=%s command=\"%s\"\n",
                mode == GATE_MODE_ENFORCE ? "ENFORCE" : "SHADOW",
                device_name, drv->name,
                gate_tier_name(gate_tier),
                gate_tier_name(state->gate_max_tier),
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
                         gate_tier_name(state->gate_max_tier));
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
                     gate_tier_name(state->gate_max_tier));

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
                    cJSON_AddStringToObject(o, "gate_max_tier",
                                            gate_tier_name(state->gate_max_tier));
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

                virp_chain_entry_t ce;
                virp_error_t cerr = virp_chain_append(&state->chain, session_id,
                                                      "gate_rejection",
                                                      artifact_id, artifact_hash,
                                                      &ce);
                if (cerr == VIRP_OK) {
                    /* Store the body under the same id the entry names.
                     * Best-effort like the append itself: a storage
                     * failure must not alter the rejection, but it is
                     * logged so a chain with unrecoverable reasons is
                     * visible rather than silent. */
                    if (body) {
                        virp_error_t serr = virp_chain_artifact_store(
                                &state->chain, artifact_id, "gate_rejection",
                                body, artifact_hash, session_id);
                        if (serr != VIRP_OK)
                            fprintf(stderr, "[GATE] rejection reason body "
                                    "store failed: %s (entry %s retains only "
                                    "the commitment)\n",
                                    virp_error_str(serr), artifact_id);
                    } else {
                        fprintf(stderr, "[GATE] rejection reason body could "
                                "not be built; entry %s retains only the "
                                "commitment\n", artifact_id);
                    }
                    fprintf(stderr, "[GATE] rejection persisted: session=%s "
                            "seq=%lld hash=%.16s\n", session_id,
                            (long long)ce.sequence, ce.chain_entry_hash);
                } else {
                    fprintf(stderr, "[GATE] rejection chain_append failed: %s\n",
                            virp_error_str(cerr));
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

    virp_exec_result_t result;
    virp_error_t err = drv->execute(conn, command, &result);
    if (err != VIRP_OK) {
        drop_connection(state, dev_idx);
        pthread_mutex_unlock(&state->exec_mutex[dev_idx]);
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg),
                 "ERROR: driver execute failed on '%s': %s",
                 device_name, virp_error_str(err));
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

    /* On failure: drop stale connection, retry once with fresh connection */
    if (!result.success && result.output_len == 0) {
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
     * Driver soft-failure with no output: the driver refused the command
     * before any device I/O (VIRP_OK + success=false + error_msg — the
     * shape REST drivers like Wazuh use for invalid or BLACK-tier
     * endpoints). Nothing executed, so this must be a signed ERROR
     * observation carrying the command's true tier — never the
     * DEVICE_OUTPUT / v2 session-bound constructor used for executed
     * output, which downstream renders as a logged change.
     */
    if (!result.success && result.output_len == 0 && result.error_msg[0]) {
        char err_msg[sizeof(result.error_msg) + 96];
        snprintf(err_msg, sizeof(err_msg),
                 "ERROR: driver refused '%s': %s",
                 device_name, result.error_msg);
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

    const uint8_t *obs_data = (const uint8_t *)result.output;
    uint16_t data_len = (result.output_len > 65530) ?
                         65530 : (uint16_t)result.output_len;

    /* Phase C truth-fix: stamp the observation with the command's real
     * gate-classified tier (clamped to a transmittable tier) instead of a
     * blanket GREEN. show system admin → RED; get system status → GREEN. */
    if (obs_version == 2) {
        /*
         * v2 success path: session-bound observation signed with the
         * HKDF session key. seq_num is per-session monotonic
         * (session.last_seq under session_mutex), which is what the
         * verifier's replay high-water store checks against. If the
         * session died while the command ran, fail — never downgrade
         * to master-key signing on a v2 request.
         */
        pthread_mutex_lock(&state->session_mutex);
        if (!state->ctx ||
            virp_session_require_active(state->ctx) != VIRP_OK ||
            !state->ctx->session.session_key_valid) {
            err = VIRP_ERR_SESSION_INVALID;
        } else {
            /* Truncate like the v1 path does rather than erroring:
             * total message (88 hdr + payload + 32 sig) must fit in
             * VIRP_MAX_MESSAGE_SIZE. */
            if ((size_t)data_len > VIRP_MAX_MESSAGE_SIZE -
                                   VIRP_OBS_V2_HEADER_SIZE -
                                   VIRP_OBS_V2_SIG_SIZE)
                data_len = (uint16_t)(VIRP_MAX_MESSAGE_SIZE -
                                      VIRP_OBS_V2_HEADER_SIZE -
                                      VIRP_OBS_V2_SIG_SIZE);
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
    uint8_t         *resp_buf;      /* heap-allocated, VIRP_MAX_MESSAGE_SIZE */
    size_t          resp_len;
    virp_error_t    err;
} batch_thread_arg_t;

static void *batch_execute_thread(void *arg)
{
    batch_thread_arg_t *bta = (batch_thread_arg_t *)arg;
    bta->resp_len = 0;
    bta->err = onode_execute_obs(bta->state, bta->device, bta->command,
                                 bta->obs_version,
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
 */
static int send_framed(int fd, const void *buf, size_t len)
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

static void handle_client(onode_state_t *state, int client_fd)
{
    char recv_buf[ONODE_MAX_REQUEST_SIZE];
    uint8_t resp_buf[VIRP_MAX_MESSAGE_SIZE];
    size_t resp_len = 0;

    /* Set receive timeout */
    struct timeval tv = { .tv_sec = ONODE_RECV_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

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

    switch (req.action) {
    case ONODE_ACTION_EXECUTE:
        if (req.device[0] == '\0' || req.command[0] == '\0') {
            send_framed_error(client_fd, VIRP_ERR_NULL_PTR);
            break;
        }
        err = onode_execute_obs_ex(state, req.device, req.command,
                                req.obs_version,
                                req.proposal_id[0] ? req.proposal_id : NULL,
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
        if (req.session_id[0] == '\0' || req.artifact_type[0] == '\0' ||
            req.artifact_id[0] == '\0' || req.artifact_hash[0] == '\0') {
            send_framed_error(client_fd, VIRP_ERR_NULL_PTR);
            break;
        }
        {
            virp_chain_entry_t chain_entry;
            err = virp_chain_append(&state->chain, req.session_id,
                                     req.artifact_type, req.artifact_id,
                                     req.artifact_hash, &chain_entry);
            if (err != VIRP_OK) {
                send_framed_error(client_fd, err);
                break;
            }
            /* Store raw artifact content if provided */
            if (req.artifact_content[0] != '\0') {
                virp_chain_artifact_store(&state->chain,
                    req.artifact_id, req.artifact_type,
                    req.artifact_content, req.artifact_hash,
                    req.session_id);
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
    free(arg);

    /* handle_client() closes the fd on every return path. */
    handle_client(state, fd);

    /* Release the worker slot and update the live counter. */
    pthread_mutex_lock(&state->state_mutex);
    if (state->workers_live > 0)
        state->workers_live--;
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

    state->connections[state->device_count] = NULL;
    state->device_count++;

    fprintf(stderr, "[O-Node] Added device: %s (%s) node_id=0x%08x\n",
            device->hostname, device->host, device->node_id);

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

            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

            pthread_t tid;
            int rc = pthread_create(&tid, &attr, connection_worker, arg);
            pthread_attr_destroy(&attr);
            if (rc != 0) {
                /* Thread creation failed: undo semaphore + free arg. */
                sem_post(&state->worker_sem);
                free(arg);
                fprintf(stderr, "[O-Node] pthread_create failed: %s\n",
                        strerror(rc));
                close(client_fd);
                continue;
            }

            pthread_mutex_lock(&state->state_mutex);
            state->workers_live++;
            pthread_mutex_unlock(&state->state_mutex);
        }
    }

    fprintf(stderr, "[O-Node] Shutting down...\n");

    /*
     * Drain the worker pool. Workers are detached (no pthread_join), so we
     * wait on the counter they maintain under state_mutex. This lets each
     * in-flight request finish its execute AND its chain (audit) write
     * before teardown, so a restart cannot truncate a durable record.
     *
     * Bounded to ~30s — comfortably longer than the worst-case in-flight
     * request (SSH read timeout ~10-15s + a fast SQLite chain append) yet
     * well inside systemd's 90s stop timeout, so a genuinely wedged worker
     * still can't push us past the deadline into a SIGKILL. If it does time
     * out we warn (audit visibility) rather than block forever.
     */
    for (int waited = 0; waited < 300; waited++) {   /* 300 * 100ms = 30s */
        pthread_mutex_lock(&state->state_mutex);
        uint32_t live = state->workers_live;
        pthread_mutex_unlock(&state->state_mutex);
        if (live == 0) break;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000L };  /* 100ms */
        nanosleep(&ts, NULL);
    }
    pthread_mutex_lock(&state->state_mutex);
    uint32_t live_final = state->workers_live;
    pthread_mutex_unlock(&state->state_mutex);
    if (live_final > 0) {
        fprintf(stderr,
                "[O-Node] drain timeout — %u worker(s) still live\n",
                live_final);
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

    /* Wipe device passwords from inventory */
    for (int i = 0; i < state->device_count; i++) {
        OPENSSL_cleanse(state->devices[i].password,
                        sizeof(state->devices[i].password));
        OPENSSL_cleanse(state->devices[i].enable_password,
                        sizeof(state->devices[i].enable_password));
        OPENSSL_cleanse(state->devices[i].api_token,
                        sizeof(state->devices[i].api_token));
    }

    /* Destroy mutexes and worker semaphore */
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
