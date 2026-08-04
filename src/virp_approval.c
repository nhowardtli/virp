/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Approval flow: propose → approve → apply (see include/virp_approval.h)
 *
 * The approver signs the padding-free CANONICAL payload (72 bytes, built
 * by virp_approval_build_canonical), NOT the JSON record. The record's
 * line-1 JSON is metadata; apply reconstructs the canonical bytes from
 * those fields and re-verifies, so a tampered field fails the signature.
 * Nanosecond timestamps are stored as decimal STRINGS: they exceed 2^53
 * and a JSON number (cJSON uses doubles) would round-trip lossily and
 * corrupt the canonical bytes.
 */

#define _POSIX_C_SOURCE 200809L

#include "virp_approval.h"
#include "virp_fault_inject.h"   /* lab-only; compiles away without -DVIRP_FAULT_INJECT */
#include "virp_crypto.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "cJSON.h"

/* Serializes consumed.list read-modify-write across worker threads. */
static pthread_mutex_t consume_mu = PTHREAD_MUTEX_INITIALIZER;

/* =========================================================================
 * Small helpers
 * ========================================================================= */

const char *virp_approval_err_name(virp_error_t err)
{
    switch (err) {
    case VIRP_ERR_APPROVAL_EXPIRED:         return "approval_expired";
    case VIRP_ERR_APPROVAL_REUSED:          return "approval_reused";
    case VIRP_ERR_APPROVAL_HASH_MISMATCH:   return "approval_hash_mismatch";
    case VIRP_ERR_APPROVAL_DEVICE_MISMATCH: return "approval_device_mismatch";
    case VIRP_ERR_APPROVAL_BAD_SIGNATURE:   return "approval_bad_signature";
    case VIRP_ERR_APPROVAL_NOT_FOUND:       return "approval_not_found";
    case VIRP_ERR_APPROVAL_CONSUMED:        return "approval_proposal_consumed";
    case VIRP_ERR_APPROVAL_KEY_UNENROLLED:  return "approval_key_unenrolled";
    case VIRP_ERR_APPROVAL_KEY_DISABLED:    return "approval_key_disabled";
    case VIRP_APPROVAL_ALREADY_EXISTS:      return "approval_already_exists";
    default:                                return "error";
    }
}

static uint64_t now_realtime_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void sha256_hex(const void *data, size_t len, char out[65])
{
    unsigned char md[32];
    unsigned int mdlen = 0;
    EVP_Digest(data, len, md, &mdlen, EVP_sha256(), NULL);
    for (int i = 0; i < 32; i++)
        snprintf(out + i * 2, 3, "%02x", md[i]);
}

/*
 * command_hash = SHA-256 hex, the same derivation the v2 observation
 * header uses — including the typed-operation split.
 *
 * typed_profile NULL -> canonicalize, then hash (historic CLI path).
 * typed_profile set  -> exact validated octets via virp_typed_op_hash().
 *
 * The split matters most HERE. An approval record binds an approver's
 * signature to a command hash; if two different command spellings hash
 * alike, an approval issued for one authorizes the other. The typed
 * parser refuses whitespace variants, but the canonicalizer collapses
 * them, so without this split `pbs  op=X` (refused) and `pbs op=X`
 * (approved) share a hash. Latent only while no typed profile has an
 * approvable non-GREEN row.
 */
static virp_error_t command_hash_hex(const char *command,
                                     const char *typed_profile,
                                     char out[65])
{
    if (typed_profile) {
        uint8_t md[32];
        virp_error_t e = virp_typed_op_hash(typed_profile, command,
                                            strlen(command), md);
        if (e != VIRP_OK) return e;
        for (int i = 0; i < 32; i++)
            snprintf(out + i * 2, 3, "%02x", md[i]);
        return VIRP_OK;
    }

    char canon[512];
    if (virp_canonicalize_command(command, canon, sizeof(canon)) < 0)
        return VIRP_ERR_INVALID_LENGTH;
    sha256_hex(canon, strlen(canon), out);
    return VIRP_OK;
}

/*
 * proposal_id values come from clients and become path components:
 * accept EXACTLY 32 lowercase hex chars, nothing else.
 */
static bool proposal_id_valid(const char *id)
{
    if (!id) return false;
    size_t n = strspn(id, "0123456789abcdef");
    return n == VIRP_APPROVAL_ID_HEX_LEN && id[n] == '\0';
}

static bool hex64_valid(const char *h)
{
    if (!h) return false;
    size_t n = strspn(h, "0123456789abcdef");
    return n == 64 && h[n] == '\0';
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Ensure dir and its proposals/, approvals/, challenges/ subdirs exist
 * (0700; EEXIST is fine). */
static virp_error_t ensure_dirs(const char *dir)
{
    char sub[VIRP_APPROVAL_DIR_MAX + 16];
    if (!dir || !dir[0] || strlen(dir) >= VIRP_APPROVAL_DIR_MAX)
        return VIRP_ERR_INVALID_LENGTH;
    if (mkdir(dir, 0700) != 0 && errno != EEXIST)
        return VIRP_ERR_CHAIN_DB;
    const char *subs[] = { "proposals", "approvals", "challenges" };
    for (size_t i = 0; i < sizeof(subs) / sizeof(subs[0]); i++) {
        snprintf(sub, sizeof(sub), "%s/%s", dir, subs[i]);
        if (mkdir(sub, 0700) != 0 && errno != EEXIST)
            return VIRP_ERR_CHAIN_DB;
    }
    return VIRP_OK;
}

/* Decode `n` hex chars into `out` (n/2 bytes). Returns 0 or -1. */
static int hex2bin(const char *hex, size_t n, uint8_t *out)
{
    if (strlen(hex) < n) return -1;
    for (size_t i = 0; i < n; i += 2) {
        int hi = hexval(hex[i]), lo = hexval(hex[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static void put_be64(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) { p[i] = (uint8_t)(v & 0xff); v >>= 8; }
}
static void put_be32(uint8_t *p, uint32_t v)
{
    for (int i = 3; i >= 0; i--) { p[i] = (uint8_t)(v & 0xff); v >>= 8; }
}

virp_error_t virp_approval_build_canonical(const char *proposal_id_hex,
                                           const char *command_hash_hex,
                                           uint32_t device_node_id,
                                           uint64_t approved_at_ns,
                                           uint32_t ttl_seconds,
                                           uint8_t out[VIRP_APPROVAL_CANON_SIZE])
{
    if (!proposal_id_hex || !command_hash_hex || !out)
        return VIRP_ERR_NULL_PTR;
    if (!proposal_id_valid(proposal_id_hex) || !hex64_valid(command_hash_hex))
        return VIRP_ERR_INVALID_LENGTH;

    memcpy(out, VIRP_APPROVAL_CANON_MAGIC, 4);
    if (hex2bin(proposal_id_hex, 32, out + 4) != 0)     /* 16 bytes */
        return VIRP_ERR_INVALID_LENGTH;
    if (hex2bin(command_hash_hex, 64, out + 20) != 0)   /* 32 bytes */
        return VIRP_ERR_INVALID_LENGTH;
    put_be64(out + 52, (uint64_t)device_node_id);
    put_be64(out + 60, approved_at_ns);
    put_be32(out + 68, ttl_seconds);
    return VIRP_OK;
}

/*
 * Durable small-file write for NUL-terminated record text.
 *
 * Thin shim over virp_write_file_durable(), which owns the symlink-safe
 * create (O_EXCL|O_NOFOLLOW|O_CLOEXEC after unlinking any stale temp),
 * the exact-mode fchmod, the short-write loop, and the parent-directory
 * fsync. Callers here all write text records, so strlen is correct; the
 * shared helper takes a length because key material is binary.
 */
static virp_error_t write_file_durable(const char *path, mode_t mode,
                                       const char *content)
{
    return virp_write_file_durable(path, mode, content, strlen(content));
}

/* Read a whole record file (bounded). Returns byte count or -1. */
static ssize_t read_file(const char *path, char *buf, size_t buf_len)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t got = fread(buf, 1, buf_len - 1, f);
    fclose(f);
    buf[got] = '\0';
    return (ssize_t)got;
}

/* Split a record buffer into up to 3 lines (in place). Missing lines
 * come back as "". */
static void split_lines(char *buf, char *lines[3])
{
    lines[0] = buf;
    lines[1] = lines[2] = buf + strlen(buf);   /* default: empty */
    char *p = strchr(buf, '\n');
    if (!p) return;
    *p = '\0';
    lines[1] = p + 1;
    p = strchr(lines[1], '\n');
    if (!p) return;
    *p = '\0';
    lines[2] = p + 1;
    p = strchr(lines[2], '\n');
    if (p) *p = '\0';
}

/* Copy a required string field out of a cJSON object. */
static bool jget_str(cJSON *root, const char *key, char *dst, size_t dst_len)
{
    cJSON *it = cJSON_GetObjectItemCaseSensitive(root, key);
    if (!cJSON_IsString(it) || !it->valuestring) return false;
    snprintf(dst, dst_len, "%s", it->valuestring);
    return true;
}

static bool jget_u64(cJSON *root, const char *key, uint64_t *out)
{
    cJSON *it = cJSON_GetObjectItemCaseSensitive(root, key);
    if (!cJSON_IsNumber(it) || it->valuedouble < 0) return false;
    *out = (uint64_t)it->valuedouble;
    return true;
}

/*
 * Read a uint64 stored as a DECIMAL STRING. Nanosecond timestamps exceed
 * 2^53 and a JSON number (cJSON stores doubles) would round-trip lossily,
 * corrupting the canonical bytes the signature covers. Timestamps are
 * therefore serialized as strings.
 */
static bool jget_u64str(cJSON *root, const char *key, uint64_t *out)
{
    cJSON *it = cJSON_GetObjectItemCaseSensitive(root, key);
    if (!cJSON_IsString(it) || !it->valuestring || !it->valuestring[0])
        return false;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(it->valuestring, &end, 10);
    if (errno != 0 || *end != '\0') return false;
    *out = (uint64_t)v;
    return true;
}

/* Add a uint64 as a decimal string (see jget_u64str). */
static bool jadd_u64str(cJSON *o, const char *key, uint64_t v)
{
    char s[24];
    snprintf(s, sizeof(s), "%llu", (unsigned long long)v);
    return cJSON_AddStringToObject(o, key, s) != NULL;
}

/* =========================================================================
 * Proposal
 * ========================================================================= */

static void proposal_path(const char *dir, const char *id,
                          char *out, size_t out_len)
{
    snprintf(out, out_len, "%s/proposals/%s.rec", dir, id);
}

static void approval_path(const char *dir, const char *id,
                          char *out, size_t out_len)
{
    snprintf(out, out_len, "%s/approvals/%s.rec", dir, id);
}

/* Serialize the proposal body as one compact JSON line. */
static virp_error_t proposal_json(const virp_proposal_rec_t *p,
                                  char *out, size_t out_len)
{
    cJSON *o = cJSON_CreateObject();
    if (!o) return VIRP_ERR_BUFFER_TOO_SMALL;
    bool ok =
        cJSON_AddStringToObject(o, "proposal_id", p->proposal_id) &&
        cJSON_AddStringToObject(o, "session_id", p->session_id) &&
        cJSON_AddStringToObject(o, "device", p->device) &&
        cJSON_AddNumberToObject(o, "device_node_id", (double)p->device_node_id) &&
        cJSON_AddStringToObject(o, "command", p->command) &&
        cJSON_AddStringToObject(o, "command_hash", p->command_hash) &&
        cJSON_AddStringToObject(o, "proposer", p->proposer) &&
        jadd_u64str(o, "timestamp_ns", p->timestamp_ns) &&
        cJSON_AddStringToObject(o, "tier", p->tier);
    if (!ok) { cJSON_Delete(o); return VIRP_ERR_BUFFER_TOO_SMALL; }
    char *s = cJSON_PrintUnformatted(o);
    cJSON_Delete(o);
    if (!s) return VIRP_ERR_BUFFER_TOO_SMALL;
    int n = snprintf(out, out_len, "%s", s);
    cJSON_free(s);
    if (n < 0 || (size_t)n >= out_len)
        return VIRP_ERR_BUFFER_TOO_SMALL;
    return VIRP_OK;
}

virp_error_t virp_approval_propose(const char *dir,
                                   virp_chain_state_t *chain,
                                   const char *session_id,
                                   const char *device,
                                   uint32_t device_node_id,
                                   const char *command,
                                   const char *typed_profile,
                                   const char *proposer,
                                   const char *tier_name,
                                   virp_proposal_rec_t *out)
{
    if (!dir || !device || !command || !out)
        return VIRP_ERR_NULL_PTR;

    virp_error_t err = ensure_dirs(dir);
    if (err != VIRP_OK) return err;

    memset(out, 0, sizeof(*out));

    uint8_t rnd[VIRP_APPROVAL_ID_HEX_LEN / 2];
    if (RAND_bytes(rnd, sizeof(rnd)) != 1)
        return VIRP_ERR_CRYPTO;
    for (size_t i = 0; i < sizeof(rnd); i++)
        snprintf(out->proposal_id + i * 2, 3, "%02x", rnd[i]);

    snprintf(out->session_id, sizeof(out->session_id), "%s",
             session_id ? session_id : "");
    snprintf(out->device, sizeof(out->device), "%s", device);
    out->device_node_id = device_node_id;
    snprintf(out->command, sizeof(out->command), "%s", command);
    err = command_hash_hex(command, typed_profile, out->command_hash);
    if (err != VIRP_OK) return err;
    snprintf(out->proposer, sizeof(out->proposer), "%s",
             proposer && proposer[0] ? proposer : "unauthenticated-v1");
    out->timestamp_ns = now_realtime_ns();
    snprintf(out->tier, sizeof(out->tier), "%s", tier_name ? tier_name : "?");

    char body[2560];
    err = proposal_json(out, body, sizeof(body));
    if (err != VIRP_OK) return err;

    /* PROPOSAL chain entry first, so the record can carry its hash. */
    if (chain) {
        char artifact_hash[65];
        sha256_hex(body, strlen(body), artifact_hash);
        char artifact_id[64];
        snprintf(artifact_id, sizeof(artifact_id), "proposal:%s",
                 out->proposal_id);
        char chain_session[96];
        snprintf(chain_session, sizeof(chain_session), "approval:%s", device);
        /* Entry + body in one transaction: a filed proposal always has
         * its body recoverable from the chain, and a body-store failure
         * fails the filing typed instead of stranding a commitment. */
        virp_chain_entry_t ce;
        err = virp_chain_append_with_artifact(chain, chain_session,
                                              "proposal", artifact_id,
                                              artifact_hash, body, &ce);
        if (err != VIRP_OK) return err;
        snprintf(out->chain_entry_hash, sizeof(out->chain_entry_hash), "%s",
                 ce.chain_entry_hash);
    }

    char rec[2700];
    snprintf(rec, sizeof(rec), "%s\n%s\n", body,
             out->chain_entry_hash[0] ? out->chain_entry_hash : "-");

    char path[VIRP_APPROVAL_DIR_MAX + 64];
    proposal_path(dir, out->proposal_id, path, sizeof(path));
    return write_file_durable(path, 0640, rec);
}

virp_error_t virp_approval_load_proposal(const char *dir,
                                         const char *proposal_id,
                                         virp_proposal_rec_t *out)
{
    if (!dir || !out)
        return VIRP_ERR_NULL_PTR;
    if (!proposal_id_valid(proposal_id))
        return VIRP_ERR_APPROVAL_NOT_FOUND;

    char path[VIRP_APPROVAL_DIR_MAX + 64];
    proposal_path(dir, proposal_id, path, sizeof(path));

    char buf[4096];
    if (read_file(path, buf, sizeof(buf)) < 0)
        return VIRP_ERR_APPROVAL_NOT_FOUND;

    char *lines[3];
    split_lines(buf, lines);

    cJSON *o = cJSON_Parse(lines[0]);
    if (!o || !cJSON_IsObject(o)) {
        if (o) cJSON_Delete(o);
        return VIRP_ERR_CHAIN_DB;               /* corrupt — fail closed */
    }

    memset(out, 0, sizeof(*out));
    uint64_t nid = 0, ts = 0;
    bool ok =
        jget_str(o, "proposal_id", out->proposal_id, sizeof(out->proposal_id)) &&
        jget_str(o, "session_id", out->session_id, sizeof(out->session_id)) &&
        jget_str(o, "device", out->device, sizeof(out->device)) &&
        jget_u64(o, "device_node_id", &nid) &&
        jget_str(o, "command", out->command, sizeof(out->command)) &&
        jget_str(o, "command_hash", out->command_hash, sizeof(out->command_hash)) &&
        jget_str(o, "proposer", out->proposer, sizeof(out->proposer)) &&
        jget_u64str(o, "timestamp_ns", &ts) &&
        jget_str(o, "tier", out->tier, sizeof(out->tier));
    cJSON_Delete(o);
    if (!ok || nid > UINT32_MAX ||
        strcmp(out->proposal_id, proposal_id) != 0 ||
        !hex64_valid(out->command_hash))
        return VIRP_ERR_CHAIN_DB;
    out->device_node_id = (uint32_t)nid;
    out->timestamp_ns = ts;

    if (lines[1][0] && strcmp(lines[1], "-") != 0)
        snprintf(out->chain_entry_hash, sizeof(out->chain_entry_hash), "%s",
                 lines[1]);
    return VIRP_OK;
}

/* =========================================================================
 * Approval
 * ========================================================================= */

/* Serializes the SUBMIT critical section (OUTCOME/existing-approval check
 * → chain append → record write) so two concurrent submits for one
 * proposal produce exactly one APPROVAL chain entry. */
static pthread_mutex_t submit_mu = PTHREAD_MUTEX_INITIALIZER;

/* Metadata JSON for the approval record (line 1). NOT the signed bytes —
 * the signature is over the 72-byte canonical payload. */
static virp_error_t approval_json(const virp_approval_rec_t *a,
                                  char *out, size_t out_len)
{
    cJSON *o = cJSON_CreateObject();
    if (!o) return VIRP_ERR_BUFFER_TOO_SMALL;
    bool ok =
        cJSON_AddStringToObject(o, "proposal_id", a->proposal_id) &&
        cJSON_AddStringToObject(o, "command_hash", a->command_hash) &&
        cJSON_AddStringToObject(o, "device", a->device) &&
        cJSON_AddNumberToObject(o, "device_node_id", (double)a->device_node_id) &&
        jadd_u64str(o, "approved_at_ns", a->approved_at_ns) &&
        cJSON_AddNumberToObject(o, "ttl_seconds", (double)a->ttl_seconds) &&
        cJSON_AddStringToObject(o, "approver_key_id", a->approver_key_id) &&
        cJSON_AddStringToObject(o, "operator", a->operator);
    if (!ok) { cJSON_Delete(o); return VIRP_ERR_BUFFER_TOO_SMALL; }
    char *s = cJSON_PrintUnformatted(o);
    cJSON_Delete(o);
    if (!s) return VIRP_ERR_BUFFER_TOO_SMALL;
    int n = snprintf(out, out_len, "%s", s);
    cJSON_free(s);
    if (n < 0 || (size_t)n >= out_len)
        return VIRP_ERR_BUFFER_TOO_SMALL;
    return VIRP_OK;
}

virp_error_t virp_approval_write_record(const char *dir,
                                        const virp_approval_rec_t *rec,
                                        const uint8_t *sig, size_t sig_len)
{
    if (!dir || !rec || !sig)
        return VIRP_ERR_NULL_PTR;
    if (sig_len != VIRP_APPROVER_SIG_SIZE)
        return VIRP_ERR_INVALID_LENGTH;
    if (!proposal_id_valid(rec->proposal_id))
        return VIRP_ERR_APPROVAL_NOT_FOUND;

    virp_error_t err = ensure_dirs(dir);
    if (err != VIRP_OK) return err;

    char body[1700];
    err = approval_json(rec, body, sizeof(body));
    if (err != VIRP_OK) return err;

    char sig_hex[2 * VIRP_APPROVER_SIG_SIZE + 1];
    for (size_t i = 0; i < sig_len; i++)
        snprintf(sig_hex + i * 2, 3, "%02x", sig[i]);

    char filebuf[2200];
    snprintf(filebuf, sizeof(filebuf), "%s\n%s\n%s\n", body, sig_hex,
             rec->chain_entry_hash[0] ? rec->chain_entry_hash : "-");

    char path[VIRP_APPROVAL_DIR_MAX + 64];
    approval_path(dir, rec->proposal_id, path, sizeof(path));
    /* 0644: a signed public statement the daemon (any uid) must read. */
    return write_file_durable(path, 0644, filebuf);
}

/* =========================================================================
 * Challenge (pending) records
 * ========================================================================= */

static void challenge_path(const char *dir, const char *id,
                           char *out, size_t out_len)
{
    snprintf(out, out_len, "%s/challenges/%s.rec", dir, id);
}

static virp_error_t challenge_write(const char *dir,
                                    const virp_approval_challenge_t *c)
{
    cJSON *o = cJSON_CreateObject();
    if (!o) return VIRP_ERR_BUFFER_TOO_SMALL;
    bool ok =
        cJSON_AddStringToObject(o, "proposal_id", c->proposal_id) &&
        cJSON_AddStringToObject(o, "command_hash", c->command_hash) &&
        cJSON_AddStringToObject(o, "device", c->device) &&
        cJSON_AddNumberToObject(o, "device_node_id", (double)c->device_node_id) &&
        jadd_u64str(o, "approved_at_ns", c->approved_at_ns) &&
        cJSON_AddNumberToObject(o, "ttl_seconds", (double)c->ttl_seconds);
    if (!ok) { cJSON_Delete(o); return VIRP_ERR_BUFFER_TOO_SMALL; }
    char *s = cJSON_PrintUnformatted(o);
    cJSON_Delete(o);
    if (!s) return VIRP_ERR_BUFFER_TOO_SMALL;
    char path[VIRP_APPROVAL_DIR_MAX + 64];
    challenge_path(dir, c->proposal_id, path, sizeof(path));
    virp_error_t err = write_file_durable(path, 0640, s);
    cJSON_free(s);
    return err;
}

/* Load a pending challenge and reconstruct its canonical bytes. */
static virp_error_t challenge_load(const char *dir, const char *proposal_id,
                                   virp_approval_challenge_t *out)
{
    char path[VIRP_APPROVAL_DIR_MAX + 64];
    challenge_path(dir, proposal_id, path, sizeof(path));
    char buf[2048];
    if (read_file(path, buf, sizeof(buf)) < 0)
        return VIRP_ERR_APPROVAL_NOT_FOUND;

    cJSON *o = cJSON_Parse(buf);
    if (!o || !cJSON_IsObject(o)) {
        if (o) cJSON_Delete(o);
        return VIRP_ERR_CHAIN_DB;
    }
    memset(out, 0, sizeof(*out));
    uint64_t nid = 0, at = 0, ttl = 0;
    bool ok =
        jget_str(o, "proposal_id", out->proposal_id, sizeof(out->proposal_id)) &&
        jget_str(o, "command_hash", out->command_hash, sizeof(out->command_hash)) &&
        jget_str(o, "device", out->device, sizeof(out->device)) &&
        jget_u64(o, "device_node_id", &nid) &&
        jget_u64str(o, "approved_at_ns", &at) &&
        jget_u64(o, "ttl_seconds", &ttl);
    cJSON_Delete(o);
    if (!ok || nid > UINT32_MAX || ttl > 86400 ||
        strcmp(out->proposal_id, proposal_id) != 0 ||
        !hex64_valid(out->command_hash))
        return VIRP_ERR_CHAIN_DB;
    out->device_node_id = (uint32_t)nid;
    out->approved_at_ns = at;
    out->ttl_seconds = (uint32_t)ttl;
    return virp_approval_build_canonical(out->proposal_id, out->command_hash,
                                         out->device_node_id,
                                         out->approved_at_ns,
                                         out->ttl_seconds, out->canonical);
}

/* L1 enforcement: does an OUTCOME chain entry already exist? On query
 * error, fail CLOSED (treat as consumed) so a second approval is never
 * minted when we cannot prove the first did not run. */
static bool approval_has_outcome(virp_chain_state_t *chain,
                                 const char *proposal_id)
{
    if (!chain) return false;
    char aid[64];
    snprintf(aid, sizeof(aid), "outcome:%s", proposal_id);
    bool exists = false;
    if (virp_chain_artifact_exists(chain, aid, &exists) != VIRP_OK)
        return true;
    return exists;
}

/* =========================================================================
 * Challenge / Submit (daemon-side; daemon is the sole chain writer)
 * ========================================================================= */

virp_error_t virp_approval_challenge(const char *dir,
                                     virp_chain_state_t *chain,
                                     const char *proposal_id,
                                     uint64_t now_ns,
                                     virp_approval_challenge_t *out)
{
    if (!dir || !proposal_id || !out)
        return VIRP_ERR_NULL_PTR;
    if (!proposal_id_valid(proposal_id))
        return VIRP_ERR_APPROVAL_NOT_FOUND;

    /* L1: no challenge for a proposal that already produced an outcome. */
    if (approval_has_outcome(chain, proposal_id))
        return VIRP_ERR_APPROVAL_CONSUMED;

    virp_proposal_rec_t prop;
    virp_error_t err = virp_approval_load_proposal(dir, proposal_id, &prop);
    if (err != VIRP_OK) return err;

    err = ensure_dirs(dir);
    if (err != VIRP_OK) return err;

    memset(out, 0, sizeof(*out));
    snprintf(out->proposal_id, sizeof(out->proposal_id), "%s", prop.proposal_id);
    snprintf(out->device, sizeof(out->device), "%s", prop.device);
    snprintf(out->command, sizeof(out->command), "%s", prop.command);
    snprintf(out->command_hash, sizeof(out->command_hash), "%s",
             prop.command_hash);
    snprintf(out->tier, sizeof(out->tier), "%s", prop.tier);
    out->device_node_id = prop.device_node_id;
    out->approved_at_ns = now_ns ? now_ns : now_realtime_ns();
    out->ttl_seconds = VIRP_APPROVAL_TTL_SECONDS;

    err = virp_approval_build_canonical(out->proposal_id, out->command_hash,
                                        out->device_node_id,
                                        out->approved_at_ns, out->ttl_seconds,
                                        out->canonical);
    if (err != VIRP_OK) return err;

    return challenge_write(dir, out);
}

static virp_error_t approval_record_load(const char *dir,
                                         const char *proposal_id,
                                         virp_approval_rec_t *out);

virp_error_t virp_approval_submit(const char *dir,
                                  const virp_approver_registry_t *reg,
                                  virp_chain_state_t *chain,
                                  const char *proposal_id,
                                  const char *key_id,
                                  const uint8_t *sig, size_t sig_len,
                                  virp_approval_rec_t *out)
{
    if (!dir || !reg || !proposal_id || !key_id || !sig || !out)
        return VIRP_ERR_NULL_PTR;
    if (!proposal_id_valid(proposal_id))
        return VIRP_ERR_APPROVAL_NOT_FOUND;
    if (sig_len != VIRP_APPROVER_SIG_SIZE)
        return VIRP_ERR_APPROVAL_BAD_SIGNATURE;

    /* L1: a proposal that already produced an OUTCOME cannot be approved
     * again — checked BEFORE signature verification so the rejection names
     * the consumed state, not a signature problem. */
    if (approval_has_outcome(chain, proposal_id))
        return VIRP_ERR_APPROVAL_CONSUMED;

    /* key_id must be enrolled (and enabled). */
    const virp_approver_t *ent = virp_approver_registry_find_any(reg, key_id);
    if (!ent)
        return VIRP_ERR_APPROVAL_KEY_UNENROLLED;
    if (!ent->enabled)
        return VIRP_ERR_APPROVAL_KEY_DISABLED;

    /* Reconstruct the exact canonical bytes from the pending challenge. */
    virp_approval_challenge_t ch;
    virp_error_t err = challenge_load(dir, proposal_id, &ch);
    if (err != VIRP_OK) return err;

    /* Verify the signature over the canonical bytes with the enrolled key. */
    if (virp_approver_verify(ent, ch.canonical, VIRP_APPROVAL_CANON_SIZE,
                             sig, sig_len) != VIRP_OK)
        return VIRP_ERR_APPROVAL_BAD_SIGNATURE;

    memset(out, 0, sizeof(*out));
    snprintf(out->proposal_id, sizeof(out->proposal_id), "%s", ch.proposal_id);
    snprintf(out->command_hash, sizeof(out->command_hash), "%s", ch.command_hash);
    snprintf(out->device, sizeof(out->device), "%s", ch.device);
    out->device_node_id = ch.device_node_id;
    out->approved_at_ns = ch.approved_at_ns;
    out->ttl_seconds = ch.ttl_seconds;
    snprintf(out->approver_key_id, sizeof(out->approver_key_id), "%s",
             ent->key_id);
    snprintf(out->operator, sizeof(out->operator), "%s", ent->operator);
    memcpy(out->sig, sig, sig_len);

    /* Serialize the chain-append + record-write so concurrent submits for
     * one proposal yield exactly one APPROVAL entry. */
    pthread_mutex_lock(&submit_mu);

    /* Re-check L1 under the lock, and short-circuit if this proposal was
     * already submitted (idempotent: load the existing record, one entry). */
    if (approval_has_outcome(chain, proposal_id)) {
        pthread_mutex_unlock(&submit_mu);
        return VIRP_ERR_APPROVAL_CONSUMED;
    }
    char apath[VIRP_APPROVAL_DIR_MAX + 64];
    approval_path(dir, proposal_id, apath, sizeof(apath));
    char probe[16];
    if (read_file(apath, probe, sizeof(probe)) >= 0) {
        /* Already approved by a concurrent/earlier submit. Attribution
         * is the product: *out was filled above with the CALLER's
         * identity, but the approver of record is whoever won the race
         * — overwrite *out from the canonical persisted record and say
         * so with a distinct success-class code, so no caller can log
         * or report the loser as the approver. */
        virp_error_t lerr = approval_record_load(dir, proposal_id, out);
        pthread_mutex_unlock(&submit_mu);
        return (lerr == VIRP_OK) ? VIRP_APPROVAL_ALREADY_EXISTS : lerr;
    }

    if (chain) {
        char content[1700];
        err = approval_json(out, content, sizeof(content));
        if (err != VIRP_OK) { pthread_mutex_unlock(&submit_mu); return err; }
        char artifact_hash[65];
        sha256_hex(content, strlen(content), artifact_hash);
        char artifact_id[64];
        snprintf(artifact_id, sizeof(artifact_id), "approval:%s",
                 out->proposal_id);
        char chain_session[96];
        snprintf(chain_session, sizeof(chain_session), "approval:%s",
                 out->device);
        /* Entry + body in one transaction — same rationale as the
         * proposal filing above. */
        virp_chain_entry_t ce;
        err = virp_chain_append_with_artifact(chain, chain_session,
                                              "approval", artifact_id,
                                              artifact_hash, content, &ce);
        if (err != VIRP_OK) { pthread_mutex_unlock(&submit_mu); return err; }
        snprintf(out->chain_entry_hash, sizeof(out->chain_entry_hash), "%s",
                 ce.chain_entry_hash);
    }

    err = virp_approval_write_record(dir, out, sig, sig_len);
    pthread_mutex_unlock(&submit_mu);
    return err;
}

/* =========================================================================
 * Apply-side verification + single-use consume
 * ========================================================================= */

static virp_error_t approval_load_raw(const char *dir,
                                      const char *proposal_id,
                                      char *body, size_t body_len,
                                      uint8_t sig[VIRP_FED_SIG_SIZE],
                                      char chain_hash[65])
{
    char path[VIRP_APPROVAL_DIR_MAX + 64];
    approval_path(dir, proposal_id, path, sizeof(path));

    char buf[4096];
    if (read_file(path, buf, sizeof(buf)) < 0)
        return VIRP_ERR_APPROVAL_NOT_FOUND;

    char *lines[3];
    split_lines(buf, lines);

    size_t blen = strlen(lines[0]);
    if (blen == 0 || blen >= body_len)
        return VIRP_ERR_APPROVAL_BAD_SIGNATURE;
    memcpy(body, lines[0], blen + 1);

    if (strlen(lines[1]) != 2 * VIRP_FED_SIG_SIZE)
        return VIRP_ERR_APPROVAL_BAD_SIGNATURE;
    for (int i = 0; i < VIRP_FED_SIG_SIZE; i++) {
        int hi = hexval(lines[1][i * 2]);
        int lo = hexval(lines[1][i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return VIRP_ERR_APPROVAL_BAD_SIGNATURE;
        sig[i] = (uint8_t)((hi << 4) | lo);
    }

    chain_hash[0] = '\0';
    if (lines[2][0] && strcmp(lines[2], "-") != 0)
        snprintf(chain_hash, 65, "%s", lines[2]);
    return VIRP_OK;
}

/*
 * Load + parse the persisted approval record into *out — the single
 * parser for the on-disk record, shared by verify_consume and the
 * submit already-exists path so "who is the approver of record" has
 * exactly one answer. Structural validation only (shape, proposal-id
 * echo, hex fields); enrollment, signature, command/device binding and
 * TTL checks remain the caller's job.
 */
static virp_error_t approval_record_load(const char *dir,
                                         const char *proposal_id,
                                         virp_approval_rec_t *out)
{
    char body[2048];
    uint8_t sig[VIRP_FED_SIG_SIZE];
    char chain_hash[65];
    virp_error_t err = approval_load_raw(dir, proposal_id, body, sizeof(body),
                                         sig, chain_hash);
    if (err != VIRP_OK) return err;

    /* Parse the binding (untrusted until the caller's signature check,
     * which covers the whole body — a tampered field changes the signed
     * bytes). */
    cJSON *o = cJSON_Parse(body);
    if (!o || !cJSON_IsObject(o)) {
        if (o) cJSON_Delete(o);
        return VIRP_ERR_APPROVAL_BAD_SIGNATURE;
    }
    memset(out, 0, sizeof(*out));
    uint64_t nid = 0, at = 0, ttl = 0;
    bool ok =
        jget_str(o, "proposal_id", out->proposal_id, sizeof(out->proposal_id)) &&
        jget_str(o, "command_hash", out->command_hash, sizeof(out->command_hash)) &&
        jget_str(o, "device", out->device, sizeof(out->device)) &&
        jget_u64(o, "device_node_id", &nid) &&
        jget_u64str(o, "approved_at_ns", &at) &&
        jget_u64(o, "ttl_seconds", &ttl) &&
        jget_str(o, "approver_key_id", out->approver_key_id,
                 sizeof(out->approver_key_id));
    jget_str(o, "operator", out->operator, sizeof(out->operator));
    cJSON_Delete(o);
    if (!ok || nid > UINT32_MAX || ttl > 86400 ||
        strcmp(out->proposal_id, proposal_id) != 0 ||
        !hex64_valid(out->command_hash))
        return VIRP_ERR_APPROVAL_BAD_SIGNATURE;
    out->device_node_id = (uint32_t)nid;
    out->approved_at_ns = at;
    out->ttl_seconds = (uint32_t)ttl;
    memcpy(out->sig, sig, sizeof(out->sig));
    snprintf(out->chain_entry_hash, sizeof(out->chain_entry_hash), "%s",
             chain_hash);
    return VIRP_OK;
}

/*
 * Single-use consume. consumed.list is the durable replay store for
 * approvals — same pattern as the observation seqstore: temp-write,
 * fsync, rename; a failed persist means the approval is NOT consumed
 * in memory and NOT accepted (fail closed). The file is re-read on
 * every call, so consumed state survives daemon restarts by
 * construction.
 */
static virp_error_t consume_once(const char *dir, const char *proposal_id)
{
    char path[VIRP_APPROVAL_DIR_MAX + 32];
    snprintf(path, sizeof(path), "%s/consumed.list", dir);

    pthread_mutex_lock(&consume_mu);

    char existing[65536];
    existing[0] = '\0';
    FILE *f = fopen(path, "r");
    if (f) {
        size_t got = fread(existing, 1, sizeof(existing) - 1, f);
        fclose(f);
        existing[got] = '\0';
        /* An over-full store would silently truncate below — refuse. */
        if (got == sizeof(existing) - 1) {
            pthread_mutex_unlock(&consume_mu);
            return VIRP_ERR_CHAIN_DB;
        }
    }

    /* Already consumed? Exact line match. */
    const char *p = existing;
    size_t idlen = strlen(proposal_id);
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t linelen = nl ? (size_t)(nl - p) : strlen(p);
        if (linelen == idlen && strncmp(p, proposal_id, idlen) == 0) {
            pthread_mutex_unlock(&consume_mu);
            return VIRP_ERR_APPROVAL_REUSED;
        }
        if (!nl) break;
        p = nl + 1;
    }

    char updated[65536 + 64];
    snprintf(updated, sizeof(updated), "%s%s\n", existing, proposal_id);
    virp_error_t err = write_file_durable(path, 0600, updated);

    pthread_mutex_unlock(&consume_mu);
    return err;   /* persist failure → non-OK → caller rejects (fail closed) */
}

virp_error_t virp_approval_verify_consume(const char *dir,
                                          const virp_approver_registry_t *reg,
                                          const char *proposal_id,
                                          const char *device,
                                          uint32_t device_node_id,
                                          const char *command,
                                          const char *typed_profile,
                                          uint64_t now_ns,
                                          virp_approval_rec_t *out)
{
    if (!dir || !reg || !device || !command || !out)
        return VIRP_ERR_NULL_PTR;
    if (!proposal_id_valid(proposal_id))
        return VIRP_ERR_APPROVAL_NOT_FOUND;

    virp_error_t err = approval_record_load(dir, proposal_id, out);
    if (err != VIRP_OK) return err;

    /* 1. The signing key must be enrolled (and enabled). Distinguish
     * unenrolled from disabled so the rejection names the true cause. */
    const virp_approver_t *ent =
        virp_approver_registry_find_any(reg, out->approver_key_id);
    if (!ent)
        return VIRP_ERR_APPROVAL_KEY_UNENROLLED;
    if (!ent->enabled)
        return VIRP_ERR_APPROVAL_KEY_DISABLED;

    /* 2. Signature over the canonical payload reconstructed from the
     * record's own fields — a tampered field (e.g. one bit of
     * command_hash) changes the canonical bytes and fails the check. */
    uint8_t canon[VIRP_APPROVAL_CANON_SIZE];
    if (virp_approval_build_canonical(out->proposal_id, out->command_hash,
                                      out->device_node_id, out->approved_at_ns,
                                      out->ttl_seconds, canon) != VIRP_OK)
        return VIRP_ERR_APPROVAL_BAD_SIGNATURE;
    if (virp_approver_verify(ent, canon, sizeof(canon),
                             out->sig, sizeof(out->sig)) != VIRP_OK)
        return VIRP_ERR_APPROVAL_BAD_SIGNATURE;

    /* 3. Command binding. */
    char cmd_hash[65];
    if (command_hash_hex(command, typed_profile, cmd_hash) != VIRP_OK ||
        strcmp(cmd_hash, out->command_hash) != 0)
        return VIRP_ERR_APPROVAL_HASH_MISMATCH;

    /* 4. Device binding. */
    if (strcmp(device, out->device) != 0 ||
        device_node_id != out->device_node_id)
        return VIRP_ERR_APPROVAL_DEVICE_MISMATCH;

    /* 5. TTL. A future-dated approval (beyond 60s clock skew) is treated
     * as expired rather than granted a longer window. */
    if (now_ns == 0)
        now_ns = now_realtime_ns();
    uint64_t expiry = out->approved_at_ns +
                      (uint64_t)out->ttl_seconds * 1000000000ULL;
    if (now_ns > expiry ||
        out->approved_at_ns > now_ns + 60ULL * 1000000000ULL)
        return VIRP_ERR_APPROVAL_EXPIRED;

    /* 6. Single-use consume (durable; persist failure fails closed). */
    VIRP_FI("pre_consume");
    {
        virp_error_t _c = consume_once(dir, proposal_id);
        if (_c == VIRP_OK) VIRP_FI("post_consume");
        return _c;
    }
}
