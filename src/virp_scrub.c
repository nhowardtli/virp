/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Scrub-at-capture — secret-shaped content redaction for observation bodies
 *
 * Design contract and ruleset: include/virp_scrub.h and SCRUB-DESIGN.md.
 * Shape: a pure line-oriented scanner in the mold of cisco_scrub_config
 * (src/drivers/driver_cisco.c) — exact-token matching so non-secret
 * lines pass byte-identically, redaction replaces the secret span with
 * a visible [REDACTED: <reason>] marker, and every failure path is
 * fail-closed (the caller wrapper substitutes the whole body).
 *
 * THE HONESTY LIMIT: known-shapes only. An unlabeled plaintext password
 * or a bare hex token is NOT caught. See the header comment in
 * virp_scrub.h before describing this feature anywhere.
 */

#define _DEFAULT_SOURCE

#include "virp_scrub.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* TEST-ONLY forced failure (G3). Fails CLOSED only — see header. */
static bool scrub_force_error = false;
void virp_scrub_test_force_error(bool on) { scrub_force_error = on; }

/* =========================================================================
 * Small helpers — token matching is exact and case-insensitive, so
 * `service password-encryption` (token "password-encryption") never
 * matches the token "password".
 * ========================================================================= */

static bool ci_eq(const char *tok, size_t len, const char *word)
{
    if (strlen(word) != len) return false;
    for (size_t i = 0; i < len; i++)
        if (tolower((unsigned char)tok[i]) != tolower((unsigned char)word[i]))
            return false;
    return true;
}

static bool ci_ends_with(const char *tok, size_t len, const char *suffix)
{
    size_t sl = strlen(suffix);
    if (len < sl) return false;
    return ci_eq(tok + (len - sl), sl, suffix);
}

/* Append [src, src+n) to out; false on overflow (fail-closed trigger). */
static bool emit(char *out, size_t cap, size_t *pos,
                 const char *src, size_t n)
{
    if (*pos + n >= cap) return false;
    memcpy(out + *pos, src, n);
    *pos += n;
    return true;
}

static bool emit_marker(char *out, size_t cap, size_t *pos,
                        const char *reason)
{
    return emit(out, cap, pos, VIRP_SCRUB_MARK_PREFIX,
                strlen(VIRP_SCRUB_MARK_PREFIX)) &&
           emit(out, cap, pos, reason, strlen(reason)) &&
           emit(out, cap, pos, VIRP_SCRUB_MARK_SUFFIX,
                strlen(VIRP_SCRUB_MARK_SUFFIX));
}

/* Token walk state over one line (terminator excluded). */
typedef struct {
    const char *line;
    size_t      len;
    size_t      pos;        /* scan cursor */
} tokwalk_t;

/* Next token: [*tok, *tok + *tlen), advancing past leading blanks.
 * Returns false at end of line. */
static bool next_tok(tokwalk_t *w, const char **tok, size_t *tlen)
{
    while (w->pos < w->len &&
           (w->line[w->pos] == ' ' || w->line[w->pos] == '\t'))
        w->pos++;
    if (w->pos >= w->len) return false;
    size_t start = w->pos;
    while (w->pos < w->len &&
           w->line[w->pos] != ' ' && w->line[w->pos] != '\t')
        w->pos++;
    *tok = w->line + start;
    *tlen = w->pos - start;
    return true;
}

static bool tok_is_numeric(const char *tok, size_t len)
{
    if (len == 0) return false;
    for (size_t i = 0; i < len; i++)
        if (!isdigit((unsigned char)tok[i])) return false;
    return true;
}

/* Idempotence guard: the value position already holds a redaction
 * marker — the line was scrubbed before (or upstream, by a driver
 * scrub). Re-redacting it would corrupt the marker on every pass. */
static bool value_is_marker(const char *p, const char *line, size_t len)
{
    size_t remaining = len - (size_t)(p - line);
    size_t ml = strlen(VIRP_SCRUB_MARK_PREFIX);
    return remaining >= ml && memcmp(p, VIRP_SCRUB_MARK_PREFIX, ml) == 0;
}

/* =========================================================================
 * Per-line rules
 *
 * Each rule, when it fires, emits the KEPT prefix of the line plus a
 * marker (and for token-replacement rules, the kept remainder), so the
 * line stays recognizable as "a password line, redacted". First match
 * wins; a clean line is emitted verbatim.
 * ========================================================================= */

/* PEM block detection. Any "-----BEGIN <anything> PRIVATE KEY-----"
 * opens a block (covers RSA/EC/DSA/OPENSSH/ENCRYPTED variants). */
static bool line_opens_pem(const char *line, size_t len)
{
    return memmem(line, len, "-----BEGIN ", 11) != NULL &&
           memmem(line, len, "PRIVATE KEY-----", 16) != NULL;
}

static bool line_closes_pem(const char *line, size_t len)
{
    return memmem(line, len, "-----END", 8) != NULL &&
           memmem(line, len, "PRIVATE KEY-----", 16) != NULL;
}

/*
 * `snmp-server community <string> ...` — replace the community token,
 * keep the rest of the line (RO/RW/view/ACL stay diagnostic).
 */
static int rule_snmp_community(const char *line, size_t len,
                               char *out, size_t cap, size_t *pos)
{
    tokwalk_t w = { line, len, 0 };
    const char *t1, *t2, *t3;
    size_t l1, l2, l3;

    if (!next_tok(&w, &t1, &l1) || !ci_eq(t1, l1, "snmp-server")) return 0;
    if (!next_tok(&w, &t2, &l2) || !ci_eq(t2, l2, "community"))   return 0;
    if (!next_tok(&w, &t3, &l3))                                  return 0;
    if (value_is_marker(t3, line, len))                           return 0;

    /* keep through "community ", marker for the token, keep the rest */
    if (!emit(out, cap, pos, line, (size_t)(t3 - line)) ||
        !emit_marker(out, cap, pos, "snmp-community") ||
        !emit(out, cap, pos, t3 + l3, len - (size_t)(t3 + l3 - line)))
        return -1;
    return 1;
}

/*
 * `crypto ... key [<enc#>] <SECRET> [address|hostname ...]` — the
 * ISAKMP pre-shared-key shape. Redact only the key token (skipping an
 * optional numeric encryption-type token) so the peer address stays
 * visible.
 */
static int rule_crypto_key(const char *line, size_t len,
                           char *out, size_t cap, size_t *pos)
{
    tokwalk_t w = { line, len, 0 };
    const char *t; size_t tl;

    if (!next_tok(&w, &t, &tl) || !ci_eq(t, tl, "crypto")) return 0;

    while (next_tok(&w, &t, &tl)) {
        if (!ci_eq(t, tl, "key")) continue;

        const char *v; size_t vl;
        if (!next_tok(&w, &v, &vl)) return 0;      /* bare "key" — no value */
        if (tok_is_numeric(v, vl)) {               /* encryption-type digit */
            if (!next_tok(&w, &v, &vl)) return 0;
        }
        if (value_is_marker(v, line, len)) return 0;   /* already scrubbed */
        if (!emit(out, cap, pos, line, (size_t)(v - line)) ||
            !emit_marker(out, cap, pos, "pre-shared-key") ||
            !emit(out, cap, pos, v + vl, len - (size_t)(v + vl - line)))
            return -1;
        return 1;
    }
    return 0;
}

/*
 * First-token `key <string>` — the tacacs/radius server-block and
 * key-chain shape. Redacted UNLESS the remainder is purely numeric
 * (`key 1` — a key-chain index) or the next token is `chain`
 * (`key chain NAME` — a block header). Same exceptions as the cisco
 * driver scrub, for the same reason.
 */
static int rule_leading_key(const char *line, size_t len,
                            char *out, size_t cap, size_t *pos)
{
    tokwalk_t w = { line, len, 0 };
    const char *t, *v; size_t tl, vl;

    if (!next_tok(&w, &t, &tl) || !ci_eq(t, tl, "key")) return 0;
    if (!next_tok(&w, &v, &vl)) return 0;              /* bare "key" */
    if (ci_eq(v, vl, "chain")) return 0;               /* block header */
    if (tok_is_numeric(v, vl)) {
        const char *r; size_t rl;                      /* `key 1` alone? */
        if (!next_tok(&w, &r, &rl)) return 0;          /* index — keep */
    }
    if (value_is_marker(v, line, len)) return 0;       /* already scrubbed */
    if (!emit(out, cap, pos, line, (size_t)(v - line)) ||
        !emit_marker(out, cap, pos, "key"))
        return -1;
    return 1;
}

/*
 * Keyword-token rules: an exact secret-bearing token redacts everything
 * after it (over-redaction is the fail-closed direction; the kept
 * prefix keeps the line recognizable). Also handles the generic
 * labeled form `<label>[:=] <value>` where the label token equals or
 * ends in a secret keyword.
 *
 * Returns the reason string when the token at [tok, tok+tlen) (with
 * prev_tok context) is a redaction trigger, NULL otherwise.
 */
static const char *keyword_reason(const char *tok, size_t tlen,
                                  const char *prev, size_t plen)
{
    /* strip ONE trailing ':' or '=' so `password:` / `secret=` match */
    if (tlen > 1 && (tok[tlen - 1] == ':' || tok[tlen - 1] == '='))
        tlen--;

    bool after_enable = prev && ci_eq(prev, plen, "enable");

    if (ci_eq(tok, tlen, "password") || ci_eq(tok, tlen, "passwd"))
        return after_enable ? "enable-password" : "password";
    if (ci_eq(tok, tlen, "secret"))
        return after_enable ? "enable-secret" : "secret";
    if (ci_eq(tok, tlen, "pre-shared-key")) return "pre-shared-key";
    if (ci_eq(tok, tlen, "wpa-psk"))        return "wpa-psk";
    if (ci_eq(tok, tlen, "psk"))            return "psk";
    if (ci_eq(tok, tlen, "key-string"))     return "key-string";
    return NULL;
}

/* Labeled-secret suffix match on the LABEL part of a token (the part
 * before any ':'/'=' — computed by the caller): PVE_API_TOKEN=,
 * admin_password:, X-Api-Key= … . The [:=] separator is required, so
 * prose containing "token" is untouched. */
static const char *label_reason(const char *label, size_t llen)
{
    if (ci_ends_with(label, llen, "password") ||
        ci_ends_with(label, llen, "passwd"))
        return "password";
    if (ci_ends_with(label, llen, "secret"))   return "secret";
    if (ci_ends_with(label, llen, "api-key") ||
        ci_ends_with(label, llen, "api_key") ||
        ci_ends_with(label, llen, "apikey"))   return "api-key";
    if (ci_ends_with(label, llen, "token"))    return "token";
    if (ci_ends_with(label, llen, "psk"))      return "psk";
    return NULL;
}

/*
 * Scrub one line (terminator excluded). Returns 1 if a redaction was
 * emitted, 0 if the line was emitted verbatim, -1 on overflow.
 */
static int scrub_line(const char *line, size_t len,
                      char *out, size_t cap, size_t *pos)
{
    int r;

    if ((r = rule_snmp_community(line, len, out, cap, pos)) != 0) return r;
    if ((r = rule_crypto_key(line, len, out, cap, pos)) != 0)     return r;
    if ((r = rule_leading_key(line, len, out, cap, pos)) != 0)    return r;

    /* token sweep: exact keywords, then labeled suffix forms */
    tokwalk_t w = { line, len, 0 };
    const char *tok, *prev = NULL;
    size_t tlen, plen = 0;

    while (next_tok(&w, &tok, &tlen)) {
        const char *reason = keyword_reason(tok, tlen, prev, plen);
        if (reason) {
            /* idempotence: the value after the keyword is already a
             * redaction marker — leave the line exactly as it is. */
            size_t vstart = (size_t)(tok + tlen - line);
            while (vstart < len &&
                   (line[vstart] == ' ' || line[vstart] == '\t'))
                vstart++;
            if (vstart < len && value_is_marker(line + vstart, line, len)) {
                prev = tok; plen = tlen;
                continue;
            }
            /* keep through the keyword token (and its attached
             * separator, if any); everything after is the secret. */
            size_t keep = (size_t)(tok + tlen - line);
            if (!emit(out, cap, pos, line, keep) ||
                !emit(out, cap, pos, " ", 1) ||
                !emit_marker(out, cap, pos, reason))
                return -1;
            return 1;
        }

        /* labeled form: split the token at its first ':' or '=' —
         * `PVE_API_TOKEN=sk-…` is one whitespace token, so the label
         * is the part before the separator. */
        const char *sep = NULL;
        for (size_t k = 1; k < tlen; k++) {
            if (tok[k] == ':' || tok[k] == '=') { sep = tok + k; break; }
        }
        size_t llen = sep ? (size_t)(sep - tok) : tlen;
        reason = label_reason(tok, llen);
        if (reason) {
            if (sep && sep + 1 < tok + tlen) {
                /* idempotence: attached value is already a marker */
                if (value_is_marker(sep + 1, line, len)) {
                    prev = tok; plen = tlen;
                    continue;
                }
                /* LABEL=value in one token: keep label + separator,
                 * marker for the attached value, keep the rest. */
                if (!emit(out, cap, pos, line, (size_t)(sep + 1 - line)) ||
                    !emit_marker(out, cap, pos, reason) ||
                    !emit(out, cap, pos, tok + tlen,
                          len - (size_t)(tok + tlen - line)))
                    return -1;
                return 1;
            }
            /* Separator trailing (`LABEL= value`) or detached
             * (`LABEL = value` / `LABEL : value`): keep through the
             * separator, redact the remainder of the line. */
            size_t after = (size_t)(tok + tlen - line);
            if (!sep) {
                size_t save = after;
                while (after < len &&
                       (line[after] == ' ' || line[after] == '\t'))
                    after++;
                if (after < len &&
                    (line[after] == ':' || line[after] == '=')) {
                    after++;                     /* the ':'/'=' itself */
                } else {
                    /* no separator at all — not the labeled form;
                     * plain prose containing the word stays intact. */
                    after = save;
                    prev = tok; plen = tlen;
                    continue;
                }
            }
            size_t vstart = after;
            while (vstart < len &&
                   (line[vstart] == ' ' || line[vstart] == '\t'))
                vstart++;
            if (vstart < len && value_is_marker(line + vstart, line, len)) {
                prev = tok; plen = tlen;
                continue;
            }
            if (!emit(out, cap, pos, line, after) ||
                !emit(out, cap, pos, " ", 1) ||
                !emit_marker(out, cap, pos, reason))
                return -1;
            return 1;
        }

        prev = tok; plen = tlen;
    }

    /* clean line — verbatim */
    return emit(out, cap, pos, line, len) ? 0 : -1;
}

/* =========================================================================
 * Public scanner
 * ========================================================================= */

virp_error_t virp_scrub_body(const char *in, size_t in_len,
                             char *out, size_t out_cap,
                             size_t *out_len,
                             unsigned *redactions)
{
    if (!in || !out || !out_len || !redactions)
        return VIRP_ERR_NULL_PTR;

    *out_len = 0;
    *redactions = 0;

    if (scrub_force_error)
        return VIRP_ERR_CRYPTO;      /* G3: prove the caller fails closed */

    size_t pos = 0;
    size_t i = 0;
    bool in_pem = false;

    while (i < in_len) {
        /* one line: [i, eol), terminator [eol, next) preserved as-is */
        size_t eol = i;
        while (eol < in_len && in[eol] != '\n') eol++;
        size_t line_end = eol;                   /* excl. \n */
        if (line_end > i && in[line_end - 1] == '\r') line_end--;
        const char *line = in + i;
        size_t len = line_end - i;
        const char *term = in + line_end;
        size_t term_len = (eol < in_len) ? (eol - line_end + 1)
                                         : (eol - line_end);

        if (in_pem) {
            if (line_closes_pem(line, len)) {
                in_pem = false;
                if (!emit(out, out_cap, &pos, line, len) ||
                    !emit(out, out_cap, &pos, term, term_len))
                    goto overflow;
            }
            /* interior lines: dropped — the block is already
             * represented by its single marker line. An unterminated
             * block therefore redacts through end of body, which is
             * the fail-closed direction. */
        } else if (line_opens_pem(line, len)) {
            in_pem = true;
            (*redactions)++;
            if (!emit(out, out_cap, &pos, line, len) ||
                !emit(out, out_cap, &pos, term, term_len) ||
                !emit_marker(out, out_cap, &pos, "private-key-block") ||
                !emit(out, out_cap, &pos, term, term_len))
                goto overflow;
        } else {
            int r = scrub_line(line, len, out, out_cap, &pos);
            if (r < 0) goto overflow;
            if (r > 0) (*redactions)++;
            if (!emit(out, out_cap, &pos, term, term_len))
                goto overflow;
        }

        i = eol + ((eol < in_len) ? 1 : 0);
    }

    *out_len = pos;
    return VIRP_OK;

overflow:
    *out_len = 0;
    return VIRP_ERR_BUFFER_TOO_SMALL;
}

/* =========================================================================
 * Fail-closed capture-path wrapper
 * ========================================================================= */

/* Replace a fixed buffer's content with the whole-field error marker. */
static void fail_closed(char *buf, size_t buf_size, size_t *len_io)
{
    /* VIRP_SCRUB_MARK_ERROR is 24 bytes with NUL; every field this
     * wrapper touches is far larger, but guard anyway. */
    size_t n = strlen(VIRP_SCRUB_MARK_ERROR);
    if (n >= buf_size) n = buf_size - 1;
    memcpy(buf, VIRP_SCRUB_MARK_ERROR, n);
    buf[n] = '\0';
    if (len_io) *len_io = n;
}

void virp_scrub_exec_result(virp_exec_result_t *result)
{
    if (!result) return;

    /* ── the observation body ─────────────────────────────────────── */
    if (result->output_len > 0) {
        size_t cap = sizeof(result->output);
        size_t out_len = 0;
        unsigned n = 0;
        char *scratch = malloc(cap);
        virp_error_t err = scratch
            ? virp_scrub_body(result->output, result->output_len,
                              scratch, cap, &out_len, &n)
            : VIRP_ERR_NULL_PTR;                 /* alloc failure — closed */

        if (err != VIRP_OK) {
            fail_closed(result->output, sizeof(result->output),
                        &result->output_len);
            fprintf(stderr, "[SCRUB] body scrub failed (%s) — body fully "
                    "redacted (fail-closed)\n", virp_error_str(err));
        } else if (n > 0) {
            memcpy(result->output, scratch, out_len);
            if (out_len < sizeof(result->output))
                result->output[out_len] = '\0';
            result->output_len = out_len;
            fprintf(stderr, "[SCRUB] %u redaction(s) applied to captured "
                    "body before signing\n", n);
        }
        /* n == 0: clean body — deliberately not copied back, so a clean
         * capture is bit-for-bit untouched (gate G1). */
        free(scratch);
    }

    /* ── driver error text (feeds signed ERROR observation bodies and
     *    the gate_execution "error" field; may quote device output) ── */
    if (result->error_msg[0] != '\0') {
        char scratch[sizeof(result->error_msg) + 128]; /* marker headroom */
        size_t out_len = 0;
        unsigned n = 0;
        virp_error_t err = virp_scrub_body(result->error_msg,
                                           strlen(result->error_msg),
                                           scratch, sizeof(scratch),
                                           &out_len, &n);
        if (err != VIRP_OK || out_len >= sizeof(result->error_msg)) {
            fail_closed(result->error_msg, sizeof(result->error_msg), NULL);
            fprintf(stderr, "[SCRUB] error_msg scrub failed — field fully "
                    "redacted (fail-closed)\n");
        } else if (n > 0) {
            memcpy(result->error_msg, scratch, out_len);
            result->error_msg[out_len] = '\0';
            fprintf(stderr, "[SCRUB] %u redaction(s) applied to driver "
                    "error text before signing\n", n);
        }
    }
}
