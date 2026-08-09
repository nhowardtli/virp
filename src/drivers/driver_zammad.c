/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Zammad Device Driver — REST API via libcurl + personal access token
 *
 * Third REST-based driver, structured after driver_librenms.c (static
 * token, no lifecycle) with driver_pbs.c's transport discipline (no
 * redirects, no path normalization, no way to weaken TLS).
 *
 * Handles:
 *   - Token auth: "Authorization: Token token=<value>" — Zammad's
 *     personal-access-token scheme, NOT Bearer. Never logged.
 *   - GET-only transport; non-GET method prefixes refused outright
 *   - HTTPS always, verification always on, no config knob to disable
 *   - Command routing table for trust tier classification
 *
 * Design mirrors the other REST drivers:
 *   - The "command" parameter to execute() is a Zammad API path.
 *   - One CURL easy handle per connection, reused across requests.
 *   - Fixed buffers only; response lands in virp_exec_result_t.
 *
 * Credential path (unchanged from every other device): the token lives
 * in /etc/virp/autopilot.env (0600 root), is substituted into
 * /run/virp/devices.json by deploy/render-devices.sh at daemon start,
 * and reaches this driver only as device.api_token. It is never
 * written to a persistent file and never reaches a log line: the one
 * place it is formatted is the stack header buffer in zm_get(), which
 * is OPENSSL_cleanse()d before that function returns, and the copy in
 * conn->device is cleansed at disconnect.
 *
 * Build:  make ZAMMAD=1
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "virp_driver.h"
#include "virp_driver_zammad.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <curl/curl.h>
#include <openssl/crypto.h>

/* =========================================================================
 * Command Routing — the autopilot GREEN read set, nothing else
 *
 * Same discipline as the Wazuh and LibreNMS tables, tightened in two
 * places where those two are loose:
 *
 *   1. The query string is CLASSIFIED, not stripped. Both older REST
 *      drivers cut the path at '?' and match only what precedes it, so
 *      every parameter a caller invents rides along unclassified.
 *      Here the query is part of what is being judged: only "page" and
 *      "per_page" exist, only digit values exist, and everything else
 *      is RED.
 *
 *   2. Nothing is prefix-matched. The recorded gap in the Wazuh driver
 *      was longest-prefix matching, which let "/agents_evil" and
 *      "/agents/001/restart" inherit the GREEN "/agents" row. The two
 *      rows here that end in a variable <id> are not prefixes in that
 *      sense either: the bytes after the base must be a digit run all
 *      the way to the end of the path, so "/api/v1/tickets/1/merge"
 *      and "/api/v1/tickets_evil" both fall through to RED.
 *
 * No YELLOW rows, no BLACK rows, so every RED stays approvable through
 * propose/approve/apply.
 * ========================================================================= */

/* Fixed GREEN paths — byte-exact, no wildcards. */
static const char *const ZM_GREEN_EXACT[] = {
    ZM_API_PREFIX "/tickets",         /* ticket list          */
    ZM_API_PREFIX "/ticket_states",   /* state catalogue      */
    ZM_API_PREFIX "/groups",          /* group catalogue      */
};

/*
 * GREEN paths that end in a numeric object id. The base includes its
 * trailing slash, and the ENTIRE remainder must be digits — see
 * zm_route_path(); this is an anchored full-path rule, not a prefix.
 */
static const char *const ZM_GREEN_ID_BASE[] = {
    ZM_API_PREFIX "/tickets/",                    /* ticket detail   */
    ZM_API_PREFIX "/ticket_articles/by_ticket/",  /* ticket articles */
};

/*
 * A digit run: 1..ZM_DIGITS_MAX ASCII digits, nothing else. No sign,
 * no whitespace, no '+', no separators, no percent-encoding, no
 * locale-dependent isdigit() (which admits other bytes under some
 * locales and takes a signed char as a negative index).
 *
 * The UPPER bound is load-bearing, not cosmetic: it is what makes a
 * GREEN path length-bounded, which is what makes it un-truncatable in
 * the URL buffer. See the invariant note on ZM_DIGITS_MAX in
 * virp_driver_zammad.h before changing or dropping it.
 */
static bool zm_digits(const char *s, size_t len)
{
    if (len == 0 || len > ZM_DIGITS_MAX) return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < '0' || c > '9') return false;
    }
    return true;
}

/*
 * Query-string policy: only "page" and "per_page", each at most once,
 * each with a digits-only value.
 *
 * `q` points just past '?', `len` runs to the end of the string.
 * RED (false) for: a bare "?", an empty pair ("&&", a trailing "&"), a
 * pair with no '=', an unlisted name, an empty or non-numeric value, a
 * repeated name.
 *
 * On repeats, see the DO-NOT-RELAX note at the seen_page/seen_per_page
 * check below. It is not a strictness preference; it is the property
 * the protocol rests on.
 */
static bool zm_query_ok(const char *q, size_t len)
{
    if (len == 0) return false;                  /* path ended in a bare '?' */

    bool seen_page = false, seen_per_page = false;
    size_t i = 0;

    while (i < len) {
        size_t start = i;
        while (i < len && q[i] != '&') i++;
        size_t pair_len = i - start;

        /* Step over the separator. A '&' with nothing after it ends the
         * loop, so the empty pair it introduces has to be caught here —
         * checking pair_len alone lets "page=1&" through. */
        if (i < len) {
            i++;
            if (i == len) return false;          /* trailing '&' */
        }

        if (pair_len == 0) return false;         /* "", "&page=1", "a&&b" */

        const char *pair = q + start;
        const char *eq = memchr(pair, '=', pair_len);
        if (!eq) return false;                   /* bare flag, e.g. "?expand" */

        size_t name_len = (size_t)(eq - pair);
        size_t val_len  = pair_len - name_len - 1;
        const char *val = eq + 1;

        /*
         * DO NOT RELAX: a repeated parameter is RED, permanently.
         *
         * "?page=1&page=2" names two values for one parameter. Nothing
         * in the bytes says which one wins — precedence is the private
         * choice of whatever parses the query on the far side (Rack
         * takes the last, some stacks take the first, some build an
         * array), and it can change under us with a server upgrade we
         * neither control nor observe.
         *
         * VIRP's whole claim is that the signed bytes determine what
         * the device was asked to do. Accepting a repeat would mean the
         * gate signs a request whose effect is decided elsewhere, by a
         * rule that is not in the observation and not in the chain. The
         * signature would still verify; it would simply no longer mean
         * anything. That is a strictly worse failure than a refusal,
         * because it is invisible.
         *
         * It looks like harmless pedantry — both names are listed, both
         * values are digits — which is exactly why it needs this note
         * rather than a one-line comment. The cost of refusing is that
         * a caller emitting a duplicate gets a signed rejection and has
         * to send one value. That is the intended cost.
         *
         * This is not a Zammad-local opinion. driver_pbs.c refuses a
         * repeated typed-op key for the same reason, in its own words:
         * REASON_DUP_PARAM, "a key may appear at most once, so the
         * canonical encoding of a request is unique" — alongside
         * REASON_UNSORTED, "byte identity and semantic identity
         * coincide". The nightly corpus replay asserts it against the
         * live gate ("pbs op=backup.snapshots.list store=a store=b" →
         * RED). Relaxing it here would put two drivers in the same tree
         * on opposite sides of the same question.
         */
        if (name_len == 4 && memcmp(pair, "page", 4) == 0) {
            if (seen_page) return false;
            seen_page = true;
        } else if (name_len == 8 && memcmp(pair, "per_page", 8) == 0) {
            if (seen_per_page) return false;
            seen_per_page = true;
        } else {
            return false;                        /* unlisted parameter name */
        }

        /* A second '=' lands inside val and fails the digit test, which
         * is the intended answer: "page=1=2" is not a number. */
        if (!zm_digits(val, val_len)) return false;
    }

    return true;
}

virp_trust_tier_t zm_route_path(const char *path)
{
    if (!path) return VIRP_TIER_RED;                     /* fail closed */

    /*
     * The length cap is enforced HERE as well as in zm_get(), and both
     * are required: the transport check alone would let an over-long
     * path classify GREEN and be signed, only to be refused at
     * dispatch — a gate blessing a request the driver cannot make.
     * See the invariant note on ZM_PATH_MAX in virp_driver_zammad.h.
     */
    size_t total = strlen(path);
    if (total == 0 || total > ZM_PATH_MAX) return VIRP_TIER_RED;

    /* Split off the query string and classify it. Unlike the Wazuh and
     * LibreNMS drivers, the query is NOT ignored. */
    size_t plen = total;
    const char *qmark = memchr(path, '?', total);
    if (qmark) {
        plen = (size_t)(qmark - path);
        if (!zm_query_ok(qmark + 1, total - plen - 1))
            return VIRP_TIER_RED;
    }

    /* Byte-exact rows. Case variants are unlisted spellings, not the
     * listed row: the bytes that were classified are the bytes that get
     * requested, so a case-folded compare here would classify one
     * string and dispatch another. */
    for (size_t i = 0;
         i < sizeof(ZM_GREEN_EXACT) / sizeof(ZM_GREEN_EXACT[0]); i++) {
        size_t glen = strlen(ZM_GREEN_EXACT[i]);
        if (glen == plen && memcmp(path, ZM_GREEN_EXACT[i], glen) == 0)
            return VIRP_TIER_GREEN;
    }

    /* Rows ending in <id>: base must match byte-exactly AND the whole
     * remainder must be a digit run. Anchored at both ends — there is
     * no trailing context a caller can append. */
    for (size_t i = 0;
         i < sizeof(ZM_GREEN_ID_BASE) / sizeof(ZM_GREEN_ID_BASE[0]); i++) {
        size_t blen = strlen(ZM_GREEN_ID_BASE[i]);
        if (plen > blen &&
            memcmp(path, ZM_GREEN_ID_BASE[i], blen) == 0 &&
            zm_digits(path + blen, plen - blen))
            return VIRP_TIER_GREEN;
    }

    return VIRP_TIER_RED;                                /* RED by absence */
}

/* =========================================================================
 * TYPED WRITE OPERATION — exactly one row
 *
 * See the block comment in virp_driver_zammad.h for the grammar and the
 * body policy. The short version: method and URL come from this table,
 * never from input, and the JSON template's only substitutions are a
 * digits-only id and a body whose charset cannot carry JSON syntax.
 * ========================================================================= */

static const char REASON_OP_GRAMMAR[] =
    "typed-operation grammar violation — the exact form is "
    "`zammad op=<operation.id> id=<digits> body=\"<text>\"`, one space "
    "between tokens, parameters in the order the operation declares";
static const char REASON_OP_UNKNOWN[] =
    "unknown operation — this driver declares exactly one write, "
    "ticket.article.create; every other operation is RED by absence";
static const char REASON_OP_ID[] =
    "ticket id must be 1..20 ASCII digits with no leading zero — a "
    "leading zero would give one ticket two encodings and would not be "
    "a valid JSON number";
static const char REASON_BODY_CHARSET[] =
    "body contains a byte outside the permitted set — printable ASCII "
    "except \" \\ < >, no control bytes, no newlines, no non-ASCII";
static const char REASON_BODY_LEN[] =
    "decoded body exceeds the 512-byte cap";
static const char REASON_BODY_ESCAPE[] =
    "malformed percent-escape — an escape is %XX with two UPPERCASE hex "
    "digits";
static const char REASON_BODY_NONCANON[] =
    "non-canonical body encoding — exactly the six ingress-unsafe bytes "
    "(; | & ` $ %) are escaped and every other byte is literal, so each "
    "body has exactly one legal encoding";
static const char REASON_BODY_QUOTES[] =
    "body must be wrapped in double quotes and the closing quote must "
    "be the last byte of the command";
static const char REASON_OP_NOT_ON_DEVICE[] =
    "this device does not permit this write operation — write_ops_allow "
    "does not name it (the read-only Zammad entry names nothing)";

static const char *const ZM_PARAMS_ARTICLE[] = { "id", "body", NULL };

static const zm_op_t ZM_OPS[] = {
    {
        /*
         * The ONLY write. type/internal/content_type are part of the
         * OPERATION, not caller parameters — the same reasoning as the
         * PBS verify typefilter. Making any of them a parameter would
         * let one approved op id reach a different effect: a
         * customer-visible reply instead of an internal note, or an
         * HTML article instead of plain text. A customer-visible reply
         * is a DIFFERENT operation and would need its own row, its own
         * tier and its own review.
         */
        .id     = ZM_OP_ARTICLE_CREATE,
        .method = ZM_METHOD_POST,
        .path   = "/api/v1/ticket_articles",
        .params = ZM_PARAMS_ARTICLE,
        .tier   = VIRP_TIER_YELLOW,   /* explicit: a bounded write that
                                       * adds an internal note and changes
                                       * no ticket state. Above the GREEN
                                       * per-uid ceiling on purpose. */
    },
};

#define ZM_OPS_COUNT (sizeof(ZM_OPS) / sizeof(ZM_OPS[0]))

bool zm_method_is_allowed(int method, bool is_write_op)
{
    if (method == ZM_METHOD_GET) return true;
    /*
     * POST is reachable ONLY for the single write row. This is not a
     * general allowance: the transport still refuses every other non-GET
     * command before the connection is touched. Keeping it a predicate
     * means "no method but GET, except for that one row" is something a
     * test drives directly rather than something a reader reconstructs.
     */
    if (method == ZM_METHOD_POST && is_write_op) return true;
    return false;
}

int zm_op_table_validate(void)
{
    int bad = 0;
    for (size_t i = 0; i < ZM_OPS_COUNT; i++) {
        const zm_op_t *op = &ZM_OPS[i];
        if (!op->id || !op->path || !op->params) {
            fprintf(stderr, "[Zammad] op table row %zu is malformed\n", i);
            bad = 1; continue;
        }
        if (op->tier == VIRP_TIER_UNCLASSIFIED) {
            fprintf(stderr, "[Zammad] op row '%s' declares no tier — every "
                            "row must state one explicitly\n", op->id);
            bad = 1;
        }
        if (op->tier == VIRP_TIER_BLACK) {
            fprintf(stderr, "[Zammad] op row '%s' is BLACK — this table "
                            "carries no BLACK rows so every refusal stays "
                            "approvable\n", op->id);
            bad = 1;
        }
        /* Only the one declared write may name POST. A second POST row
         * added without review fails here, at startup, loudly. */
        if (op->method != ZM_METHOD_GET &&
            strcmp(op->id, ZM_OP_ARTICLE_CREATE) != 0) {
            fprintf(stderr, "[Zammad] op row '%s' declares a non-GET method "
                            "but is not the one reviewed write row\n", op->id);
            bad = 1;
        }
        if (!zm_method_is_allowed((int)op->method,
                                  strcmp(op->id, ZM_OP_ARTICLE_CREATE) == 0)) {
            fprintf(stderr, "[Zammad] op row '%s' declares an unusable "
                            "method\n", op->id);
            bad = 1;
        }
    }
    return bad ? -1 : 0;
}

const zm_op_t *zm_op_lookup(const char *id)
{
    if (!id) return NULL;
    for (size_t i = 0; i < ZM_OPS_COUNT; i++)
        if (strcmp(ZM_OPS[i].id, id) == 0)
            return &ZM_OPS[i];
    return NULL;
}

/*
 * The body byte set. See the BODY POLICY block in virp_driver_zammad.h
 * for why each exclusion is here; the two that carry the security
 * property are '"' and '\\'.
 *
 * NOTE this is the DRIVER's set, not the effective one. The daemon's
 * ingress separator policy (virp_command_check_separators) independently
 * refuses ; | & ` $( ${ in any command before this function is reached,
 * so the effective body charset is the intersection of the two. See the
 * INTERACTION note in virp_driver_zammad.h.
 *
 * With both excluded (and every control byte excluded), a body needs NO
 * JSON escaping, so zm_build_article_json() splices it in verbatim and
 * the bytes that were classified are byte-for-byte the bytes that go on
 * the wire. Admit either character and that identity is gone: the driver
 * would have to transform the body, and a reviewer approving the command
 * would be approving a pre-image of what actually lands in the ticket.
 */
/* Uppercase-only hex. Lowercase is refused so "%3b" and "%3B" cannot
 * both be legal encodings of the same byte. */
static int zm_hexval_upper(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool zm_must_escape(unsigned char c)
{
    /*
     * Exactly the bytes the daemon's ingress filter refuses, plus the
     * escape introducer itself. Kept in step with
     * virp_command_check_separators() by the intersection test suite,
     * which drives BOTH functions over the same bytes — if that filter
     * ever changes, the test fails rather than the encoding silently
     * becoming wrong.
     *
     * Note '$' is escaped unconditionally, though ingress only refuses
     * "$(" and "${". A per-byte rule is decidable without lookahead and
     * keeps the encoding canonical; a context-dependent one would make
     * "$x" literal and "$(" escaped, i.e. two rules for one byte.
     */
    return c == ';' || c == '|' || c == '&' || c == '`' ||
           c == '$' || c == '%';
}

int zm_decode_body(const char *enc, size_t enc_len,
                   char *out, size_t out_max, size_t *out_len,
                   const char **reason)
{
    if (reason) *reason = NULL;
    if (!enc || !out || out_max == 0) {
        if (reason) *reason = REASON_BODY_ESCAPE;
        return -1;
    }

    size_t o = 0;
    for (size_t i = 0; i < enc_len; i++) {
        unsigned char c = (unsigned char)enc[i];
        unsigned char decoded;

        if (c == '%') {
            /* "%XX", two UPPERCASE hex digits, nothing else. */
            if (i + 2 >= enc_len) {
                if (reason) *reason = REASON_BODY_ESCAPE;
                return -1;
            }
            int hi = zm_hexval_upper(enc[i + 1]);
            int lo = zm_hexval_upper(enc[i + 2]);
            if (hi < 0 || lo < 0) {
                if (reason) *reason = REASON_BODY_ESCAPE;
                return -1;
            }
            decoded = (unsigned char)((hi << 4) | lo);
            i += 2;

            /*
             * CANONICALITY, direction 1: only a byte that MUST be
             * escaped may appear escaped. "%41" for 'A' is refused, or
             * "A" and "%41" would be two signed strings with one
             * meaning and the signature would stop pinning the outcome.
             */
            if (!zm_must_escape(decoded)) {
                if (reason) *reason = REASON_BODY_NONCANON;
                return -1;
            }
        } else {
            /*
             * CANONICALITY, direction 2: a byte that must be escaped may
             * never appear literally. In production the daemon's ingress
             * filter would already have refused five of these six, but
             * this driver does not rely on another layer to enforce its
             * own encoding.
             */
            if (zm_must_escape(c)) {
                if (reason) *reason = REASON_BODY_NONCANON;
                return -1;
            }
            decoded = c;
        }

        /* The decoded byte faces the same charset either way: an escape
         * is a transport device, not a way past the body policy. "%0A"
         * is a newline and is refused exactly like a literal one. */
        if (!zm_is_body_char(decoded)) {
            if (reason) *reason = REASON_BODY_CHARSET;
            return -1;
        }

        /* Cap is on the DECODED length — what lands in the ticket. */
        if (o + 1 >= out_max || o >= ZM_BODY_MAX) {
            if (reason) *reason = REASON_BODY_LEN;
            return -1;
        }
        out[o++] = (char)decoded;
    }

    out[o] = '\0';
    if (out_len) *out_len = o;
    return 0;
}

bool zm_is_body_char(unsigned char c)
{
    if (c < 0x20 || c >= 0x7F) return false;   /* CR/LF/TAB/NUL, all UTF-8 */
    if (c == '"' || c == '\\') return false;   /* JSON syntax              */
    if (c == '<' || c == '>')  return false;   /* rendering, defence in depth */
    return true;
}

/*
 * Ticket id: 1..ZM_DIGITS_MAX digits, no leading zero unless the id is
 * exactly "0". Two reasons, and both matter:
 *   - canonical encoding: "007" and "7" name one ticket, so admitting
 *     both would give one request two signed forms.
 *   - JSON validity: the id is emitted as a NUMBER, and {"ticket_id":007}
 *     is not valid JSON. Rejecting the shape is better than quoting it
 *     and hoping the server coerces.
 */
static bool zm_is_ticket_id(const char *s, size_t len)
{
    if (!zm_digits(s, len)) return false;
    if (len > 1 && s[0] == '0') return false;
    return true;
}

bool zm_device_allows_op(const char *write_ops_allow, const char *op_id)
{
    /* Absent or empty means no writes. This is the DEFAULT for every
     * device that never names the field, which is what makes omitting
     * it safe — including on the read-only Zammad entry. */
    if (!write_ops_allow || !*write_ops_allow || !op_id || !*op_id)
        return false;

    size_t idlen = strlen(op_id);
    const char *p = write_ops_allow;
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t n = comma ? (size_t)(comma - p) : strlen(p);
        /* Whole-entry exact match. No trimming, no prefixes, no
         * wildcards: "ticket.article" must not reach
         * "ticket.article.create", and " ticket.article.create" with a
         * stray space is a misconfiguration the operator should see
         * rather than one the driver silently repairs. */
        if (n == idlen && memcmp(p, op_id, n) == 0)
            return true;
        if (!comma) break;
        p = comma + 1;
    }
    return false;
}

static const char ZM_OP_PREFIX[] = "zammad ";

int zm_parse_command(const char *command, zm_request_t *out,
                     const char **reason)
{
    if (reason) *reason = NULL;
    if (!command || !out) {
        if (reason) *reason = REASON_OP_GRAMMAR;
        return -1;
    }
    memset(out, 0, sizeof(*out));

    size_t len = strlen(command);
    if (len == 0 || len >= ZM_COMMAND_MAX) {
        if (reason) *reason = REASON_OP_GRAMMAR;
        return -1;
    }

    /*
     * Byte guards BEFORE tokenizing. Control bytes are refused across
     * the whole command, not only inside the body: a CR or LF anywhere
     * is a request-boundary smuggle, and the daemon's ingress separator
     * policy treats it the same way one layer up.
     *
     * Space runs are refused so there is exactly one spelling of the
     * token separator. The body is exempt from the space-run rule —
     * "a  b" is legitimate prose — so the scan stops at `body=`.
     */
    const char *body_kw = strstr(command, " body=\"");
    size_t guard_len = body_kw ? (size_t)(body_kw - command) : len;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)command[i];
        if (c < 0x20 || c == 0x7F) {
            if (reason) *reason = REASON_BODY_CHARSET;
            return -1;
        }
        if (i < guard_len && c == ' ' && i + 1 < len && command[i + 1] == ' ') {
            if (reason) *reason = REASON_OP_GRAMMAR;
            return -1;
        }
    }
    if (command[len - 1] == ' ') {
        if (reason) *reason = REASON_OP_GRAMMAR;
        return -1;
    }

    if (strncmp(command, ZM_OP_PREFIX, sizeof(ZM_OP_PREFIX) - 1) != 0) {
        if (reason) *reason = REASON_OP_GRAMMAR;
        return -1;
    }
    const char *p = command + sizeof(ZM_OP_PREFIX) - 1;

    /* op=<id> */
    static const char OP_KEY[] = "op=";
    if (strncmp(p, OP_KEY, sizeof(OP_KEY) - 1) != 0) {
        if (reason) *reason = REASON_OP_GRAMMAR;
        return -1;
    }
    p += sizeof(OP_KEY) - 1;

    char op_id[ZM_OP_ID_MAX];
    size_t n = 0;
    while (*p && *p != ' ') {
        if (n + 1 >= sizeof(op_id)) {
            if (reason) *reason = REASON_OP_GRAMMAR;
            return -1;
        }
        op_id[n++] = *p++;
    }
    op_id[n] = '\0';

    const zm_op_t *op = zm_op_lookup(op_id);
    if (!op) {
        if (reason) *reason = REASON_OP_UNKNOWN;
        return -1;
    }
    out->op = op;

    /*
     * Parameters, in the ORDER the row declares. Positional order is the
     * canonicalization here — see the header for why PBS's sort-by-key
     * rule does not carry over to keys named before "op".
     */
    for (size_t k = 0; op->params[k]; k++) {
        const char *key = op->params[k];
        size_t klen = strlen(key);

        if (*p != ' ') {                       /* missing parameter */
            if (reason) *reason = REASON_OP_GRAMMAR;
            return -1;
        }
        p++;

        if (strncmp(p, key, klen) != 0 || p[klen] != '=') {
            if (reason) *reason = REASON_OP_GRAMMAR;
            return -1;
        }
        p += klen + 1;

        if (strcmp(key, "id") == 0) {
            const char *start = p;
            while (*p && *p != ' ') p++;
            size_t vlen = (size_t)(p - start);
            if (!zm_is_ticket_id(start, vlen)) {
                if (reason) *reason = REASON_OP_ID;
                return -1;
            }
            memcpy(out->id, start, vlen);
            out->id[vlen] = '\0';
        } else if (strcmp(key, "body") == 0) {
            /*
             * Opening quote, then bytes, then a closing quote that MUST
             * be the final byte of the command. Because '"' is not a
             * permitted body byte, the first quote we meet IS the
             * closing one — there is exactly one parse and no escape
             * mechanism to reason about.
             */
            if (*p != '"') {
                if (reason) *reason = REASON_BODY_QUOTES;
                return -1;
            }
            p++;
            const char *enc = p;
            while (*p && *p != '"') p++;
            if (*p != '"' || p[1] != '\0') {
                if (reason) *reason = REASON_BODY_QUOTES;
                return -1;
            }
            size_t enc_len = (size_t)(p - enc);
            if (enc_len > ZM_BODY_ENC_MAX) {
                if (reason) *reason = REASON_BODY_LEN;
                return -1;
            }
            /*
             * The CLASSIFIER decodes. It has to: the cap is on the
             * decoded length and the charset applies to decoded bytes,
             * so neither can be judged from the encoded form alone. The
             * transport then decodes the same bytes with the same
             * function — one decoder, so what was classified is what is
             * posted.
             */
            if (zm_decode_body(enc, enc_len, out->body, sizeof(out->body),
                               &out->body_len, reason) != 0)
                return -1;
            if (out->body_len == 0) {   /* an empty note is not a note */
                if (reason) *reason = REASON_BODY_LEN;
                return -1;
            }
            p++;                               /* consume closing quote */
        } else {
            if (reason) *reason = REASON_OP_GRAMMAR;   /* unreachable */
            return -1;
        }
    }

    if (*p != '\0') {                          /* trailing tokens */
        if (reason) *reason = REASON_OP_GRAMMAR;
        return -1;
    }
    return 0;
}

int zm_build_article_json(const zm_request_t *req, char *out, size_t out_len)
{
    if (!req || !req->op || !out) return -1;

    /*
     * Static template, two substitutions. `id` is digits with no leading
     * zero, so it is a valid JSON number; `body` has already been
     * restricted to bytes that need no JSON escaping, so it is spliced
     * in VERBATIM. Nothing here transforms either value — that is what
     * makes the classified bytes and the transmitted bytes the same
     * bytes.
     *
     * type/internal/content_type are fixed: an internal plain-text note.
     * They are properties of the approved OPERATION, not caller input.
     */
    int w = snprintf(out, out_len,
                     "{\"ticket_id\":%s,"
                     "\"body\":\"%s\","
                     "\"type\":\"note\","
                     "\"internal\":true,"
                     "\"content_type\":\"text/plain\"}",
                     req->id, req->body);
    if (w < 0 || (size_t)w >= out_len) return -1;   /* fail closed */
    return 0;
}

/*
 * The one place a submitted command becomes a request path — used by
 * BOTH the gate hook and execute(), so the bytes that were classified
 * are provably the bytes that get requested. Returns NULL for a non-GET
 * method prefix or anything that is not a rooted path.
 *
 * "GET " is matched case-exactly, like every other row in this driver:
 * "get /api/v1/tickets" is an unlisted spelling and falls through RED.
 */
static const char *zm_command_path(const char *command)
{
    if (!command) return NULL;

    const char *p = command;
    while (*p == ' ') p++;
    if (strncmp(p, "GET ", 4) == 0) {
        p += 4;
        while (*p == ' ') p++;
    }
    if (p[0] != '/') return NULL;   /* non-GET method, or unrooted path */
    return p;
}

virp_trust_tier_t zammad_gate_classify(const char *command, const char **reason)
{
    if (reason) *reason = NULL;
    if (!command) return VIRP_TIER_RED;

    /*
     * Shape dispatch. The two grammars cannot collide: a typed operation
     * begins with the literal "zammad " and a read begins with '/' (after
     * an optional "GET "). Anything matching neither is RED.
     *
     * The typed-op branch is checked FIRST and by exact prefix, so a
     * read path can never be re-read as an operation or the reverse.
     */
    if (strncmp(command, ZM_OP_PREFIX, sizeof(ZM_OP_PREFIX) - 1) == 0) {
        zm_request_t req;
        const char *why = NULL;
        if (zm_parse_command(command, &req, &why) != 0) {
            if (reason) *reason = why;
            return VIRP_TIER_RED;
        }
        /*
         * The row's declared tier, not "parsed successfully, therefore
         * fine". YELLOW here is what keeps the write above uid 993's
         * GREEN ceiling — see the header.
         */
        return req.op->tier;
    }

    const char *path = zm_command_path(command);
    if (!path) return VIRP_TIER_RED;
    return zm_route_path(path);
}

virp_trust_tier_t zammad_gate_tier(const char *command)
{
    return zammad_gate_classify(command, NULL);
}

const char *zammad_gate_reason(const char *command)
{
    const char *reason = NULL;
    (void)zammad_gate_classify(command, &reason);
    return reason;
}

/* =========================================================================
 * Connection State
 * ========================================================================= */

struct virp_conn {
    virp_device_t       device;
    CURL               *curl;
    char                base_url[512];      /* https://host:port */
    bool                connected;
};

/* =========================================================================
 * CURL write callback — accumulate response into a fixed buffer
 * ========================================================================= */

typedef struct {
    char   *buf;
    size_t  buf_size;
    size_t  offset;
} zm_response_t;

static size_t zm_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    zm_response_t *resp = (zm_response_t *)userdata;
    size_t bytes = size * nmemb;
    size_t avail = resp->buf_size - resp->offset - 1;   /* reserve NUL */

    if (bytes > avail)
        bytes = avail;

    if (bytes > 0) {
        memcpy(resp->buf + resp->offset, ptr, bytes);
        resp->offset += bytes;
        resp->buf[resp->offset] = '\0';
    }

    return size * nmemb;   /* always report full consumption to curl */
}

/*
 * TLS is not configurable.
 *
 * The Wazuh driver has VIRP_WAZUH_INSECURE and the LibreNMS driver
 * picks plain http for any port that is not 443 — both are config
 * knobs whose value can mean "do not check". This driver has neither:
 * the scheme is always https, VERIFYPEER/VERIFYHOST are always on, and
 * there is no CA-bundle override, so the only trust anchors are the
 * host's CA store — where the Zammad certificate already lives.
 * Rotating to a certificate outside that store is therefore a host
 * trust-store change, which is the intended cost.
 */
static void zm_configure_tls(CURL *curl)
{
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
}

/*
 * One GET against the API. Internal transport helper shared by the
 * connect probe, execute, and health_check.
 *
 * `path` must already have passed zm_command_path(); it is sent
 * verbatim. The token goes into a stack header buffer and is cleansed
 * before return — it must never reach a log line, an error_msg, or an
 * observation payload.
 */
static virp_error_t zm_perform(struct virp_conn *conn, zm_method_t method,
                               const char *post_json, const char *path,
                               char *out, size_t out_len, long *http_code);

/*
 * One request against the API.
 *
 * `method` is the typed enum, and `post_json` is the exact body to send
 * for ZM_METHOD_POST (NULL for GET). `is_write_op` records whether the
 * caller has established that this is the single reviewed write row; it
 * is the ONLY thing that can unlock POST, and it is re-checked here
 * rather than trusted from the caller's control flow.
 */
static virp_error_t zm_request(struct virp_conn *conn, zm_method_t method,
                               bool is_write_op, const char *post_json,
                               const char *path,
                               char *out, size_t out_len, long *http_code)
{
    /*
     * Method whitelist at the transport, not only at the table. The
     * table says which method a row uses; this says which methods the
     * driver is willing to put on a socket at all. Both have to agree,
     * so a table row edited to POST without the corresponding review
     * still cannot issue one.
     */
    if (!zm_method_is_allowed((int)method, is_write_op)) {
        fprintf(stderr, "[Zammad] refusing method %d (write_op=%d) — the "
                        "transport issues GET, and POST only for the one "
                        "declared write operation\n",
                (int)method, (int)is_write_op);
        return ZM_ERR_METHOD;
    }
    if (method == ZM_METHOD_POST && !post_json) return ZM_ERR_METHOD;

    return zm_perform(conn, method, post_json, path, out, out_len, http_code);
}

static virp_error_t zm_perform(struct virp_conn *conn, zm_method_t method,
                               const char *post_json, const char *path,
                               char *out, size_t out_len, long *http_code)
{
    /*
     * The classifier caps a GREEN path at ZM_PATH_MAX, so a longer one
     * cannot have been approved as GREEN — but the transport refuses
     * independently rather than trusting that, and it checks the
     * snprintf return: a silently truncated URL is a request for a
     * DIFFERENT resource than the one that was classified.
     *
     * This is the second half of a two-sided invariant; the classifier
     * holds the other half. See the ZM_PATH_MAX note in
     * virp_driver_zammad.h for why neither side is redundant.
     */
    if (strlen(path) > ZM_PATH_MAX) {
        fprintf(stderr, "[Zammad] path exceeds %d bytes — refusing\n",
                ZM_PATH_MAX);
        return ZM_ERR_CURL_PERFORM;
    }

    char url[2048];
    int url_len = snprintf(url, sizeof(url), "%s%s", conn->base_url, path);
    if (url_len < 0 || (size_t)url_len >= sizeof(url)) {
        fprintf(stderr, "[Zammad] URL would truncate — refusing\n");
        return ZM_ERR_CURL_PERFORM;
    }

    /* Zammad personal access token — "Token token=<value>", not Bearer. */
    char auth_hdr[ZM_TOKEN_MAX + 32];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Token token=%s",
             conn->device.api_token);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_hdr);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    zm_response_t resp = { .buf = out, .buf_size = out_len, .offset = 0 };
    out[0] = '\0';

    curl_easy_reset(conn->curl);
    curl_easy_setopt(conn->curl, CURLOPT_URL, url);
    if (method == ZM_METHOD_POST) {
        /*
         * POSTFIELDSIZE is set explicitly from strlen rather than left
         * to libcurl's own strlen: the body is the approved bytes and
         * its length is part of what was approved, so the transport
         * states it instead of re-deriving it.
         */
        curl_easy_setopt(conn->curl, CURLOPT_POST, 1L);
        curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDS, post_json);
        curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDSIZE,
                         (long)strlen(post_json));
    } else {
        curl_easy_setopt(conn->curl, CURLOPT_HTTPGET, 1L);
    }
    curl_easy_setopt(conn->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, zm_write_cb);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(conn->curl, CURLOPT_CONNECTTIMEOUT,
                     (long)ZM_CONNECT_TIMEOUT_SEC);
    curl_easy_setopt(conn->curl, CURLOPT_TIMEOUT, (long)ZM_API_TIMEOUT_SEC);
    /* No redirects: a redirect is a URL we did not classify, and
     * following one would carry the Authorization header to whatever
     * host the response named. */
    curl_easy_setopt(conn->curl, CURLOPT_FOLLOWLOCATION, 0L);

    /*
     * Transmit the classified path EXACTLY as classified. Without this
     * libcurl squashes /./ and /../ before sending, so a path the gate
     * called RED could be normalized into one it calls GREEN — or the
     * reverse. The return IS checked: a libcurl that does not know this
     * option would silently keep normalizing, and silent normalization
     * is exactly the divergence being prevented.
     *
     * Dot segments cannot survive zm_route_path() either (an <id> is
     * digits, so "." and ".." are RED) — belt and braces, because an
     * intermediary may normalize regardless of what this client asks.
     */
    CURLcode pai = curl_easy_setopt(conn->curl, CURLOPT_PATH_AS_IS, 1L);
    if (pai != CURLE_OK) {
        fprintf(stderr, "[Zammad] CURLOPT_PATH_AS_IS unsupported (%s) — "
                        "refusing: the transmitted path could differ from "
                        "the classified one\n", curl_easy_strerror(pai));
        curl_slist_free_all(headers);
        OPENSSL_cleanse(auth_hdr, sizeof(auth_hdr));
        return ZM_ERR_CURL_PERFORM;
    }

    zm_configure_tls(conn->curl);

    CURLcode rc = curl_easy_perform(conn->curl);

    curl_slist_free_all(headers);
    OPENSSL_cleanse(auth_hdr, sizeof(auth_hdr));

    if (rc != CURLE_OK) {
        /* curl_easy_strerror() describes the class of failure and never
         * echoes the request headers, so this cannot leak the token. */
        fprintf(stderr, "[Zammad] curl error on %s: %s\n",
                conn->device.hostname, curl_easy_strerror(rc));
        if (rc == CURLE_COULDNT_CONNECT || rc == CURLE_OPERATION_TIMEDOUT ||
            rc == CURLE_SSL_CONNECT_ERROR || rc == CURLE_PEER_FAILED_VERIFICATION)
            conn->connected = false;
        return ZM_ERR_CURL_PERFORM;
    }

    curl_easy_getinfo(conn->curl, CURLINFO_RESPONSE_CODE, http_code);
    return VIRP_OK;
}

/*
 * Zammad signals an application error with a top-level envelope:
 *   {"error":"...", "error_human":"..."}
 *
 * Matched ONLY at the head of the body — leading whitespace, '{', then
 * the "error" key — deliberately not with a strstr() over the whole
 * response the way the Wazuh and LibreNMS drivers do. Ticket titles and
 * article bodies are attacker-supplied text that this driver returns
 * verbatim, so a customer who opens a ticket titled  "error"  would
 * otherwise flip every ticket-list read to failed. The narrow match
 * cannot be forged from inside a nested string value.
 *
 * The tradeoff: an error object whose "error" key is not first is
 * missed. That costs nothing in practice — a real Zammad failure also
 * carries a 4xx/5xx status, which is checked separately and first.
 */
static bool zm_body_is_error(const char *body)
{
    const char *p = body;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '{') return false;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return strncmp(p, "\"error\"", 7) == 0;
}

/* =========================================================================
 * Driver: connect — init CURL, validate the token with one probe
 * ========================================================================= */

static virp_conn_t *zammad_connect(const virp_device_t *device)
{
    if (!device) return NULL;

    if (device->api_token[0] == '\0') {
        fprintf(stderr, "[Zammad] No api_token configured for %s\n",
                device->hostname);
        return NULL;
    }

    struct virp_conn *conn = calloc(1, sizeof(struct virp_conn));
    if (!conn) return NULL;

    memcpy(&conn->device, device, sizeof(*device));
    conn->connected = false;

    /*
     * Always https. The port is configurable; the scheme is not. (The
     * LibreNMS driver derives http from a non-443 port — a Zammad
     * instance on 8443 must not get plaintext because of a port
     * number.)
     */
    uint16_t port = device->api_port ? device->api_port :
                    (device->port ? device->port : ZM_DEFAULT_PORT);
    snprintf(conn->base_url, sizeof(conn->base_url), "https://%s:%u",
             device->host, port);

    conn->curl = curl_easy_init();
    if (!conn->curl) {
        fprintf(stderr, "[Zammad] curl_easy_init() failed\n");
        OPENSSL_cleanse(conn->device.api_token,
                        sizeof(conn->device.api_token));
        free(conn);
        return NULL;
    }

    fprintf(stderr, "[Zammad] Connecting to %s\n", conn->base_url);

    /*
     * Validate the token with an internal probe. The probe path is one
     * of the GREEN rows (/api/v1/ticket_states — the smallest of them):
     * the daemon must never touch an endpoint its own classifier calls
     * RED, and a least-privileged token may not be granted anything
     * outside the enumerated set.
     */
    char probe[1024];
    long http_code = 0;
    virp_error_t err = zm_request(conn, ZM_METHOD_GET, false, NULL,
                                  ZM_EP_TICKET_STATES,
                                  probe, sizeof(probe), &http_code);
    if (err != VIRP_OK || http_code != 200) {
        fprintf(stderr, "[Zammad] Token probe failed on %s: HTTP %ld\n",
                device->hostname, http_code);
        curl_easy_cleanup(conn->curl);
        OPENSSL_cleanse(conn->device.api_token,
                        sizeof(conn->device.api_token));
        OPENSSL_cleanse(probe, sizeof(probe));
        free(conn);
        return NULL;
    }

    conn->connected = true;
    fprintf(stderr, "[Zammad] Connected: %s:%u\n", device->host, port);
    return (virp_conn_t *)conn;
}

/* =========================================================================
 * Driver: execute — one GET, response wrapped like the other drivers
 * ========================================================================= */

static virp_error_t zammad_execute(virp_conn_t *base_conn,
                                   const char *command,
                                   virp_exec_result_t *result)
{
    if (!base_conn || !command || !result)
        return VIRP_ERR_NULL_PTR;

    struct virp_conn *conn = (struct virp_conn *)base_conn;
    memset(result, 0, sizeof(*result));

    /*
     * WRITE PATH — the single typed operation, and the only way a
     * non-GET method can ever be issued by this driver.
     *
     * Dispatched by exact literal prefix, before the read path, using
     * the SAME parser the classifier used, so the operation that was
     * classified is the operation that executes.
     */
    if (strncmp(command, ZM_OP_PREFIX, sizeof(ZM_OP_PREFIX) - 1) == 0) {
        zm_request_t req;
        const char *reason = NULL;

        if (zm_parse_command(command, &req, &reason) != 0) {
            result->success = false;
            result->exit_code = 1;
            result->no_dispatch = true;
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Refused before any network activity: %s",
                     reason ? reason : REASON_OP_GRAMMAR);
            return VIRP_OK;
        }

        /*
         * DEVICE SCOPE. The gate judged the command; only the driver can
         * judge the credential. zammad-ro and zammad-rw point at the same
         * host and differ in exactly two things: the token behind them
         * and this allowlist. An approved, correctly-formed write
         * submitted against the read-only entry dies here, before the
         * connection is touched — it does not become a 403 from Zammad,
         * because relying on the far side to enforce our own policy is
         * how a token-permission change silently becomes a policy change.
         */
        if (!zm_device_allows_op(conn->device.write_ops_allow, req.op->id)) {
            result->success = false;
            result->exit_code = 1;
            result->no_dispatch = true;
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Refused on %.32s: %s",
                     conn->device.hostname, REASON_OP_NOT_ON_DEVICE);
            return VIRP_OK;
        }

        char json[ZM_BODY_MAX + 256];
        if (zm_build_article_json(&req, json, sizeof(json)) != 0) {
            result->success = false;
            result->exit_code = 1;
            result->no_dispatch = true;
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Refused: request body would not fit its buffer");
            return VIRP_OK;
        }

        if (!conn->connected) {
            result->success = false;
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Not connected to %s", conn->device.hostname);
            return ZM_ERR_NOT_CONNECTED;
        }

        struct timespec wstart, wend;
        clock_gettime(CLOCK_MONOTONIC, &wstart);

        char wresp[ZM_RESPONSE_MAX];
        long wcode = 0;
        virp_error_t werr = zm_request(conn, req.op->method, /*is_write_op=*/true,
                                       json, req.op->path,
                                       wresp, sizeof(wresp), &wcode);

        clock_gettime(CLOCK_MONOTONIC, &wend);
        result->exec_time_ms =
            (uint64_t)((wend.tv_sec - wstart.tv_sec) * 1000 +
                       (wend.tv_nsec - wstart.tv_nsec) / 1000000);

        if (werr != VIRP_OK) {
            result->success = false;
            result->exit_code = 1;
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "transport error on %.48s%.64s",
                     conn->device.hostname, req.op->path);
            return VIRP_OK;
        }

        /*
         * The observation records the operation as approved AND the exact
         * JSON that was posted. Recording the derived body next to the
         * command is what lets a later reader confirm the derivation
         * without re-running the driver — the same reason the PBS
         * observation carries its derived path.
         */
        int w = snprintf(result->output, sizeof(result->output),
                         "%s>%s %s [HTTP %ld]\n%s\n%s",
                         conn->device.hostname, "POST", req.op->path,
                         wcode, json, wresp);
        result->output_len = (w > 0) ? (size_t)w : 0;

        if (wcode == 401 || wcode == 403) {
            result->success = false;
            result->exit_code = (int)wcode;
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "HTTP %ld auth failure on %s", wcode,
                     conn->device.hostname);
        } else if (wcode >= 400) {
            result->success = false;
            result->exit_code = (int)wcode;
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "HTTP %ld from %s%s", wcode,
                     conn->device.hostname, req.op->path);
        } else {
            result->success = true;
            result->exit_code = 0;
            if (zm_body_is_error(wresp)) {
                result->success = false;
                result->exit_code = 1;
                snprintf(result->error_msg, sizeof(result->error_msg),
                         "Zammad API error in response from %s",
                         conn->device.hostname);
            }
        }
        return VIRP_OK;
    }

    /*
     * GET-only transport honesty — same rule, same ordering, and the
     * same helper the classifier used, so a command can never be
     * classified as one thing and dispatched as another.
     *
     * Everything that is not the typed write above still lands here, and
     * this branch has NOT been loosened: a non-GET method prefix is
     * refused exactly as before, before the connection is touched. POST
     * did not become generally available; one table row became reachable.
     *
     * Checked BEFORE the connectivity test so the refusal is
     * deterministic and offline-testable. This driver can only issue
     * GETs; a command carrying a non-GET method prefix (or anything
     * that is not a rooted path) is refused outright as a soft failure,
     * which the O-Node wraps as a signed ERROR observation
     * (executed=no).
     *
     * The path goes straight to libcurl's CURLOPT_URL as a C string —
     * no shell interpretation, no fork/exec. Bytes like ; | & ` $ ( )
     * are ordinary URL characters here, not shell operators; they are
     * nonetheless RED at the gate because they cannot occur in any
     * listed row.
     */
    const char *path = zm_command_path(command);
    if (!path) {
        result->success = false;
        result->no_dispatch = true;   /* refused before any request went out */
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Refused: GET-only REST driver cannot honor '%.64s' "
                 "(non-GET method or unrooted path)", command);
        return VIRP_OK;
    }

    /*
     * NOTE: execute() deliberately does NOT re-check the tier. The gate
     * decides, and a RED path that a human approved through
     * propose/approve/apply must still run. What execute() enforces is
     * the transport contract — GET, this path, verbatim.
     */

    if (!conn->connected) {
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Not connected to %s", conn->device.hostname);
        return ZM_ERR_NOT_CONNECTED;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    char api_response[ZM_RESPONSE_MAX];
    long http_code = 0;
    virp_error_t err = zm_request(conn, ZM_METHOD_GET, false, NULL, path,
                                  api_response, sizeof(api_response),
                                  &http_code);

    clock_gettime(CLOCK_MONOTONIC, &end);
    result->exec_time_ms = (uint64_t)((end.tv_sec - start.tv_sec) * 1000 +
                                      (end.tv_nsec - start.tv_nsec) / 1000000);

    if (err != VIRP_OK) {
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "curl error on %s%s", conn->device.hostname, path);
        return VIRP_OK;
    }

    int written = snprintf(result->output, sizeof(result->output),
                           "%s>%s [HTTP %ld]\n%s",
                           conn->device.hostname, path,
                           http_code, api_response);
    result->output_len = (written > 0) ? (size_t)written : 0;

    if (http_code == 401 || http_code == 403) {
        result->success = false;
        result->exit_code = (int)http_code;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "HTTP %ld auth failure on %s", http_code,
                 conn->device.hostname);
    } else if (http_code >= 400) {
        result->success = false;
        result->exit_code = (int)http_code;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "HTTP %ld from %s%s", http_code,
                 conn->device.hostname, path);
    } else {
        result->success = true;
        result->exit_code = 0;

        if (zm_body_is_error(api_response)) {
            result->success = false;
            result->exit_code = 1;
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Zammad API error in response from %s",
                     conn->device.hostname);
        }
    }

    return VIRP_OK;
}

/* =========================================================================
 * Driver: disconnect / detect / health_check
 * ========================================================================= */

static void zammad_disconnect(virp_conn_t *base_conn)
{
    if (!base_conn) return;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    if (conn->curl) {
        curl_easy_cleanup(conn->curl);
        conn->curl = NULL;
    }

    conn->connected = false;
    fprintf(stderr, "[Zammad] Disconnected: %s\n", conn->device.hostname);

    OPENSSL_cleanse(conn->device.api_token, sizeof(conn->device.api_token));
    free(conn);
}

static bool zammad_detect(virp_conn_t *base_conn)
{
    if (!base_conn) return false;
    struct virp_conn *conn = (struct virp_conn *)base_conn;
    return conn->device.vendor == VIRP_VENDOR_ZAMMAD;
}

static virp_error_t zammad_health_check(virp_conn_t *base_conn)
{
    if (!base_conn) return VIRP_ERR_NULL_PTR;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    if (!conn->connected) return ZM_ERR_NOT_CONNECTED;

    /* Health probe stays inside the GREEN read set — see connect(). */
    char probe[1024];
    long http_code = 0;
    virp_error_t err = zm_request(conn, ZM_METHOD_GET, false, NULL,
                                  ZM_EP_TICKET_STATES,
                                  probe, sizeof(probe), &http_code);
    if (err != VIRP_OK) return err;
    return http_code == 200 ? VIRP_OK : ZM_ERR_AUTH_FAILED;
}

/* =========================================================================
 * Driver Registration
 * ========================================================================= */

static virp_driver_t zammad_driver = {
    .name       = "zammad",
    .vendor     = VIRP_VENDOR_ZAMMAD,
    .connect    = zammad_connect,
    .execute    = zammad_execute,
    .disconnect = zammad_disconnect,
    .detect     = zammad_detect,
    .health_check = zammad_health_check,
    .route_command = zammad_gate_tier,
    .route_reason  = zammad_gate_reason,
};

const virp_driver_t *virp_driver_zammad(void)
{
    return &zammad_driver;
}

void virp_driver_zammad_init(void)
{
    /*
     * Table invariants BEFORE registration. A row that declares no tier,
     * a BLACK row, or a second row that names POST is a startup failure
     * rather than a silent runtime surprise — the write surface of this
     * driver is one row and that has to be enforced somewhere the
     * compiler cannot.
     */
    if (zm_op_table_validate() != 0) {
        fprintf(stderr, "[Zammad] op table failed validation — driver NOT "
                        "registered; no Zammad device will be usable\n");
        return;
    }
    virp_driver_register(&zammad_driver);
}
