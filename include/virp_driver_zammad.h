/*
 * virp_driver_zammad.h — Zammad REST API driver for VIRP
 *
 * Third token-auth REST driver, same shape as the LibreNMS one: a
 * static personal access token in a header, no token lifecycle,
 * GET-only transport.
 *
 * Device config mapping (devices.json):
 *   host       — Zammad host/FQDN (must match the certificate)
 *   api_token  — Zammad personal access token, sent as
 *                "Authorization: Token token=<value>" (NOT Bearer)
 *   api_port / port — API port; default 443. The scheme is ALWAYS
 *                https regardless of port — see the TLS note below.
 *
 * TLS: verification is unconditional. There is no VIRP_ZAMMAD_INSECURE
 * escape hatch (unlike the Wazuh driver's lab drop-in), no CA-bundle
 * override, and no plaintext scheme selection (unlike the LibreNMS
 * driver, where a non-443 port silently means http). The Zammad
 * certificate is in the host CA store; anything that would make this
 * driver accept a different identity is a config knob that disables
 * TLS, so none exists.
 *
 * The "command" parameter to execute() is a Zammad API path, e.g.
 *   /api/v1/tickets?per_page=50
 *   /api/v1/ticket_articles/by_ticket/1234
 *
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 */

#ifndef VIRP_DRIVER_ZAMMAD_H
#define VIRP_DRIVER_ZAMMAD_H

#include "virp_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Zammad-specific error codes (extend virp_error_t range) ───── */
#define ZM_ERR_NOT_CONNECTED    ((virp_error_t)(-230))
#define ZM_ERR_AUTH_FAILED      ((virp_error_t)(-231))
#define ZM_ERR_CURL_INIT        ((virp_error_t)(-232))
#define ZM_ERR_CURL_PERFORM     ((virp_error_t)(-233))
#define ZM_ERR_API_ERROR        ((virp_error_t)(-234))
#define ZM_ERR_METHOD           ((virp_error_t)(-235))

/* ── Tunables ─────────────────────────────────────────────────── */
#define ZM_API_TIMEOUT_SEC      30
#define ZM_CONNECT_TIMEOUT_SEC  10
#define ZM_DEFAULT_PORT         443
#define ZM_TOKEN_MAX            256
#define ZM_RESPONSE_MAX         (VIRP_OUTPUT_MAX - 256)

/*
 * LOAD-BEARING INVARIANT — these two caps are not tidiness, and
 * removing or raising either one silently breaks a security property.
 *
 * The property: a path that classifies GREEN can never be long enough
 * to truncate in the URL buffer, so the request that goes on the wire
 * is always the request that was classified and signed.
 *
 * How the two caps produce it:
 *
 *   ZM_DIGITS_MAX bounds every variable-length element a GREEN path
 *   can contain. There are only two — the <id> segment and a
 *   page/per_page value — and both are digit runs. With the fixed row
 *   text (longest base 34 bytes) plus at most one id and two query
 *   values, a GREEN path cannot exceed 110 bytes. 20 digits holds any
 *   value a uint64 can express, so no real Zammad object id is
 *   excluded; the cap costs nothing and buys the bound.
 *
 *   ZM_PATH_MAX is the backstop for everything else, and is checked in
 *   BOTH places that matter: zm_route_path() refuses a longer path
 *   outright, and zm_get() refuses it again before building the URL.
 *   512 + the longest base_url ("https://" + 255-byte host + ":65535")
 *   stays far inside the 2048-byte url[] buffer, and zm_get() also
 *   checks the snprintf return, so truncation is caught even if these
 *   bounds are later wrong.
 *
 * Why the CLASSIFIER carries the cap and not just the transport: if
 * only the transport enforced it, an over-long path could classify
 * GREEN, be approved and signed, and then be refused at dispatch — the
 * gate would have blessed a request the driver cannot make. Classifier
 * and transport must agree on what is issuable, so the bound lives in
 * both.
 *
 * If a future Zammad row needs a non-numeric variable segment, this
 * argument does NOT carry over: the new element has to come with its
 * own length bound, or the truncation property is gone.
 */
#define ZM_DIGITS_MAX           20      /* see invariant above — load-bearing */
#define ZM_PATH_MAX             512     /* see invariant above — load-bearing */

/* ── Collector endpoints (the GREEN read set, verbatim) ───────── */
#define ZM_API_PREFIX           "/api/v1"
#define ZM_EP_TICKETS           ZM_API_PREFIX "/tickets"
#define ZM_EP_TICKET_STATES     ZM_API_PREFIX "/ticket_states"
#define ZM_EP_GROUPS            ZM_API_PREFIX "/groups"

/* =====================================================================
 * TYPED WRITE OPERATIONS
 *
 * Reads in this driver are API PATHS (above). The single write is NOT:
 * it is a canonical typed operation in the shape driver_pbs.c
 * established, because the properties that model buys are exactly the
 * ones a write needs.
 *
 *     zammad op=ticket.article.create id=<digits> body="<text>"
 *
 * Method and URL are derived INSIDE the driver from a static table and
 * never from input. The JSON that gets posted is a static template with
 * two substitutions, both already validated. So the approved bytes fully
 * determine the request: there is no syntax left to interpret.
 *
 * ONE row. No state change, no assignment, no close, no user or group
 * operation, no customer-visible reply. Everything else is RED by
 * absence, and absence is the enforcement — there is no row to reach.
 *
 * GRAMMAR (exact; anything else is refused before any network activity):
 *   - literal leading "zammad ", exactly one space between tokens
 *   - no leading/trailing space, no space runs, no tabs, no control bytes
 *   - parameters appear in the ORDER THE OP ROW DECLARES them, each
 *     exactly once, and only the declared keys
 *   - `body` is the last token and is the only quoted value
 *
 * NOTE the deliberate divergence from PBS here: PBS canonicalizes token
 * order by requiring keys to sort strictly ascending AND strictly after
 * "op". That trick cannot survive a parameter named before "op", and
 * both of these are ("body" < "id" < "op"). Order is therefore fixed
 * POSITIONALLY by the table instead, which yields the same property —
 * exactly one encoding of any request — without depending on how the
 * parameters happen to be spelled.
 * ===================================================================== */

/*
 * Method. Two members, and the second one is why this type exists: the
 * transport switches on it, so adding a write method is a compile-time
 * review point in every switch rather than a string comparison somebody
 * can get wrong. PBS declares GET only; this driver declares POST too
 * and exactly one row is allowed to name it.
 */
typedef enum {
    ZM_METHOD_GET  = 1,
    ZM_METHOD_POST = 2,
} zm_method_t;

/* ── Body policy — the whole risk surface of this feature ─────────────
 *
 * The body is the only free-form text anywhere in VIRP's command
 * grammar, so it gets the strictest rules in the tree.
 *
 * ENCODING: strict canonical percent-encoding, and it is BIJECTIVE —
 * one body has exactly one legal encoding, and one legal encoding has
 * exactly one body. That is the property the whole feature rests on, so
 * it is worth stating why an encoding exists at all.
 *
 * The daemon's ingress filter (virp_command_check_separators) refuses
 * ';' '|' '&' '`' "$(" "${" in ANY command, before any driver sees it.
 * That rule is right for a command and wrong for prose: "&" and "$"
 * occur in ordinary ticket text. Carrying the body raw would therefore
 * silently forbid legitimate sentences, and narrowing the documented
 * charset to match ingress would bake a command-shell concern into what
 * a human may write in a ticket. So the body travels ENCODED — the
 * signed command contains only ingress-safe bytes — and is decoded at
 * the transport.
 *
 * THE RULE, exactly:
 *
 *   Six bytes MUST be percent-escaped and may never appear literally:
 *       ;  |  &  `  $        the ingress separators
 *       %                    the escape introducer itself, or the
 *                            encoding would be ambiguous
 *
 *   Every OTHER byte of the decoded charset MUST appear literally and
 *   may never be escaped. "%41" for 'A' is REFUSED. This is what makes
 *   the encoding canonical rather than merely decodable: without it,
 *   "A" and "%41" would be two signed strings with one meaning, and the
 *   signed bytes would stop determining the outcome.
 *
 *   An escape is exactly "%XX" with two UPPERCASE hex digits. Lowercase
 *   is refused for the same canonicality reason — "%3b" and "%3B" must
 *   not both be legal.
 *
 *   A decoded byte must still be in the BYTE SET below. "%0A" does not
 *   produce a newline; it is refused, because the decoded charset is
 *   unchanged by the introduction of an encoding layer.
 *
 * So the escape mechanism exists for exactly six characters, and buys
 * back the prose that the ingress filter would otherwise have cost.
 * Readability survives: everything else is literal, so an approver
 * reading the signed command reads the body, not a cipher. That is
 * deliberately not base64 — a reviewer approving an opaque blob is
 * approving a pre-image of what lands in the ticket, which is the
 * failure this driver is built to avoid.
 *
 * BYTE SET (of the DECODED body): printable ASCII 0x20..0x7E, minus
 * four characters:
 *     "  (0x22)  would terminate the value, and admitting it would
 *               require a quoting mechanism on top of the encoding. It
 *               is also the JSON string terminator.
 *     \  (0x5C)  the JSON escape introducer. Excluding it and '"' is
 *               what lets the DECODED body be spliced into the JSON
 *               template verbatim: with neither present, no JSON
 *               escaping is needed, so no second transformation happens
 *               between the decoded bytes and the transmitted bytes.
 *     <  (0x3C)
 *     >  (0x3E)  defence in depth for rendering. The op posts
 *               content_type text/plain, but a Zammad UI or a future
 *               integration that renders an article as HTML would turn
 *               a body into stored XSS. Excluding the tag delimiters
 *               means that is not reachable even if the content type is
 *               ever wrong.
 *
 * Everything below 0x20 and everything at or above 0x7F is refused in
 * BOTH forms — literal and escaped — which covers CR, LF, TAB, NUL and
 * all of UTF-8. Non-ASCII is refused DELIBERATELY: UTF-8 admits multiple
 * normalizations (NFC/NFD) of the same visual string, so "the signed
 * bytes determine the outcome" would quietly become "…up to a
 * normalization nobody recorded". An accented character is worth less
 * than that property. This is a real usability limit, not an oversight.
 *
 * NEWLINES: forbidden, literally and as "%0A". There is no multi-line
 * body. A newline in a command string is also the classic
 * request-boundary smuggle, which the daemon's ingress policy already
 * treats as such one layer up.
 *
 * QUOTES: the ENCODED value is delimited by a leading '"' immediately
 * after `body=` and a trailing '"' that MUST be the final byte of the
 * command. Because '"' is in neither the literal set nor any legal
 * escape, the closing quote is unambiguous and there is exactly one
 * parse.
 *
 * LENGTH: ZM_BODY_MAX bytes of DECODED body — the cap is on what lands
 * in the ticket, not on how many characters it took to spell it, or an
 * escape-heavy body would be penalised for containing punctuation.
 * Enforced by the CLASSIFIER and again by the transport, for the reason
 * ZM_PATH_MAX is enforced twice: a cap only at the transport would let
 * an over-long body classify YELLOW and be approved and signed, then be
 * refused at dispatch — the gate blessing a request the driver cannot
 * make.
 * ------------------------------------------------------------------- */
#define ZM_BODY_MAX             512     /* DECODED body bytes, excl. NUL */
/* Worst case is every byte escaped, "%XX" — three encoded bytes per
 * decoded byte. The classifier caps the decoded length, so this only has
 * to be big enough to hold the longest legal encoding of it. */
#define ZM_BODY_ENC_MAX         (ZM_BODY_MAX * 3)
#define ZM_OP_ID_MAX            64
#define ZM_KEY_MAX              16
#define ZM_COMMAND_MAX          (ZM_BODY_ENC_MAX + 256)  /* whole command */
#define ZM_MAX_PARAMS           2
#define ZM_MAX_WRITE_OPS        8       /* per-device write allowlist    */

/* The one write op id, spelled once so table, driver and tests agree. */
#define ZM_OP_ARTICLE_CREATE    "ticket.article.create"

/* ── Op table row ─────────────────────────────────────────────────── */
typedef struct {
    const char        *id;
    zm_method_t        method;
    const char        *path;        /* static; no substitution at all   */
    const char *const *params;      /* NULL-terminated, IN ORDER        */
    virp_trust_tier_t  tier;        /* mandatory, never defaulted       */
} zm_op_t;

/* ── Parsed request ─────────────────────────────────────────────────
 * `body` is the DECODED text — what actually lands in the ticket. The
 * encoded form stays visible in the command string the observation
 * records, so both are in evidence and either can be re-derived from
 * the other.
 * ------------------------------------------------------------------- */
typedef struct {
    const zm_op_t *op;
    char           id[ZM_DIGITS_MAX + 1];
    char           body[ZM_BODY_MAX + 1];
    size_t         body_len;
} zm_request_t;

/* ── Public API ───────────────────────────────────────────────── */
void                 virp_driver_zammad_init(void);
const virp_driver_t *virp_driver_zammad(void);

/*
 * Validate the op table at init: every row must declare a tier and a
 * method, no row may be BLACK (so every refusal stays approvable), and
 * — the one that matters here — no row but ZM_OP_ARTICLE_CREATE may
 * declare a non-GET method. Returns 0 clean, -1 after naming the row.
 */
int zm_op_table_validate(void);

/* Exact-id lookup; NULL for anything not in the table. */
const zm_op_t *zm_op_lookup(const char *id);

/*
 * Parse a canonical typed-operation command. Returns 0 and fills *out,
 * or -1 with *reason set to a static teaching string. Never partially
 * succeeds, never rewrites input, never falls back to a looser reading.
 * Runs before any network activity, so every refusal is a signed typed
 * ERROR rather than a request.
 */
int zm_parse_command(const char *command, zm_request_t *out,
                     const char **reason);

/*
 * Is this byte permitted in the DECODED body? Exposed so the byte-set
 * policy is a unit-testable predicate rather than a property a reader
 * has to reconstruct from a loop.
 */
bool zm_is_body_char(unsigned char c);

/*
 * Must this decoded byte be percent-escaped in the command? True for
 * exactly the six: ; | & ` $ %. A byte for which this is false may
 * NEVER appear escaped, and a byte for which it is true may NEVER
 * appear literally — that pair of rules is what makes the encoding
 * canonical, so both directions are enforced and both are tested.
 */
bool zm_must_escape(unsigned char c);

/*
 * Decode the body value from its canonical percent-encoded form.
 *
 * Refuses, with *reason set: a non-canonical escape (an escape for a
 * byte that should be literal), lowercase hex, a truncated or malformed
 * escape, a literal byte that should have been escaped, any decoded
 * byte outside the body charset, and a decoded length over ZM_BODY_MAX.
 *
 * INJECTIVE by construction: distinct legal inputs decode to distinct
 * bodies, and each body has exactly one legal encoding.
 *
 * Returns 0 with *out NUL-terminated and *out_len set, or -1.
 */
int zm_decode_body(const char *enc, size_t enc_len,
                   char *out, size_t out_max, size_t *out_len,
                   const char **reason);

/*
 * The transport's method whitelist, as a pure predicate. `is_write_op`
 * says whether the caller has already established that this is the one
 * row permitted to POST — POST is allowed ONLY then. Making this a
 * predicate is what turns "no method but GET can be issued except for
 * the single write row" into a claim tests can drive directly.
 */
bool zm_method_is_allowed(int method, bool is_write_op);

/*
 * Does this DEVICE permit this write op? `write_ops_allow` is the
 * device's comma-separated allowlist (NULL or empty = no writes at all,
 * which is the default and the read-only device's configuration).
 * Exact match on a whole entry; no prefixes, no wildcards.
 *
 * Pure, so "the ro device cannot reach the write row" is testable
 * without a socket and therefore without tripping the live-contact
 * fence.
 */
bool zm_device_allows_op(const char *write_ops_allow, const char *op_id);

/*
 * Build the POST body for an already-parsed write request. The template
 * is static; the only substitutions are the digits-only id and the
 * charset-validated body, neither of which can carry JSON syntax.
 * Returns 0 on success, -1 if it would not fit (fails closed).
 */
int zm_build_article_json(const zm_request_t *req, char *out, size_t out_len);

/*
 * Route an API path (with optional query string) to its trust tier.
 *
 * GREEN is exactly five shapes, matched byte-exact:
 *   /api/v1/tickets
 *   /api/v1/tickets/<id>
 *   /api/v1/ticket_articles/by_ticket/<id>
 *   /api/v1/ticket_states
 *   /api/v1/groups
 * where <id> is 1..ZM_DIGITS_MAX ASCII digits and nothing else.
 *
 * A query string, if present, may carry only "page" and "per_page",
 * each at most once, each with a digits-only value. Any other
 * parameter name, any non-numeric or empty value, a repeated
 * parameter, a bare "?", or a malformed pair is RED.
 *
 * Everything else — every write endpoint, every unlisted read — is
 * VIRP_TIER_RED by absence (fail closed). No YELLOW rows, no BLACK
 * rows, so every RED stays approvable through propose/approve/apply.
 */
virp_trust_tier_t zm_route_path(const char *path);

/*
 * route_command hook for the O-Node tier gate.
 *
 * Dispatches on shape, and the two shapes cannot be confused because
 * one starts with '/' (after an optional "GET ") and the other with the
 * literal "zammad ":
 *
 *   "zammad ..."  → typed operation. The one write row classifies
 *                   YELLOW; every grammar violation, unknown op, bad
 *                   body byte, oversize body and malformed id is RED.
 *   "/..."        → read path, as before (GREEN rows, classified query).
 *   anything else → RED (non-GET method prefix, unrooted path).
 *
 * YELLOW for the write is load-bearing, not a label. The node-wide
 * ceiling is YELLOW, but uid 993 (virp-netclaw, the remote requester)
 * carries a per-uid ceiling of GREEN in socket_uid_tier_ceilings, and
 * onode_effective_max_tier() only ever TIGHTENS. So a remote requester
 * hits gate_tier_blocks(YELLOW, GREEN) → blocked → proposal-only, and
 * cannot self-apply because it holds no approver key. A local operator
 * at the node-wide YELLOW ceiling can execute it directly. Demoting
 * this row to GREEN would hand the write to the remote path silently.
 */
virp_trust_tier_t zammad_gate_tier(const char *command);

/* Shared classifier: tier, plus the teaching reason when non-NULL. */
virp_trust_tier_t zammad_gate_classify(const char *command,
                                       const char **reason);

/* route_reason hook — static teaching string, or NULL for the generic. */
const char *zammad_gate_reason(const char *command);

#ifdef __cplusplus
}
#endif
#endif /* VIRP_DRIVER_ZAMMAD_H */
