/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Collector-side response body filtering (allowlist, recorded).
 *
 * Removes sensitive fields from a driver's REST response BEFORE the
 * bytes are hashed, signed, or chained — at the SCRUB-BARRIER in
 * onode_execute_obs_ex(). Once bytes enter the append-only chain they
 * can never be removed, so render-time redaction is not a defense;
 * this is.
 *
 * Discipline:
 *   - ALLOWLIST, never denylist: a rule enumerates the keys that may
 *     pass. A field the upstream API adds tomorrow is dropped by
 *     default, not leaked by default.
 *   - RECORDED, never silent: a body that was filtered carries a
 *     "_virp_filtered" object naming every removed key (names only,
 *     never values), so no reader can mistake it for the raw response.
 *     A body from which nothing was removed is byte-identical to the
 *     raw response and carries no annotation.
 *   - FAIL CLOSED: if a rule matches but the payload cannot be parsed
 *     (or the filtered form cannot be stored), the payload is WITHHELD
 *     and replaced by a stub recording sha256 + length of the original
 *     bytes. A parse hiccup must not become a credential leak.
 *
 * Rules are config-driven per (driver, endpoint path): JSON loaded
 * from the path in $VIRP_BODY_FILTERS if set, else
 * /etc/virp/body-filters.json if present, else compiled-in defaults
 * (deploy/body-filters.json ships the same content as the built-in).
 * The next collector with this class of problem is a config line.
 */

#ifndef VIRP_BODY_FILTER_H
#define VIRP_BODY_FILTER_H

#include "virp_driver.h"

/* Outcome of one apply call, for logging and tests. */
typedef enum {
    VIRP_BF_UNTOUCHED = 0,   /* no rule matched, or nothing removed  */
    VIRP_BF_FILTERED  = 1,   /* fields removed; _virp_filtered added */
    VIRP_BF_WITHHELD  = 2,   /* matched rule, unusable payload: body
                                replaced by a withhold stub           */
} virp_bf_outcome_t;

/*
 * Load filter rules. config_path == NULL resolves the config as
 * documented above ($VIRP_BODY_FILTERS → /etc/virp/body-filters.json →
 * built-in). Explicit call is optional: the first apply() self-
 * initializes the same way (thread-safe, once). A config file that
 * exists but does not parse falls back to the BUILT-IN rules — never
 * to "no filtering" — and says so on stderr. Returns VIRP_OK when the
 * intended rule set is active.
 */
virp_error_t virp_body_filter_init(const char *config_path);

/*
 * Filter result->output in place, before any hash/sign/chain use.
 *
 * driver_name — drv->name of the driver that produced the result.
 * command     — the command as admitted by the gate (e.g.
 *               "GET /api/v0/devices?type=all"); the rule match strips
 *               a leading method word and the query string.
 *
 * Matches at most one rule (first match wins). Only result->output /
 * result->output_len are modified; on any modification the vacated
 * tail of the buffer is cleansed so removed values do not linger.
 */
virp_bf_outcome_t virp_body_filter_apply(const char *driver_name,
                                         const char *command,
                                         virp_exec_result_t *result);

/* Test hook: drop loaded rules so the next init/apply reloads. */
void virp_body_filter_reset_for_tests(void);

#endif /* VIRP_BODY_FILTER_H */
