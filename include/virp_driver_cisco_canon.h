/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Cisco IOS command canonicalizer + exact-match tier table (v1, EXEC mode)
 *
 * WHY THIS MODULE EXISTS. IOS accepts any unambiguous prefix of a
 * keyword: `sh run`, `sho running` and `show running-config` are ONE
 * command to the device. A gate that tiers spellings instead of
 * commands treats them as three — the cosmetic-gate case: two
 * spellings of one command yielding two classifications, two rules,
 * two hash identities. This module resolves spelling BEFORE anything
 * downstream sees the command, so classification, the signed command
 * hash, and the executed bytes all operate on ONE canonical string.
 *
 * LAYERING (load-bearing — the FortiGate `show ` catch-all removed in
 * b26e34d is the precedent):
 *
 *   canonicalizer  — ALL prefix logic lives here, IOS-parser style:
 *                    per-token, against a command tree, ambiguity
 *                    FAILS CLOSED (no canonical form, RED).
 *   tier table     — EXACT-MATCH on canonical strings ONLY. No prefix
 *                    matching of any kind. IOS abbreviations ARE
 *                    prefixes, so a prefix-shaped tier row is exactly
 *                    the boundary bug b26e34d removed.
 *
 * Pure code, no transport dependencies: lives in the core library so
 * the gate suites run without CISCO=1 and the daemon can classify for
 * both cisco_ios and cisco_iosxe.
 */

#ifndef VIRP_DRIVER_CISCO_CANON_H
#define VIRP_DRIVER_CISCO_CANON_H

#include "virp.h"
#include "virp_driver.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Canonical output bound. Matches the daemon's 512-byte v2
 * canonicalization probe: a canonical string always fits where the
 * signed command hash is computed. */
#define CISCO_CANON_MAX 512

/*
 * Classifier version, stamped on every classification (journal [GATE]
 * line, gate_rejection chain body). Bump when the tree, the table, or
 * the resolution rules change meaning — the stamp exists so an audit
 * can tie a recorded decision to the rule set that produced it.
 */
extern const char CISCO_CANON_VERSION[];

/*
 * Canonicalize one EXEC-mode command: keywords resolved per-token
 * (case-insensitive, exact match first, then unique prefix),
 * arguments preserved byte-for-byte, whitespace runs collapsed.
 *
 * Returns the canonical length (>= 0) with the canonical string in
 * `out`, or -1 when NO canonical form exists: ambiguous abbreviation
 * (2+ candidate keywords — fails closed, candidates are logged),
 * unrecognized token at a node that takes no arguments, an illegal
 * separator, or overflow. On -1 the caller keeps the raw bytes and
 * the classifier fails closed on them.
 *
 * This is the virp_driver_t.canon_command hook. It logs failure
 * detail to stderr (it runs once per request, in the daemon); the
 * side-effect-free classification hooks below never log.
 */
int cisco_canon_command(const char *command, char *out, size_t out_cap);

/*
 * Gate hooks (route_command / route_rule / route_reason contracts):
 * read-only, side-effect free, static strings only. Each internally
 * canonicalizes, so a directly-called classification is identical to
 * the daemon's canonicalize-then-classify path — the raw spelling can
 * never reach the tier table.
 */
virp_trust_tier_t cisco_gate_tier(const char *command);
const char *cisco_gate_rule(const char *command);    /* never NULL */
const char *cisco_gate_reason(const char *command);  /* NULL = generic */

/*
 * Table init invariants, checked loudly at registration (zammad
 * pattern): every row GREEN/YELLOW/RED (no untierable row, no BLACK),
 * no prefix-shaped entry (trailing space / doubled space / tab), each
 * row canonicalizes to itself (tree coverage + idempotence), each row
 * classifies to its declared tier and rule (reachability), no
 * duplicates. Returns 0 when all hold; on failure prints every
 * violation and returns -1 — the caller must NOT register the driver.
 */
int cisco_canon_table_validate(void);

/*
 * Test-support accessors (table-driven suites; see the equivalent
 * pair for the FortiGate table). cisco_canon_table_lookup is the
 * EXACT-match lookup itself, exposed so tests can pin the
 * canonical-only invariant: lookup("sh run") == NULL forever.
 * Returns the row's rule id, or NULL when no row matches exactly.
 */
size_t cisco_canon_table_count(void);
const char *cisco_canon_table_entry(size_t i, virp_trust_tier_t *tier,
                                    const char **rule_id);
const char *cisco_canon_table_lookup(const char *canonical,
                                     virp_trust_tier_t *tier);

#ifdef __cplusplus
}
#endif
#endif /* VIRP_DRIVER_CISCO_CANON_H */
