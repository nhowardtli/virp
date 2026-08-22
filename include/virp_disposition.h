/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Execution disposition: the ONE vocabulary for "what happened to
 * a command after the gate admitted it".
 *
 * THIS HEADER IS THE SINGLE SOURCE OF TRUTH. report/virp_disposition.py
 * is GENERATED from it by scripts/gen_disposition.py and `make
 * check-disposition` (part of all-tests) fails if the two drift. Edit
 * here, regenerate, never edit the Python by hand.
 *
 * Why this exists (two convergent external reviews, 2026-08): when a
 * command's result could not be determined, the OUTCOME record persisted
 * "success": false. That is invented negative certainty — the honest
 * client-side truth was "this may have executed" and the durable record
 * said "confirmed failure". An auditor reconstructing an incident from
 * the chain would be misled in the one case that matters most. The
 * boolean has no value for "we do not know"; this enum does.
 *
 * Exactly FOUR persistable states. Every durable record of an admitted
 * execution (approval OUTCOME bodies, gate_execution bodies) carries one
 * of these as its `disposition` field, and that field is the truth. Any
 * `success` boolean alongside it is DERIVED (see
 * virp_disposition_success_json) and exists only as a convenience.
 *
 *   NOT_DISPATCHED      The driver PROVED no byte of the command reached
 *                       the device (refused before the first transport
 *                       write: not connected, pre-I/O validation, channel
 *                       never opened, TLS pin rejected). This is EXACTLY
 *                       the condition under which the O-Node's single
 *                       auto-retry fires — result.no_dispatch — and must
 *                       never be wider or narrower than that.
 *   EXECUTED_CONFIRMED  Dispatched, completed cleanly, and the device
 *                       reported success.
 *   EXECUTED_FAILED     Dispatched, completed cleanly, and the device
 *                       reported failure (non-zero exit, error text, a
 *                       refusal the device itself produced).
 *   EXECUTED_UNKNOWN    Dispatch MAY have occurred and the result is not
 *                       confirmed: timeout after send, connection lost
 *                       mid-command, channel closed without an exit
 *                       status, driver threw, response lost, daemon
 *                       died. Never counted as success, never counted as
 *                       failure, never retried.
 *
 * UNSET (0) is NOT a fifth state. It is the zero value a driver result
 * carries when the driver has not classified its own termination
 * (unconverted drivers); virp_disposition_resolve() turns it into one of
 * the four before anything is persisted, and virp_disposition_persistable()
 * refuses it. It never appears in a record.
 *
 * LEGACY RECORDS. The chain is append-only; records written before this
 * vocabulary existed carry only "success": true/false and no
 * `disposition` key. A reader MUST NOT map those onto the four states
 * above — a legacy "success": false could have been any of
 * EXECUTED_FAILED, EXECUTED_UNKNOWN or NOT_DISPATCHED, and that is the
 * ambiguity this enum was introduced to end, not to paper over. Readers
 * render them as LEGACY_CONFIRMED / LEGACY_FAILED. The distinguishing
 * rule, stated once here and mirrored in report/verify.py:
 *
 *   new record     := body has a "disposition" key whose value is one of
 *                     the four names above (bodies also carry
 *                     "schema": "outcome/2" or "gate_execution/2")
 *   legacy record  := body has NO "disposition" key (outcome/1 bodies had
 *                     no schema field at all; gate_execution/1 bodies
 *                     carried the raw DRIVER classification under this
 *                     key name, see VIRP_GATE_EXECUTION_SCHEMA_V1 below)
 *
 * gate_execution/1 caveat: those bodies DID carry a "disposition" key,
 * but it held the driver-level termination string (including "UNSET"
 * and "DRIVER_ERROR", which are not dispositions). A reader must
 * therefore key on the schema for gate_execution bodies: schema
 * gate_execution/1 => legacy, derive LEGACY_* from "success"; schema
 * gate_execution/2 => "disposition" is authoritative.
 */

#ifndef VIRP_DISPOSITION_H
#define VIRP_DISPOSITION_H

#include <stdbool.h>

typedef enum {
    /* Driver-internal zero value: "not classified". NEVER persisted. */
    VIRP_DISPOSITION_UNSET              = 0,
    VIRP_DISPOSITION_NOT_DISPATCHED     = 1,
    VIRP_DISPOSITION_EXECUTED_CONFIRMED = 2,
    VIRP_DISPOSITION_EXECUTED_FAILED    = 3,
    VIRP_DISPOSITION_EXECUTED_UNKNOWN   = 4,
} virp_disposition_t;

/* Canonical names. These exact strings are what is written into chain
 * bodies and what the report layer matches on. */
#define VIRP_DISPOSITION_NAME_NOT_DISPATCHED      "NOT_DISPATCHED"
#define VIRP_DISPOSITION_NAME_EXECUTED_CONFIRMED  "EXECUTED_CONFIRMED"
#define VIRP_DISPOSITION_NAME_EXECUTED_FAILED     "EXECUTED_FAILED"
#define VIRP_DISPOSITION_NAME_EXECUTED_UNKNOWN    "EXECUTED_UNKNOWN"

/* Reader-side labels for records that predate the vocabulary. Not
 * states; never written by the daemon. Defined here so the whole
 * vocabulary, including how the past is rendered, has one home. */
#define VIRP_DISPOSITION_LEGACY_CONFIRMED         "LEGACY_CONFIRMED"
#define VIRP_DISPOSITION_LEGACY_FAILED            "LEGACY_FAILED"

/* Body schema tags. A reader distinguishes new from legacy by these. */
#define VIRP_OUTCOME_SCHEMA_V2                    "outcome/2"
#define VIRP_GATE_EXECUTION_SCHEMA_V1             "gate_execution/1"
#define VIRP_GATE_EXECUTION_SCHEMA_V2             "gate_execution/2"

/* Canonical name for a disposition. UNSET renders as "UNSET" for logs
 * only; it is refused by virp_disposition_persistable(). */
const char *virp_disposition_str(virp_disposition_t d);

/* Parse a canonical name back to the enum. Returns UNSET for anything
 * that is not one of the four persistable names. */
virp_disposition_t virp_disposition_parse(const char *name);

/* True for the four states that may be written to a record. */
bool virp_disposition_persistable(virp_disposition_t d);

/*
 * The DERIVED boolean, as JSON text, for a record that also carries the
 * disposition. Only EXECUTED_CONFIRMED is "true" and only EXECUTED_FAILED
 * is "false"; EXECUTED_UNKNOWN and NOT_DISPATCHED yield "null", because
 * for those the yes/no question has no honest answer and a false would
 * reproduce exactly the defect this vocabulary removes.
 */
const char *virp_disposition_success_json(virp_disposition_t d);

/* "executed" convenience: could the device have run the command? True
 * for everything except NOT_DISPATCHED (UNKNOWN counts — that is what
 * unknown means). */
bool virp_disposition_may_have_executed(virp_disposition_t d);

#endif /* VIRP_DISPOSITION_H */
