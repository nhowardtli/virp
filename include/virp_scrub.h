/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Scrub-at-capture — secret-shaped content redaction for observation bodies
 *
 * Runs in the O-Node capture path, on the driver's exec result, BEFORE
 * the body is hashed, signed, or committed to anywhere (S-1). The
 * redacted form IS the artifact: the observation signature and the
 * gate_execution response_sha256 commitment are computed over the
 * scrubbed bytes, so a verifier sees the redaction as signed content,
 * never as tampering. No original is retained — not in the chain, not
 * in a sidecar, not in a field.
 *
 * This is a safety net for the ACCIDENTAL case (a device unexpectedly
 * echoes a credential), layered behind the per-driver config scrubs
 * (cisco_scrub_config and siblings), which remain the primary defense
 * for reads that are KNOWN to carry credentials.
 *
 * THE HONESTY LIMIT — read before describing this feature anywhere:
 * this scrubber reduces the blast radius of an accidental credential
 * dump for RECOGNIZED FORMATS. It does not guarantee the chain is
 * secret-free. A credential that looks like ordinary text — an
 * unlabeled plaintext password, a bare hex token — will NOT be caught.
 * Say "secrets in recognized formats are scrubbed at capture"; never
 * say "no secret can enter the chain".
 */

#ifndef VIRP_SCRUB_H
#define VIRP_SCRUB_H

#include "virp.h"
#include "virp_driver.h"

/* Every redaction is a visible, signed marker — never a silent drop.
 * A blank looks like missing data; a marker shows the scrub fired and
 * why, and because it is signed, the redaction is tamper-evident. */
#define VIRP_SCRUB_MARK_PREFIX  "[REDACTED: "
#define VIRP_SCRUB_MARK_SUFFIX  "]"

/* The whole-body fail-closed marker. If the scrubber cannot complete
 * on a body, the body becomes exactly this — a scanner that fails
 * open is worse than none. */
#define VIRP_SCRUB_MARK_ERROR   "[REDACTED: scrub-error]"

/*
 * Pure scanner: scrub [in, in+in_len) into out (capacity out_cap),
 * *out_len receives the redacted length, *redactions the number of
 * spans redacted (0 == clean body, out is a byte-identical copy).
 *
 * v1 ruleset — conservative, known shapes only (see SCRUB-DESIGN.md):
 *   - Cisco-style credential lines: enable secret/password,
 *     `password <n> <hash>`, `secret <n> <hash>`,
 *     `username ... password|secret ...` — everything after the
 *     keyword is replaced with a marker.
 *   - `snmp-server community <string> ...` — the community token is
 *     replaced; the rest of the line (RO/RW, ACL) is kept.
 *   - Pre-shared keys: `pre-shared-key`, `psk`, `wpa-psk`,
 *     `key-string`, `crypto ... key <tok> [address ...]`, and a
 *     first-token `key <string>` line (tacacs/radius/key-chain shape,
 *     with the `key <number>` / `key chain` exceptions).
 *   - PEM private-key blocks: interior replaced with one
 *     [REDACTED: private-key-block] line (BEGIN/END lines kept). An
 *     unterminated block redacts through end of body.
 *   - Generic labeled secrets: a label token equal to (or ending in)
 *     password/passwd/secret/token/api-key/api_key/apikey followed by
 *     `:` or `=` — the value is replaced, the label kept.
 *
 * Returns VIRP_OK on completion. On any failure (output would not
 * fit, forced test error) returns the error with *out_len zeroed —
 * the caller MUST NOT use out and MUST fail closed.
 *
 * Pure function, no allocation, no globals except the test hook below;
 * exposed for the unit suite (tests/test_virp_scrub.c).
 */
virp_error_t virp_scrub_body(const char *in, size_t in_len,
                             char *out, size_t out_cap,
                             size_t *out_len,
                             unsigned *redactions);

/*
 * Fail-closed wrapper for the capture path: scrub result->output and
 * result->error_msg IN PLACE. Cannot fail open:
 *   - clean field  → byte-identical no-op;
 *   - redactions   → field replaced with the scrubbed form;
 *   - scrub error  → field replaced ENTIRELY with
 *                    "[REDACTED: scrub-error]".
 * Empty fields are left empty (nothing was captured; a marker there
 * would fabricate content). Never touches success/exit_code/
 * disposition — only the two text fields that feed signed bodies.
 */
void virp_scrub_exec_result(virp_exec_result_t *result);

/*
 * TEST-ONLY: force virp_scrub_body to fail unconditionally, to prove
 * the fail-closed contract (gate G3). Deliberately fails in the CLOSED
 * direction only — arming it can only cause over-redaction, never
 * leak. There is intentionally NO hook that disables scrubbing.
 */
void virp_scrub_test_force_error(bool on);

#endif /* VIRP_SCRUB_H */
