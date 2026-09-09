/*
 * virp_driver_fortigate.h — FortiGate device driver for VIRP
 *
 * SSH-only transport. No REST API, no fallback.
 *
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#ifndef VIRP_DRIVER_FORTIGATE_H
#define VIRP_DRIVER_FORTIGATE_H

#include "virp_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── FortiGate-specific error codes (extend virp_error_t range) ── */
#define FG_ERR_NOT_CONNECTED    ((virp_error_t)(-100))
#define FG_ERR_TRANSPORT        ((virp_error_t)(-101))
#define FG_ERR_AUTH             ((virp_error_t)(-102))

/* ── Public API ─────────────────────────────────────────────────── */

/* Driver init — call once at startup to register with driver registry */
void virp_driver_fortinet_init(void);

/*
 * BLACK tier check — returns true if the command is destructive
 * and must never be transmitted to the device.
 */
bool fg_is_black_tier(const char *command);

/*
 * Route a command to its trust tier for the O-Node enforcement gate.
 * Prefix-matched, longest match wins. Returns the tier for the
 * best-matching prefix, or VIRP_TIER_YELLOW for unmapped commands
 * (matching the ASA/JunOS default). Read-only, no side effects.
 */
virp_trust_tier_t fg_route_command(const char *command);

#ifdef __cplusplus
}
#endif

/*
 * Reply scrubbing (exposed for tests).
 *
 * fg_scrub_reply reduces a raw FortiOS reply to the device's answer:
 * it drops the command echo, and for a VDOM-wrapped command the
 * `config vdom` / `edit <vdom>` / `end` echoes around it, plus the
 * trailing prompt. Returns NULL when the command echo is absent — the
 * reply cannot then be reduced to a trustworthy body and the caller
 * reports an error instead of guessing.
 */
char *fg_scrub_reply(char *raw, size_t total, const char *command,
                     bool vdom_wrapped, size_t *out_len);
char *fg_line_after_containing(char *buf, const char *needle);
char *fg_find_last_echo_line(char *buf, const char *word);

/*
 * Prompt / pager detection (2026-09-09, FortiOS 7.6 on the 200G).
 * fg_trim_prompt_tail strips trailing whitespace and ANSI CSI sequences;
 * fg_reply_ends_with_prompt accepts the read-write '#' AND read-only '$'
 * prompt; fg_pager_pending spots the "--More--" wait state so the read
 * loop can answer it; fg_strip_pager removes the marker and its erase run
 * before the body is signed. Exported for tests/test_driver_fortigate_scrub.c.
 */
size_t fg_trim_prompt_tail(const char *raw, size_t t);
bool   fg_reply_ends_with_prompt(const char *raw, size_t total);
bool   fg_pager_pending(const char *raw, size_t total);
size_t fg_strip_pager(char *raw, size_t total);

#endif /* VIRP_DRIVER_FORTIGATE_H */
