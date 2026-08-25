/*
 * virp_driver_asa.h — Cisco ASA device driver for VIRP
 *
 * SSH-only driver for Cisco ASA firewalls (ASA-OS 9.8.x through 9.20.x).
 *
 * Key differences from IOS:
 *   - Pager disable: "terminal pager 0" (not "terminal length 0")
 *   - Enable mode drops after certain commands — re-checked before each execute
 *   - Prompt: ASA> / ASA# / ASA(config)# / ASA/ctx>
 *   - SSH KEX: diffie-hellman-group14-sha1 (9.8.x), group14-sha256 (9.12+)
 *   - CLI differences: "show route" not "show ip route", etc.
 *   - Buffer flush before each command (ASA quirk: stale output)
 *
 * NOT for FTD (Firepower Threat Defense) — that uses FMC REST API.
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#ifndef VIRP_DRIVER_ASA_H
#define VIRP_DRIVER_ASA_H

#include "virp.h"
#include "virp_driver.h"
#include "virp_ssh_io.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── ASA CLI modes ─────────────────────────────────────────────── */
typedef enum {
    ASA_MODE_USER,          /* ASA>            — user EXEC          */
    ASA_MODE_ENABLE,        /* ASA#            — privileged EXEC    */
    ASA_MODE_CONFIG,        /* ASA(config)#    — global config      */
    ASA_MODE_CONFIG_SUB,    /* ASA(config-if)# — sub-config mode    */
    ASA_MODE_UNKNOWN,       /* Can't determine mode                 */
} asa_mode_t;

/* ── ASA context tracking ──────────────────────────────────────── */
typedef struct {
    char    name[64];       /* Context name (empty = system/single) */
    bool    is_multi;       /* Multi-context mode detected          */
} asa_context_t;

/* ── Command routing table entry ───────────────────────────────── */
typedef struct {
    const char            *command_pattern;  /* CLI command prefix           */
    virp_trust_tier_t      tier;            /* GREEN/YELLOW/RED/BLACK       */
} asa_command_route_t;

/* ── Public API ────────────────────────────────────────────────── */
const virp_driver_t       *virp_driver_asa(void);
void                       virp_driver_asa_init(void);

/*
 * Route a command to its trust tier.
 * Returns the tier for the best-matching prefix, or VIRP_TIER_YELLOW
 * as the default for unmapped commands.
 */
virp_trust_tier_t asa_route_command(const char *command);

/*
 * Parse ASA prompt to determine current mode.
 */
asa_mode_t asa_parse_mode(const char *prompt);

/*
 * Credential scrub for config-bearing reads (2026-08-10) — port of
 * cisco_scrub_config to the ASA directive set. asa_scrub_config
 * rewrites config text so credential material (enable/passwd hashes,
 * username passwords, aaa-server and failover keys, SNMP communities,
 * tunnel-group pre-shared-keys, routing-protocol auth keys) is
 * replaced with "<removed>" BEFORE the observation body reaches the
 * signer. Pure function, exposed for the unit suite. Fail-closed: on
 * VIRP_ERR_BUFFER_TOO_SMALL the caller must not use — and must not
 * sign — any partial output.
 *
 * asa_command_returns_config identifies the commands whose replies
 * embed configuration; asa_execute applies the scrub to exactly those.
 */
/*
 * Compose <prompt><command>\nbody into result->output with honest
 * length accounting (Item 5): output_len is the actual stored byte
 * count; a clamped scrubbed body is withheld typed; a clamped raw
 * body is marked output_truncated. Exposed for the unit suite.
 *
 * `prompt` is the dispatch-time learned prompt, written byte-exact
 * (ISSUE-A). `hostname` appears only in operator-facing error text —
 * it is a registry claim, not device bytes, and must never re-enter
 * the signed header.
 */
virp_error_t asa_store_output(virp_exec_result_t *result,
                              const virp_ssh_prompt_t *prompt,
                              const char *hostname,
                              const char *command,
                              const char *body,
                              bool scrubbed_body);

virp_error_t asa_scrub_config(const char *in, size_t in_len,
                              char *out, size_t out_cap,
                              size_t *out_len);
bool asa_command_returns_config(const char *command);

extern const size_t ASA_ROUTE_TABLE_SIZE;
extern const asa_command_route_t ASA_ROUTE_TABLE[];

#ifdef __cplusplus
}
#endif
#endif /* VIRP_DRIVER_ASA_H */
