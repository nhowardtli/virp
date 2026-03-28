/*
 * virp_driver_juniper.h — Juniper JunOS device driver for VIRP
 *
 * SSH-only driver for Juniper SRX/EX/MX/QFX platforms (JunOS 12.x+).
 *
 * Key differences from IOS/ASA:
 *   - No enable mode — JunOS has flat privilege model
 *   - Pager disable: "set cli screen-length 0" (not terminal length)
 *   - Prompt: user@hostname> (operational), user@hostname# (config)
 *   - Error format: "syntax error", "unknown command"
 *   - Interactive shell via PTY (same transport as Cisco/ASA drivers)
 *   - Older JunOS (15.1 and below) requires legacy SSH ciphers
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#ifndef VIRP_DRIVER_JUNIPER_H
#define VIRP_DRIVER_JUNIPER_H

#include "virp.h"
#include "virp_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── JunOS CLI modes ───────────────────────────────────────────── */
typedef enum {
    JUNOS_MODE_OPERATIONAL,     /* user@hostname>          */
    JUNOS_MODE_CONFIGURE,       /* user@hostname#          */
    JUNOS_MODE_SHELL,           /* user@hostname%  (unix)  */
    JUNOS_MODE_UNKNOWN,
} junos_mode_t;

/* ── Command routing table entry ───────────────────────────────── */
typedef struct {
    const char            *command_pattern;  /* CLI command prefix           */
    virp_trust_tier_t      tier;            /* GREEN/YELLOW/RED/BLACK       */
} junos_command_route_t;

/* ── Public API ────────────────────────────────────────────────── */
const virp_driver_t       *virp_driver_juniper(void);
void                       virp_driver_juniper_init(void);

/*
 * Route a command to its trust tier.
 * Returns the tier for the best-matching prefix, or VIRP_TIER_YELLOW
 * as the default for unmapped commands.
 */
virp_trust_tier_t junos_route_command(const char *command);

/*
 * Parse JunOS prompt to determine current mode.
 */
junos_mode_t junos_parse_mode(const char *prompt);

/*
 * Detect if a command string is a batch (contains ';' or '\n' separators).
 * Batch commands are executed sequentially in a single PTY session,
 * preserving JunOS candidate configuration between commands.
 *
 * Example: "configure; set interfaces ge-0/0/0 ...; commit check; commit"
 */
bool junos_is_batch_command(const char *command);

extern const size_t JUNOS_ROUTE_TABLE_SIZE;
extern const junos_command_route_t JUNOS_ROUTE_TABLE[];

#ifdef __cplusplus
}
#endif
#endif /* VIRP_DRIVER_JUNIPER_H */
