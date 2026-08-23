/*
 * virp_driver_cisco_modes.h — IOS prompt-mode classification
 *
 * Split from virp_driver_cisco.h because that header embeds an opaque
 * virp_conn_t by value and cannot be included standalone (see the note
 * in test_driver_cisco_gate.c). This header is dependency-free so both
 * the driver and the unit tests can include it.
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#ifndef VIRP_DRIVER_CISCO_MODES_H
#define VIRP_DRIVER_CISCO_MODES_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * IOS prompt shapes:
 *   R24>              user EXEC
 *   R24#              privileged EXEC
 *   R24(config)#      global configuration
 *   R24(config-if)#   any sub-configuration (config-if, config-router, ...)
 */
typedef enum {
    CISCO_MODE_UNKNOWN = 0,
    CISCO_MODE_USER,
    CISCO_MODE_EXEC,
    CISCO_MODE_CONFIG,
    CISCO_MODE_CONFIG_SUB
} cisco_mode_t;

/* Pure prompt classifier (trailing whitespace tolerated). Any prompt
 * that does not match a known IOS shape returns CISCO_MODE_UNKNOWN —
 * the fail-closed answer for the transition-recovery path. */
cisco_mode_t cisco_parse_mode(const char *prompt);

/*
 * True if `command`, executed while the connection is in `mode`, may
 * legitimately move the prompt — the only case in which a read that
 * ends without the learned prompt is treated as a mode transition
 * rather than an incomplete read. See the recovery contract in
 * cisco_execute (driver_cisco.c).
 */
bool cisco_is_mode_changing(const char *command, cisco_mode_t mode);

#ifdef __cplusplus
}
#endif
#endif /* VIRP_DRIVER_CISCO_MODES_H */
