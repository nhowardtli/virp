/*
 * driver_panos.h — PAN-OS device driver for VIRP
 *
 * SSH-only driver for Palo Alto Networks firewalls.
 * PAN-OS CLI over SSH (operational mode, plain text output).
 *
 * Prompt format: username@hostname> (operational)
 * No enable mode needed — all operational commands available at login.
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#ifndef DRIVER_PANOS_H
#define DRIVER_PANOS_H

#include "virp_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -- Command routing table entry ----------------------------------------- */
typedef struct {
    const char         *command_pattern;
    virp_trust_tier_t   tier;
    /*
     * Opt-in prefix matching. Default false (zero-filled by every
     * existing brace initializer) means the pattern must end on a token
     * boundary — end-of-string, space or tab.
     *
     * true additionally allows the remainder to attach with NO space,
     * for PAN-OS entries whose interface unit is suffixed directly onto
     * the type name ("show interface ethernet" -> "ethernet1/1"). The
     * remainder is restricted to [A-Za-z0-9._/-]; anything else still
     * fails the boundary.
     *
     * This can never let a prefix entry absorb a second command: the
     * shared separator policy rejects every separator in the WHOLE
     * string before this table is consulted, so the remainder is
     * guaranteed separator-free and can only be arguments to the one
     * command. The flag widens what counts as a token boundary, not
     * what counts as a single command.
     *
     * A lint in the table-driven test suite REJECTS prefix=true on any
     * GREEN/YELLOW entry that is a prefix of a more sensitive entry.
     */
    bool                prefix;
} pa_command_route_t;

/* -- PAN-OS-specific error codes (extend virp_error_t range) ------------- */
#define PA_ERR_NOT_CONNECTED    ((virp_error_t)(-200))
#define PA_ERR_TRANSPORT        ((virp_error_t)(-201))
#define PA_ERR_AUTH             ((virp_error_t)(-202))

/* -- Public API ---------------------------------------------------------- */

/* Driver init — call once at startup to register with driver registry */
void virp_driver_paloalto_init(void);

/* Command routing — maps CLI command to trust tier */
virp_trust_tier_t pa_route_command(const char *command);

/* Exported for tests */
extern const size_t PA_ROUTE_TABLE_SIZE;
extern const pa_command_route_t PA_ROUTE_TABLE[];

#ifdef __cplusplus
}
#endif
#endif /* DRIVER_PANOS_H */
