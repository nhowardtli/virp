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

#ifdef __cplusplus
}
#endif
#endif /* VIRP_DRIVER_FORTIGATE_H */
