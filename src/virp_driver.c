/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Driver Registry — simple static array, no dynamic allocation
 */

#include "virp_driver.h"
#include <string.h>

static virp_driver_t registry[VIRP_DRIVER_MAX];
static int registry_count = 0;

virp_error_t virp_driver_register(const virp_driver_t *driver)
{
    if (!driver)
        return VIRP_ERR_NULL_PTR;
    if (registry_count >= VIRP_DRIVER_MAX)
        return VIRP_ERR_MESSAGE_TOO_LARGE;  /* Registry full */

    /* Check for duplicate vendor */
    for (int i = 0; i < registry_count; i++) {
        if (registry[i].vendor == driver->vendor)
            return VIRP_ERR_INVALID_TYPE;   /* Already registered */
    }

    memcpy(&registry[registry_count], driver, sizeof(virp_driver_t));
    registry_count++;
    return VIRP_OK;
}

const virp_driver_t *virp_driver_lookup(virp_vendor_t vendor)
{
    for (int i = 0; i < registry_count; i++) {
        if (registry[i].vendor == vendor)
            return &registry[i];
    }
    return NULL;
}

int virp_driver_count(void)
{
    return registry_count;
}
