/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Driver Registry — simple static array, no dynamic allocation
 */

#include "virp_driver.h"
#include <string.h>
#include <openssl/sha.h>

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

const char *virp_disposition_str(virp_disposition_t d)
{
    switch (d) {
    case VIRP_DISPOSITION_UNSET:              return "UNSET";
    case VIRP_DISPOSITION_NOT_DISPATCHED:     return VIRP_DISPOSITION_NAME_NOT_DISPATCHED;
    case VIRP_DISPOSITION_EXECUTED_CONFIRMED: return VIRP_DISPOSITION_NAME_EXECUTED_CONFIRMED;
    case VIRP_DISPOSITION_EXECUTED_FAILED:    return VIRP_DISPOSITION_NAME_EXECUTED_FAILED;
    case VIRP_DISPOSITION_EXECUTED_UNKNOWN:   return VIRP_DISPOSITION_NAME_EXECUTED_UNKNOWN;
    }
    return "INVALID";
}

virp_disposition_t virp_disposition_parse(const char *name)
{
    if (!name) return VIRP_DISPOSITION_UNSET;
    if (strcmp(name, VIRP_DISPOSITION_NAME_NOT_DISPATCHED) == 0)
        return VIRP_DISPOSITION_NOT_DISPATCHED;
    if (strcmp(name, VIRP_DISPOSITION_NAME_EXECUTED_CONFIRMED) == 0)
        return VIRP_DISPOSITION_EXECUTED_CONFIRMED;
    if (strcmp(name, VIRP_DISPOSITION_NAME_EXECUTED_FAILED) == 0)
        return VIRP_DISPOSITION_EXECUTED_FAILED;
    if (strcmp(name, VIRP_DISPOSITION_NAME_EXECUTED_UNKNOWN) == 0)
        return VIRP_DISPOSITION_EXECUTED_UNKNOWN;
    return VIRP_DISPOSITION_UNSET;
}

bool virp_disposition_persistable(virp_disposition_t d)
{
    return d == VIRP_DISPOSITION_NOT_DISPATCHED ||
           d == VIRP_DISPOSITION_EXECUTED_CONFIRMED ||
           d == VIRP_DISPOSITION_EXECUTED_FAILED ||
           d == VIRP_DISPOSITION_EXECUTED_UNKNOWN;
}

const char *virp_disposition_success_json(virp_disposition_t d)
{
    switch (d) {
    case VIRP_DISPOSITION_EXECUTED_CONFIRMED: return "true";
    case VIRP_DISPOSITION_EXECUTED_FAILED:    return "false";
    default:                                  return "null";
    }
}

bool virp_disposition_may_have_executed(virp_disposition_t d)
{
    return d != VIRP_DISPOSITION_NOT_DISPATCHED;
}

virp_disposition_t virp_disposition_resolve(const virp_exec_result_t *r,
                                            virp_error_t err)
{
    /* Rule 1: the driver threw, or there is nothing to read. */
    if (!r || err != VIRP_OK)
        return VIRP_DISPOSITION_EXECUTED_UNKNOWN;

    /* Rule 2: the retry predicate, verbatim. */
    if (!r->success && r->no_dispatch)
        return VIRP_DISPOSITION_NOT_DISPATCHED;

    /* Rule 3: a converted driver classified its own termination. */
    switch (r->disposition) {
    case VIRP_DISPOSITION_EXECUTED_CONFIRMED:
    case VIRP_DISPOSITION_EXECUTED_FAILED:
    case VIRP_DISPOSITION_EXECUTED_UNKNOWN:
        return r->disposition;
    case VIRP_DISPOSITION_NOT_DISPATCHED:
        /* Claimed not sent, but did not grant the retry license: the
         * driver contradicts itself. Read it the conservative way. */
        return VIRP_DISPOSITION_EXECUTED_UNKNOWN;
    case VIRP_DISPOSITION_UNSET:
        break;
    }

    /* Rule 4: unconverted driver — the legacy success/output rules. */
    if (r->success)
        return VIRP_DISPOSITION_EXECUTED_CONFIRMED;
    if (r->output_len == 0)
        return VIRP_DISPOSITION_EXECUTED_UNKNOWN;
    return VIRP_DISPOSITION_EXECUTED_FAILED;
}

uint64_t virp_device_id_from_hostname(const char *hostname)
{
    if (!hostname)
        return 0;

    uint8_t digest[32];
    SHA256((const uint8_t *)hostname, strlen(hostname), digest);

    uint64_t id = 0;
    for (int i = 0; i < 8; i++)
        id = (id << 8) | digest[i];
    return id;
}
