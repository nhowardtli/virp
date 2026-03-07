/*
 * virp_onode_json.c — Load devices from JSON config file
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "virp_onode.h"
#include "virp_driver.h"

/* Simple JSON string extractor (reuse pattern from onode) */
static bool jx_string(const char *json, const char *key, char *out, size_t out_sz)
{
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return false;
    p += strlen(pattern);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (*p != '"') return false;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < out_sz - 1)
        out[i++] = *p++;
    out[i] = '\0';
    return i > 0;
}

static uint32_t jx_uint32(const char *json, const char *key, uint32_t def)
{
    char val[32];
    if (!jx_string(json, key, val, sizeof(val))) return def;
    return (uint32_t)strtoul(val, NULL, 16);
}

static int jx_int(const char *json, const char *key, int def)
{
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return def;
    p += strlen(pattern);
    while (*p == ' ' || *p == ':' || *p == '\t') p++;
    if (*p == '"') { /* quoted number */
        p++;
        return atoi(p);
    }
    return atoi(p);
}

int onode_load_devices_json(onode_state_t *state, const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[O-Node] Cannot open devices file: %s\n", path);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = malloc(sz + 1);
    if (!buf) { fclose(f); return -1; }
    size_t rd = fread(buf, 1, sz, f);
    (void)rd;
    buf[sz] = '\0';
    fclose(f);

    int count = 0;

    /* Find each device object by scanning for "hostname" */
    const char *p = buf;
    while ((p = strstr(p, "\"hostname\"")) != NULL) {
        /* Find the enclosing { } for this device */
        const char *start = p;
        while (start > buf && *start != '{') start--;
        const char *end = strchr(p, '}');
        if (!end) break;

        /* Extract into temp buffer */
        size_t len = end - start + 1;
        char *dev_json = malloc(len + 1);
        memcpy(dev_json, start, len);
        dev_json[len] = '\0';

        virp_device_t device;
        memset(&device, 0, sizeof(device));

        jx_string(dev_json, "hostname", device.hostname, sizeof(device.hostname));
        jx_string(dev_json, "host", device.host, sizeof(device.host));
        jx_string(dev_json, "username", device.username, sizeof(device.username));
        jx_string(dev_json, "password", device.password, sizeof(device.password));
        jx_string(dev_json, "enable", device.enable_password, sizeof(device.enable_password));

        device.port = jx_int(dev_json, "port", 22);
        device.node_id = jx_uint32(dev_json, "node_id", 0);
        device.enabled = true;

        /* Determine vendor */
        char vendor_str[32] = {0};
        jx_string(dev_json, "vendor", vendor_str, sizeof(vendor_str));
        if (strstr(vendor_str, "cisco"))
            device.vendor = VIRP_VENDOR_CISCO_IOS;
        else if (strstr(vendor_str, "forti"))
            device.vendor = VIRP_VENDOR_FORTINET;
        else if (strstr(vendor_str, "panos") || strstr(vendor_str, "paloalto"))
            device.vendor = VIRP_VENDOR_PALOALTO;
        else if (strstr(vendor_str, "linux"))
            device.vendor = VIRP_VENDOR_LINUX;
        else if (strstr(vendor_str, "mock"))
            device.vendor = VIRP_VENDOR_MOCK;
        else
            device.vendor = VIRP_VENDOR_CISCO_IOS; /* default for lab */

        onode_add_device(state, &device);
        count++;

        free(dev_json);
        p = end + 1;
    }

    free(buf);
    fprintf(stderr, "[O-Node] Loaded %d devices from %s\n", count, path);
    return count;
}
