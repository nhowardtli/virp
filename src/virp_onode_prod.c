/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * O-Node Production Main — loads devices from JSON config
 *
 * Usage:
 *   virp-onode-prod [options]
 *     -k <okey_path>      Path to O-Key file (generates if absent)
 *     -K <prev_okey_path> Previous O-Key, VERIFY-ONLY, for the rotation
 *                         grace window. Lets observations minted before a
 *                         rotation still register instead of being lost.
 *                         NOT for compromise-driven rotation — the window
 *                         keeps honouring that key for its duration.
 *     -W <seconds>        Grace window length (default 900). Only with -K.
 *     -s <socket_path>    Unix socket path (default: /run/virp/onode.sock)
 *     -d <devices_json>   Path to devices.json config
 *     -n <node_id_hex>    Node ID in hex (default: 0x00000001)
 *     -h                  Show help
 *
 * Compiled separately against libvirp.a. Does NOT modify existing sources.
 */

#define _POSIX_C_SOURCE 200809L

#include "virp_onode.h"
#include "virp_crypto.h"   /* virp_crypto_harden_process */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strcasecmp for gate_mode / gate_max_tier parsing */
#include <signal.h>
#include <getopt.h>
#include <json-c/json.h>

/*
 * Everything between here and the end of main() is the daemon's process
 * entry point. The issue-#7 regression test links the parser (above) into
 * the test binary by compiling this same source with
 * -DVIRP_ONODE_PROD_NO_MAIN, which excludes the daemon scaffolding so
 * there's no duplicate main()/g_state and no unused-static warnings.
 */
#ifndef VIRP_ONODE_PROD_NO_MAIN

static onode_state_t g_state;

/* Forward declare drivers */
extern void virp_driver_mock_init(void);
#ifdef VIRP_DRIVER_CISCO
extern void virp_driver_cisco_init(void);
#endif
#ifdef VIRP_DRIVER_FORTINET
extern void virp_driver_fortinet_init(void);
#endif
#ifdef VIRP_DRIVER_LINUX
extern void virp_driver_linux_init(void);
/*
 * Register a device's protected VMIDs with the linux gate classifier.
 * The route_command() hook receives a command and no device, so the
 * classifier cannot look this up per-device at decision time — the
 * loader pushes it in at startup instead, and the classifier holds the
 * union across devices. Returns -1 on an unparseable list.
 */
extern int linux_gate_set_protected_vmids(const char *csv);
#endif
#ifdef VIRP_DRIVER_WAZUH
extern int wazuh_gate_set_protected_agents(const char *csv);
#endif
#ifdef VIRP_DRIVER_PALOALTO
extern void virp_driver_paloalto_init(void);
#endif
#ifdef VIRP_DRIVER_CISCO_ASA
extern void virp_driver_asa_init(void);
#endif
#ifdef VIRP_DRIVER_WAZUH
extern void virp_driver_wazuh_init(void);
#include <curl/curl.h>
#endif
#ifdef VIRP_DRIVER_LIBRENMS
extern void virp_driver_librenms_init(void);
#ifndef VIRP_DRIVER_WAZUH
#include <curl/curl.h>
#endif
#endif
#ifdef VIRP_DRIVER_JUNIPER
extern void virp_driver_juniper_init(void);
#endif
#ifdef VIRP_DRIVER_PBS
extern void virp_driver_pbs_init(void);
#if !defined(VIRP_DRIVER_WAZUH) && !defined(VIRP_DRIVER_LIBRENMS)
#include <curl/curl.h>
#endif
#endif
#ifdef VIRP_DRIVER_ZAMMAD
extern void virp_driver_zammad_init(void);
#if !defined(VIRP_DRIVER_WAZUH) && !defined(VIRP_DRIVER_LIBRENMS) && \
    !defined(VIRP_DRIVER_PBS)
#include <curl/curl.h>
#endif
#endif

static void signal_handler(int sig)
{
    (void)sig;
    fprintf(stderr, "\n[O-Node] Signal received, shutting down...\n");
    onode_shutdown(&g_state);
}

#endif  /* !VIRP_ONODE_PROD_NO_MAIN — end of daemon scaffolding */

/* =========================================================================
 * Load devices from JSON config file
 *
 * Format:
 * {
 *   "devices": [
 *     {
 *       "hostname": "R1",
 *       "host": "198.51.100.1",
 *       "port": 22,
 *       "vendor": "cisco_ios",
 *       "username": "virp-agent",
 *       "password": "secret",
 *       "enable": "secret",
 *       "node_id": "01010101"
 *     }
 *   ]
 * }
 * ========================================================================= */

static virp_vendor_t vendor_from_string(const char *s)
{
    if (!s) return VIRP_VENDOR_UNKNOWN;
    if (strcmp(s, "cisco_ios") == 0) return VIRP_VENDOR_CISCO_IOS;
    if (strcmp(s, "cisco") == 0)     return VIRP_VENDOR_CISCO_IOS;
    if (strcmp(s, "cisco_iosxe") == 0) return VIRP_VENDOR_CISCO_IOSXE;
    if (strcmp(s, "fortinet") == 0)  return VIRP_VENDOR_FORTINET;
    if (strcmp(s, "linux") == 0)     return VIRP_VENDOR_LINUX;
    if (strcmp(s, "juniper") == 0)   return VIRP_VENDOR_JUNIPER;
    if (strcmp(s, "paloalto") == 0)  return VIRP_VENDOR_PALOALTO;
    if (strcmp(s, "panos") == 0)     return VIRP_VENDOR_PALOALTO;
    if (strcmp(s, "windows") == 0)   return VIRP_VENDOR_WINDOWS;
    if (strcmp(s, "proxmox") == 0)   return VIRP_VENDOR_PROXMOX;
    if (strcmp(s, "cisco_asa") == 0) return VIRP_VENDOR_CISCO_ASA;
    if (strcmp(s, "wazuh") == 0)     return VIRP_VENDOR_WAZUH;
    if (strcmp(s, "librenms") == 0)  return VIRP_VENDOR_LIBRENMS;
    if (strcmp(s, "pbs") == 0)       return VIRP_VENDOR_PBS;
    if (strcmp(s, "zammad") == 0)    return VIRP_VENDOR_ZAMMAD;
    if (strcmp(s, "mock") == 0)      return VIRP_VENDOR_MOCK;
    return VIRP_VENDOR_UNKNOWN;
}

/*
 * Type-checked JSON accessors. Each returns true only when the key is
 * present AND the value has the expected type. Wrong-type values are
 * reported as absent so the caller's destination is left untouched.
 *
 * Why: bare json_object_get_string(val) returns NULL when val is not a
 * JSON string, and snprintf("%s", NULL) is undefined behaviour — on glibc
 * it segfaults. A config with e.g. "enable": 0 took the daemon down at
 * startup before this guard existed (issue #7).
 *
 * Mirrors json_get_string() in virp_onode_main.c and the safe pattern
 * already used by load_socket_path_override() above.
 */
static bool json_get_string(struct json_object *obj, const char *key,
                            char *out, size_t out_sz)
{
    struct json_object *val;
    if (!json_object_object_get_ex(obj, key, &val)) return false;
    if (!json_object_is_type(val, json_type_string)) return false;
    const char *s = json_object_get_string(val);
    if (!s) return false;
    snprintf(out, out_sz, "%s", s);
    return true;
}

static bool json_get_int(struct json_object *obj, const char *key, int *out)
{
    struct json_object *val;
    if (!json_object_object_get_ex(obj, key, &val)) return false;
    if (!json_object_is_type(val, json_type_int)) return false;
    *out = json_object_get_int(val);
    return true;
}

static bool json_get_bool(struct json_object *obj, const char *key, bool *out)
{
    struct json_object *val;
    if (!json_object_object_get_ex(obj, key, &val)) return false;
    if (!json_object_is_type(val, json_type_boolean)) return false;
    *out = json_object_get_boolean(val);
    return true;
}

/*
 * Parse the top-level `socket_allowed_uids` array from the config and
 * install it on the O-Node state. Absent array → state is left untouched
 * and onode_start() will self-seed with geteuid().
 */
static void load_socket_allowed_uids(onode_state_t *state,
                                     struct json_object *root)
{
    struct json_object *arr;
    if (!json_object_object_get_ex(root, "socket_allowed_uids", &arr) ||
        !json_object_is_type(arr, json_type_array)) {
        return;  /* optional */
    }

    int n = (int)json_object_array_length(arr);
    if (n <= 0) return;
    if (n > ONODE_MAX_ALLOWED_UIDS) {
        fprintf(stderr, "[O-Node] socket_allowed_uids has %d entries, "
                        "truncating to %d\n", n, ONODE_MAX_ALLOWED_UIDS);
        n = ONODE_MAX_ALLOWED_UIDS;
    }

    uid_t uids[ONODE_MAX_ALLOWED_UIDS];
    int parsed = 0;
    for (int i = 0; i < n; i++) {
        struct json_object *el = json_object_array_get_idx(arr, i);
        if (!el) continue;
        if (json_object_is_type(el, json_type_int)) {
            uids[parsed++] = (uid_t)json_object_get_int(el);
        } else if (json_object_is_type(el, json_type_string)) {
            uids[parsed++] = (uid_t)strtoul(json_object_get_string(el),
                                            NULL, 10);
        }
    }
    if (parsed > 0)
        onode_set_allowed_uids(state, uids, (size_t)parsed);
}

/*
 * Parse the optional top-level `socket_uid_tier_ceilings` object and
 * install per-uid tier ceilings. Shape:
 *
 *   "socket_uid_tier_ceilings": { "993": "green", "1002": "yellow" }
 *
 * Keys are uid strings (matching how socket_allowed_uids may be given as
 * strings); values are "green"/"yellow"/"red". Absent object → no
 * ceilings, every allowed uid keeps the node-wide gate_max_tier. A
 * ceiling for a uid NOT on the allowlist is warned about and skipped —
 * it could never take effect (the connection is refused at accept), so
 * silently keeping it would mislead an auditor reading the config.
 */
static void load_uid_tier_ceilings(onode_state_t *state,
                                   struct json_object *root)
{
    struct json_object *obj;
    if (!json_object_object_get_ex(root, "socket_uid_tier_ceilings", &obj) ||
        !json_object_is_type(obj, json_type_object)) {
        return;  /* optional */
    }

    uid_t uids[ONODE_MAX_ALLOWED_UIDS];
    virp_trust_tier_t tiers[ONODE_MAX_ALLOWED_UIDS];
    size_t count = 0;

    json_object_object_foreach(obj, key, val) {
        if (count >= ONODE_MAX_ALLOWED_UIDS) {
            fprintf(stderr, "[O-Node] socket_uid_tier_ceilings: too many "
                            "entries, ignoring '%s' and beyond\n", key);
            break;
        }
        if (!json_object_is_type(val, json_type_string)) {
            fprintf(stderr, "[O-Node] socket_uid_tier_ceilings['%s']: value "
                            "is not a tier string — skipping\n", key);
            continue;
        }
        char *end = NULL;
        unsigned long uidv = strtoul(key, &end, 10);
        if (!end || *end != '\0') {
            fprintf(stderr, "[O-Node] socket_uid_tier_ceilings key '%s' is "
                            "not a numeric uid — skipping\n", key);
            continue;
        }
        const char *s = json_object_get_string(val);
        virp_trust_tier_t tier;
        if      (strcasecmp(s, "green")  == 0) tier = VIRP_TIER_GREEN;
        else if (strcasecmp(s, "yellow") == 0) tier = VIRP_TIER_YELLOW;
        else if (strcasecmp(s, "red")    == 0) tier = VIRP_TIER_RED;
        else {
            fprintf(stderr, "[O-Node] socket_uid_tier_ceilings['%s'] = '%s' "
                            "unrecognized (want green/yellow/red) — "
                            "skipping\n", key, s);
            continue;
        }

        /* Warn if this uid is not on the allowlist — the ceiling is inert. */
        bool allowed = false;
        for (size_t i = 0; i < state->socket_allowed_uids_count; i++)
            if (state->socket_allowed_uids[i] == (uid_t)uidv) { allowed = true; break; }
        if (!allowed)
            fprintf(stderr, "[O-Node] socket_uid_tier_ceilings: uid %lu is "
                            "not in socket_allowed_uids — ceiling has no "
                            "effect (connection would be refused)\n", uidv);

        uids[count]  = (uid_t)uidv;
        tiers[count] = tier;
        count++;
    }

    if (count > 0) {
        virp_error_t err = onode_set_uid_ceilings(state, uids, tiers, count);
        if (err != VIRP_OK)
            fprintf(stderr, "[O-Node] onode_set_uid_ceilings failed: %d\n",
                    (int)err);
    }
}

/*
 * Parse the optional top-level `socket_uid_action_allow` object (Item
 * 8) and install per-uid action allowlists. Shape:
 *
 *   "socket_uid_action_allow": {
 *       "993": ["list_fleet", "health", "chain_verify", "chain_append"]
 *   }
 *
 * Keys are uid strings; values are arrays of wire action names (the
 * same names the request parser accepts — one shared table). A uid
 * absent from the object is completely unrestricted by this map, so a
 * malformed entry must NEVER fall back to "skip" the way the ceilings
 * parser does: skipping would leave the uid the operator meant to
 * restrict fully unrestricted. Fail-closed instead — any malformed
 * value or unknown action name installs a DENY-ALL entry for that uid
 * and logs loudly; the uid keeps connecting but can do nothing until
 * the config is fixed. A non-numeric key names no uid to restrict and
 * is logged as an ERROR.
 */
static void load_uid_action_allow(onode_state_t *state,
                                  struct json_object *root)
{
    struct json_object *obj;
    if (!json_object_object_get_ex(root, "socket_uid_action_allow", &obj) ||
        !json_object_is_type(obj, json_type_object)) {
        return;  /* optional */
    }

    json_object_object_foreach(obj, key, val) {
        char *end = NULL;
        unsigned long uidv = strtoul(key, &end, 10);
        if (!end || *end != '\0') {
            fprintf(stderr, "[O-Node] ERROR: socket_uid_action_allow key "
                            "'%s' is not a numeric uid — this entry "
                            "restricts NOBODY; fix the config\n", key);
            continue;
        }

        onode_action_t actions[ONODE_MAX_UID_ACTIONS];
        size_t count = 0;
        bool malformed = false;

        if (!json_object_is_type(val, json_type_array)) {
            malformed = true;
        } else {
            size_t alen = (size_t)json_object_array_length(val);
            if (alen > ONODE_MAX_UID_ACTIONS) {
                malformed = true;
            } else {
                for (size_t i = 0; i < alen; i++) {
                    struct json_object *a =
                        json_object_array_get_idx(val, i);
                    const char *name =
                        json_object_is_type(a, json_type_string)
                            ? json_object_get_string(a) : NULL;
                    onode_action_t act =
                        name ? onode_action_from_name(name)
                             : (onode_action_t)0;
                    if ((int)act == 0) {
                        fprintf(stderr, "[O-Node] socket_uid_action_allow"
                                "['%s']: '%s' is not an action name\n",
                                key, name ? name : "(not a string)");
                        malformed = true;
                        break;
                    }
                    actions[count++] = act;
                }
            }
        }

        if (malformed) {
            fprintf(stderr, "[O-Node] ERROR: socket_uid_action_allow['%s'] "
                            "is malformed — installing DENY-ALL for uid "
                            "%lu (fail closed) until the config is "
                            "fixed\n", key, uidv);
            count = 0;
        }

        virp_error_t err = onode_set_uid_actions(state, (uid_t)uidv,
                                                 actions, count);
        if (err != VIRP_OK) {
            fprintf(stderr, "[O-Node] onode_set_uid_actions(uid %lu) "
                            "failed: %d\n", uidv, (int)err);
            continue;
        }
        fprintf(stderr, "[O-Node] uid %lu action allowlist: %zu "
                        "action(s)%s\n", uidv, count,
                count == 0 ? " (DENY-ALL)" : "");

        /* Same audit courtesy as the ceilings: an entry for a uid the
         * socket allowlist refuses at accept() is inert. */
        bool allowed = false;
        for (size_t i = 0; i < state->socket_allowed_uids_count; i++)
            if (state->socket_allowed_uids[i] == (uid_t)uidv)
                { allowed = true; break; }
        if (!allowed)
            fprintf(stderr, "[O-Node] socket_uid_action_allow: uid %lu is "
                            "not in socket_allowed_uids — allowlist has "
                            "no effect (connection would be refused)\n",
                    uidv);
    }
}

/*
 * Parse the optional top-level `socket_path` override. If present, it
 * takes precedence over the -s CLI argument. This lets operators move
 * the socket (e.g. when redirecting the socat bridge) by editing the
 * config file only.
 *
 * Returns a malloc'd copy the caller must free, or NULL.
 */
static char *load_socket_path_override(struct json_object *root)
{
    struct json_object *val;
    if (!json_object_object_get_ex(root, "socket_path", &val) ||
        !json_object_is_type(val, json_type_string))
        return NULL;
    const char *s = json_object_get_string(val);
    return (s && *s) ? strdup(s) : NULL;
}

/* Parse a gate mode string ("shadow"/"enforce"). Returns true on success. */
static bool parse_gate_mode(const char *s, onode_gate_mode_t *out)
{
    if (strcasecmp(s, "enforce") == 0) { *out = GATE_MODE_ENFORCE; return true; }
    if (strcasecmp(s, "shadow")  == 0) { *out = GATE_MODE_SHADOW;  return true; }
    return false;
}

/*
 * Parse the optional tier-enforcement gate config (per-driver scoped):
 *
 *   "gate_max_tier":     "green" | "yellow" (default) | "red"
 *   "gate_default_mode": "shadow" | "enforce" (default)   -- applied to any
 *                        driver not named in gate_modes
 *   "gate_modes":        { "<driver>": "shadow"|"enforce", ... }  -- optional
 *                        per-driver overrides, keyed by driver name
 *                        (e.g. "fortigate", "cisco_ios", "cisco_asa",
 *                        "juniper", "panos", "linux", "proxmox", "wazuh").
 *
 * ("gate_mode" is accepted as a deprecated alias for gate_default_mode.)
 *
 * Absent keys leave the onode_init() defaults (ENFORCE default / no
 * overrides / YELLOW) in place. Unrecognized values are logged and ignored.
 */
static void load_gate_config(onode_state_t *state, struct json_object *root)
{
    struct json_object *v;

    /* Max tier. */
    if (json_object_object_get_ex(root, "gate_max_tier", &v) &&
        json_object_is_type(v, json_type_string)) {
        const char *s = json_object_get_string(v);
        if      (strcasecmp(s, "green")  == 0) state->gate_max_tier = VIRP_TIER_GREEN;
        else if (strcasecmp(s, "yellow") == 0) state->gate_max_tier = VIRP_TIER_YELLOW;
        else if (strcasecmp(s, "red")    == 0) state->gate_max_tier = VIRP_TIER_RED;
        else fprintf(stderr, "[O-Node] gate_max_tier '%s' unrecognized — "
                             "keeping YELLOW\n", s);
    }

    /* Default mode: gate_default_mode (canonical) or gate_mode (deprecated). */
    if (json_object_object_get_ex(root, "gate_default_mode", &v) &&
        json_object_is_type(v, json_type_string)) {
        const char *s = json_object_get_string(v);
        if (!parse_gate_mode(s, &state->gate_default_mode))
            fprintf(stderr, "[O-Node] gate_default_mode '%s' unrecognized — "
                            "keeping ENFORCE default\n", s);
    } else if (json_object_object_get_ex(root, "gate_mode", &v) &&
               json_object_is_type(v, json_type_string)) {
        const char *s = json_object_get_string(v);
        if (parse_gate_mode(s, &state->gate_default_mode))
            fprintf(stderr, "[O-Node] gate_mode is deprecated — "
                            "use gate_default_mode\n");
        else
            fprintf(stderr, "[O-Node] gate_mode '%s' unrecognized — "
                            "keeping ENFORCE default\n", s);
    }

    /* Per-driver overrides. */
    if (json_object_object_get_ex(root, "gate_modes", &v) &&
        json_object_is_type(v, json_type_object)) {
        json_object_object_foreach(v, drv_name, mode_obj) {
            if (!json_object_is_type(mode_obj, json_type_string))
                continue;
            if (state->gate_overrides_count >= ONODE_MAX_GATE_OVERRIDES) {
                fprintf(stderr, "[O-Node] gate_modes: override limit reached, "
                                "ignoring '%s'\n", drv_name);
                continue;
            }
            onode_gate_mode_t m;
            const char *ms = json_object_get_string(mode_obj);
            if (!parse_gate_mode(ms, &m)) {
                fprintf(stderr, "[O-Node] gate_modes['%s']='%s' unrecognized — "
                                "ignoring\n", drv_name, ms);
                continue;
            }
            size_t idx = state->gate_overrides_count++;
            snprintf(state->gate_overrides[idx].driver,
                     sizeof(state->gate_overrides[idx].driver), "%s", drv_name);
            state->gate_overrides[idx].mode = m;
        }
    }

    /* Log resolved posture. */
    fprintf(stderr, "[O-Node] tier gate: default=%s max_tier=%s overrides=%zu\n",
            state->gate_default_mode == GATE_MODE_ENFORCE ? "ENFORCE" : "SHADOW",
            state->gate_max_tier == VIRP_TIER_GREEN  ? "GREEN"  :
            state->gate_max_tier == VIRP_TIER_RED    ? "RED"    : "YELLOW",
            state->gate_overrides_count);
    for (size_t i = 0; i < state->gate_overrides_count; i++)
        fprintf(stderr, "[O-Node]   override: %s=%s\n",
                state->gate_overrides[i].driver,
                state->gate_overrides[i].mode == GATE_MODE_ENFORCE
                    ? "ENFORCE" : "SHADOW");
}

/*
 * Not static: the issue #7 regression test in tests/test_onode.c links
 * against the prod parser (via the *_lib.o object compiled with
 * VIRP_ONODE_PROD_NO_MAIN) and calls this directly.
 */
int load_devices(onode_state_t *state, const char *path)
{
    /* Autopilot hard exclusion — non-negotiable: refuse the entire
     * config if it mentions a blocked address anywhere. */
    const char *blocked = virp_config_file_blocked(path);
    if (blocked) {
        fprintf(stderr, "[O-Node] FATAL: device config %s contains "
                "hard-excluded address %s — refusing to load\n",
                path, blocked);
        return -1;
    }

    struct json_object *root = json_object_from_file(path);
    if (!root) {
        fprintf(stderr, "[O-Node] Failed to parse device config: %s\n", path);
        return -1;
    }

    /* Socket access gate: install allowlist before onode_start(). */
    load_socket_allowed_uids(state, root);

    /* Per-uid tier ceilings (optional). Installed before onode_start(),
     * after the allowlist so it can warn about a ceiling for a uid that
     * is not allowed to connect. */
    load_uid_tier_ceilings(state, root);
    load_uid_action_allow(state, root);

    /* Tier-enforcement gate (Phase B): override SHADOW/YELLOW defaults
     * from config if present. Installed before onode_start(). */
    load_gate_config(state, root);

    /*
     * Optional socket_path override from config. Takes precedence over
     * the -s CLI flag so operators can move the socket (for the socat
     * bridge in particular) by editing the JSON alone.
     */
    char *sock_override = load_socket_path_override(root);
    if (sock_override) {
        snprintf(state->socket_path, sizeof(state->socket_path), "%s",
                 sock_override);
        fprintf(stderr, "[O-Node] socket_path from config: %s\n",
                state->socket_path);
        free(sock_override);
    }

    struct json_object *devices_arr;
    if (!json_object_object_get_ex(root, "devices", &devices_arr) ||
        !json_object_is_type(devices_arr, json_type_array)) {
        fprintf(stderr, "[O-Node] Config missing 'devices' array\n");
        json_object_put(root);
        return -1;
    }

    int count = (int)json_object_array_length(devices_arr);
    int loaded = 0;

    for (int i = 0; i < count; i++) {
        struct json_object *dev_obj = json_object_array_get_idx(devices_arr, i);
        if (!dev_obj || !json_object_is_type(dev_obj, json_type_object))
            continue;

        virp_device_t device;
        memset(&device, 0, sizeof(device));
        device.enabled = true;
        device.port = 22;

        json_get_string(dev_obj, "hostname", device.hostname,
                        sizeof(device.hostname));
        json_get_string(dev_obj, "host",     device.host,
                        sizeof(device.host));
        json_get_string(dev_obj, "username", device.username,
                        sizeof(device.username));
        json_get_string(dev_obj, "password", device.password,
                        sizeof(device.password));
        json_get_string(dev_obj, "enable",   device.enable_password,
                        sizeof(device.enable_password));

        int port_val;
        if (json_get_int(dev_obj, "port", &port_val))
            device.port = (uint16_t)port_val;

        char vendor_str[32] = {0};
        if (json_get_string(dev_obj, "vendor", vendor_str, sizeof(vendor_str)))
            device.vendor = vendor_from_string(vendor_str);

        /*
         * node_id accepts either a hex string ("0A0000FD") or a JSON int,
         * matching virp_onode_main.c's dev parser. Other JSON types are
         * silently ignored (treated as absent) — pre-fix code dereferenced
         * a NULL string here when the value was an int/bool/null.
         */
        struct json_object *nid_val;
        if (json_object_object_get_ex(dev_obj, "node_id", &nid_val)) {
            if (json_object_is_type(nid_val, json_type_string)) {
                const char *s = json_object_get_string(nid_val);
                if (s) device.node_id = (uint32_t)strtoul(s, NULL, 16);
            } else if (json_object_is_type(nid_val, json_type_int)) {
                device.node_id = (uint32_t)json_object_get_int64(nid_val);
            }
        }

        /*
         * device_id — stable 64-bit identity bound into v2 observation
         * headers. Accepts a hex string or JSON int, mirroring node_id.
         * Absent (the common case for existing configs): derived
         * deterministically from SHA-256(hostname) after the
         * hostname-presence check below.
         */
        struct json_object *did_val;
        if (json_object_object_get_ex(dev_obj, "device_id", &did_val)) {
            if (json_object_is_type(did_val, json_type_string)) {
                const char *s = json_object_get_string(did_val);
                if (s) device.device_id = (uint64_t)strtoull(s, NULL, 16);
            } else if (json_object_is_type(did_val, json_type_int)) {
                device.device_id = (uint64_t)json_object_get_int64(did_val);
            }
        }

        /* FortiGate-specific fields (ignored for other vendors) */
        json_get_string(dev_obj, "api_token", device.api_token,
                        sizeof(device.api_token));

        int api_port_val;
        if (json_get_int(dev_obj, "api_port", &api_port_val))
            device.api_port = (uint16_t)api_port_val;

        json_get_string(dev_obj, "vdom", device.vdom, sizeof(device.vdom));

        bool bool_val;
        if (json_get_bool(dev_obj, "verify_tls", &bool_val))
            device.verify_tls = bool_val;

        if (json_get_bool(dev_obj, "ssh_legacy", &bool_val))
            device.ssh_legacy = bool_val;

        /* PBS-specific fields (ignored for other vendors).
         *
         * tls_fingerprint is the PBS driver's server identity. It is
         * deliberately NOT a verify_tls-style boolean: a boolean has a
         * value that means "don't check", and a fingerprint does not. */
        json_get_string(dev_obj, "tls_fingerprint", device.tls_fingerprint,
                        sizeof(device.tls_fingerprint));
        json_get_string(dev_obj, "datastore_allow", device.datastore_allow,
                        sizeof(device.datastore_allow));
        /*
         * write_ops_allow (Zammad): the typed write operations THIS
         * device may execute. Absent → empty → no writes, which is the
         * safe default and the read-only entry's configuration. There is
         * deliberately no "allow all" spelling.
         */
        json_get_string(dev_obj, "write_ops_allow", device.write_ops_allow,
                        sizeof(device.write_ops_allow));
        json_get_string(dev_obj, "tls_servername", device.tls_servername,
                        sizeof(device.tls_servername));

        /*
         * protected_vmids (Proxmox-on-linux): guests this gate may not
         * touch at any tier. Accepts the natural JSON spelling —
         * "protected_vmids": [313] — and an equivalent CSV string, and
         * normalizes to CSV. A malformed entry sets nothing: the
         * classifier then refuses every VMID-bearing Proxmox command,
         * which is the fail-closed reading of "this config did not
         * parse" and is loud at the first request rather than silent
         * forever.
         */
        struct json_object *pv_val;
        if (json_object_object_get_ex(dev_obj, "protected_vmids", &pv_val)) {
            if (json_object_is_type(pv_val, json_type_array)) {
                size_t used = 0;
                int n_vm = (int)json_object_array_length(pv_val);
                for (int v = 0; v < n_vm; v++) {
                    struct json_object *e = json_object_array_get_idx(pv_val, v);
                    if (!e || !json_object_is_type(e, json_type_int)) {
                        fprintf(stderr, "[O-Node] %s: protected_vmids entry %d "
                                "is not an integer — ignoring the whole list\n",
                                device.hostname, v);
                        used = 0;
                        break;
                    }
                    int written = snprintf(device.protected_vmids + used,
                                           sizeof(device.protected_vmids) - used,
                                           "%s%lld", used ? "," : "",
                                           (long long)json_object_get_int64(e));
                    if (written < 0 ||
                        (size_t)written >= sizeof(device.protected_vmids) - used) {
                        fprintf(stderr, "[O-Node] %s: protected_vmids too long "
                                "— ignoring the whole list\n", device.hostname);
                        used = 0;
                        break;
                    }
                    used += (size_t)written;
                }
                device.protected_vmids[used] = '\0';
            } else if (json_object_is_type(pv_val, json_type_string)) {
                json_get_string(dev_obj, "protected_vmids",
                                device.protected_vmids,
                                sizeof(device.protected_vmids));
            }
        }

        /*
         * protected_agents (Wazuh): agent ids the driver refuses to
         * touch at any tier. Accepts ["004","313"] (the zero-padded
         * spelling Wazuh uses in URLs), [4,313], or an equivalent CSV
         * string, and normalizes to CSV. Ids are compared numerically
         * downstream, so the paddings are interchangeable.
         *
         * Unlike protected_vmids this accepts STRING array entries as
         * well as ints, because "004" is how an operator reading the
         * Wazuh UI will naturally write it and JSON has no way to keep
         * the leading zeros on a number.
         */
        /* Guarded to match its only consumer below: without the Wazuh
         * driver compiled in there is no gate to register into, and an
         * unused-but-set variable is an error under -Werror. */
#ifdef VIRP_DRIVER_WAZUH
        bool pa_declared = false;
#endif
        struct json_object *pa_val;
        if (json_object_object_get_ex(dev_obj, "protected_agents", &pa_val)) {
#ifdef VIRP_DRIVER_WAZUH
            pa_declared = true;
#endif
            if (json_object_is_type(pa_val, json_type_array)) {
                size_t used = 0;
                int n_ag = (int)json_object_array_length(pa_val);
                for (int v = 0; v < n_ag; v++) {
                    struct json_object *e = json_object_array_get_idx(pa_val, v);
                    const char *piece = NULL;
                    char numbuf[32];
                    if (e && json_object_is_type(e, json_type_int)) {
                        snprintf(numbuf, sizeof(numbuf), "%lld",
                                 (long long)json_object_get_int64(e));
                        piece = numbuf;
                    } else if (e && json_object_is_type(e, json_type_string)) {
                        piece = json_object_get_string(e);
                    }
                    if (!piece || piece[0] == '\0') {
                        fprintf(stderr, "[O-Node] %s: protected_agents entry "
                                "%d is not an integer or string — ignoring "
                                "the whole list\n", device.hostname, v);
                        used = 0;
                        break;
                    }
                    int written = snprintf(device.protected_agents + used,
                                           sizeof(device.protected_agents) - used,
                                           "%s%s", used ? "," : "", piece);
                    if (written < 0 ||
                        (size_t)written >= sizeof(device.protected_agents) - used) {
                        fprintf(stderr, "[O-Node] %s: protected_agents too long "
                                "— ignoring the whole list\n", device.hostname);
                        used = 0;
                        break;
                    }
                    used += (size_t)written;
                }
                device.protected_agents[used] = '\0';
            } else if (json_object_is_type(pa_val, json_type_string)) {
                json_get_string(dev_obj, "protected_agents",
                                device.protected_agents,
                                sizeof(device.protected_agents));
            }
        }

        if (device.hostname[0] == '\0' || device.host[0] == '\0') {
            fprintf(stderr, "[O-Node] Skipping device %d: missing hostname/host\n", i);
            continue;
        }

        if (device.vendor == VIRP_VENDOR_UNKNOWN) {
            fprintf(stderr, "[O-Node] Skipping %s: unknown vendor\n",
                    device.hostname);
            continue;
        }

        /*
         * A PBS device without a certificate pin is a configuration
         * error, not a device to load and let fail at connect time. The
         * driver would refuse it anyway; refusing HERE makes the
         * misconfiguration visible at start rather than at first use,
         * and keeps "loaded" meaning "usable".
         */
        if (device.vendor == VIRP_VENDOR_PBS &&
            device.tls_fingerprint[0] == '\0') {
            fprintf(stderr, "[O-Node] Skipping %s: PBS device has no "
                            "tls_fingerprint — the PBS driver pins the "
                            "server certificate and has no insecure mode\n",
                    device.hostname);
            continue;
        }

#ifdef VIRP_DRIVER_LINUX
        /*
         * Push this device's protected VMIDs into the linux gate before
         * the device becomes reachable. Registration must complete at
         * load time, not at connect time: gate_classify() runs before
         * the driver ever connects, so a set populated on connect would
         * be empty for exactly the first request that needed it.
         *
         * A list that does not parse is a FATAL config error, not a
         * device to load without its protection. The whole point of the
         * field is that the guest behind it cannot be touched, and
         * loading the host anyway would leave the operator believing a
         * protection that is not in force.
         */
        if ((device.vendor == VIRP_VENDOR_LINUX ||
             device.vendor == VIRP_VENDOR_PROXMOX) &&
            device.protected_vmids[0] != '\0') {
            if (linux_gate_set_protected_vmids(device.protected_vmids) != 0) {
                fprintf(stderr, "[O-Node] FATAL: %s: unparseable "
                        "protected_vmids \"%s\" — refusing the config rather "
                        "than running without the protection it declares\n",
                        device.hostname, device.protected_vmids);
                json_object_put(root);
                return -1;
            }
        }
#endif

#ifdef VIRP_DRIVER_WAZUH
        /*
         * Push this device's protected agents into the Wazuh driver
         * before it becomes reachable, for the same reason the linux
         * gate is populated at load time: the refusal must be in force
         * for the FIRST request, not from the first connect onward.
         *
         * An unparseable list is FATAL, not a warning. The field exists
         * so that a named agent cannot be touched; loading the device
         * without it would leave the operator believing a protection
         * that is not running. Failing the whole config is the only
         * outcome that cannot be mistaken for success.
         *
         * A wazuh device that declares NO protected_agents is loaded as
         * normal — the static BLACK rules (manager configuration,
         * active-response, agent deletion) still apply. Whether an
         * unprotected wazuh device should be refused outright is a
         * policy question left to the operator, not decided here.
         */
        /*
         * A DECLARED list that normalized to nothing is fatal too.
         *
         * The array walk above drops the whole list when an entry is the
         * wrong JSON type (["004", {...}]) or when the joined CSV would
         * overflow the field. Without this arm the device then loaded
         * with an EMPTY protected set behind a single warning line — the
         * operator wrote protected_agents, saw the daemon start, and got
         * no protection at all. That is precisely the outcome the fatal
         * path exists to prevent, arriving by a different route.
         */
        if (device.vendor == VIRP_VENDOR_WAZUH &&
            pa_declared && device.protected_agents[0] == '\0') {
            fprintf(stderr, "[O-Node] FATAL: %s: protected_agents was "
                    "declared but no id survived parsing — refusing the "
                    "config rather than running without the protection it "
                    "declares\n", device.hostname);
            json_object_put(root);
            return -1;
        }

        if (device.vendor == VIRP_VENDOR_WAZUH &&
            device.protected_agents[0] != '\0') {
            if (wazuh_gate_set_protected_agents(device.protected_agents) != 0) {
                fprintf(stderr, "[O-Node] FATAL: %s: unparseable "
                        "protected_agents \"%s\" — refusing the config rather "
                        "than running without the protection it declares\n",
                        device.hostname, device.protected_agents);
                json_object_put(root);
                return -1;
            }
            fprintf(stderr, "[O-Node] %s: protected agents registered: %s\n",
                    device.hostname, device.protected_agents);
        }
#endif

        /* device_id == 0 (absent/unparseable) is derived from the
         * hostname inside onode_add_device — the single choke point. */
        virp_error_t err = onode_add_device(state, &device);
        if (err == VIRP_ERR_DUPLICATE_DEVICE) {
            /* Colliding identities are a config error, not a device to
             * skip: silently dropping one of the pair would leave which
             * ever happened to be listed first answering for both.
             * Refuse the whole config (add_device already named both
             * devices on stderr). */
            fprintf(stderr, "[O-Node] FATAL: refusing device config %s "
                    "with duplicate identities\n", path);
            json_object_put(root);
            return -1;
        }
        if (err != VIRP_OK) {
            fprintf(stderr, "[O-Node] Failed to add %s: %s\n",
                    device.hostname, virp_error_str(err));
            continue;
        }

        loaded++;
    }

    json_object_put(root);

    fprintf(stderr, "[O-Node] Loaded %d/%d devices from %s\n",
            loaded, count, path);

    return loaded;
}

/*
 * Trust chain (Primitive 6) + approval flow startup.
 *
 * Invariant enforced here: approval mode NEVER runs without a working
 * chain. A chainless approval flow issues challenges and accepts
 * approvals while writing no PROPOSAL/APPROVAL/OUTCOME history, and the
 * L1 consumed-proposal check in virp_approval.c is vacuous with a NULL
 * chain — the audit trail LIVE-PROOF-2026-07-23.md documents would
 * silently not exist. So:
 *
 *   - approval mode enabled + no chain configured  → fatal (non-VIRP_OK)
 *   - approval mode enabled + chain init failed    → fatal (non-VIRP_OK)
 *   - approval mode disabled                       → chain failure is
 *     tolerated exactly as before ("continuing without chain")
 *
 * Not static: like load_devices() above, tests/test_onode.c links this
 * via the VIRP_ONODE_PROD_NO_MAIN lib object and calls it directly.
 * Returns VIRP_OK when the daemon may start; main() exits non-zero
 * otherwise.
 */
virp_error_t onode_setup_chain_and_approvals(onode_state_t *state,
                                             uint32_t node_id,
                                             const char *chain_db_path,
                                             const char *chain_key_path,
                                             const char *approval_dir,
                                             const char *approvers_path)
{
    if (!state || !approval_dir || !approvers_path)
        return VIRP_ERR_NULL_PTR;

    bool chain_configured = (chain_db_path != NULL && chain_key_path != NULL);
    virp_error_t chain_err = VIRP_OK;

    if ((chain_db_path != NULL) != (chain_key_path != NULL))
        fprintf(stderr, "[O-Node] Warning: -c and -C must be given together "
                "— chain disabled\n");

    if (chain_configured) {
        chain_err = virp_chain_init(&state->chain, chain_db_path,
                                    chain_key_path, node_id, "local");
        if (chain_err == VIRP_OK) {
            state->chain_enabled = true;
            fprintf(stderr, "[O-Node] Trust chain enabled: db=%s\n",
                    chain_db_path);
        }
    }

    /*
     * Approval flow (propose → approve → apply). Loads the approver
     * registry (public keys only); a missing/empty registry leaves the
     * flow disabled (plain gate blocking unchanged). Enroll keys in
     * /etc/virp/approvers.json — schema and PIV enrollment in
     * docs/APPROVAL-FLOW.md.
     */
    virp_error_t aerr = onode_set_approvers(state, approval_dir,
                                            approvers_path);
    if (aerr != VIRP_OK) {
        fprintf(stderr, "[O-Node] Approval flow disabled: registry "
                "%s (%s)\n", approvers_path, virp_error_str(aerr));
        /* Non-approval mode keeps its historical chain tolerance. */
        if (chain_configured && chain_err != VIRP_OK)
            fprintf(stderr, "[O-Node] Trust chain init failed: %s "
                    "(continuing without chain)\n",
                    virp_error_str(chain_err));
        return VIRP_OK;
    }

    if (!chain_configured) {
        fprintf(stderr, "[O-Node] FATAL: approval mode is enabled (registry "
                "%s) but no trust chain is configured. Pass -c <chain.db> "
                "and -C <chain.key>. Refusing to start.\n", approvers_path);
        return VIRP_ERR_CHAIN_DB;
    }
    if (chain_err != VIRP_OK) {
        fprintf(stderr, "[O-Node] FATAL: approval mode is enabled but trust "
                "chain init failed: %s. Refusing to start.\n",
                virp_error_str(chain_err));
        return chain_err;
    }
    return VIRP_OK;
}

#ifndef VIRP_ONODE_PROD_NO_MAIN

static void usage(const char *prog)
{
    printf("\nVIRP O-Node Daemon (Production)\n");
    printf("Copyright (c) 2026 Third Level IT LLC\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -k <path>   O-Key file path (generates new key if file doesn't exist)\n");
    printf("  -K <path>   PREVIOUS O-Key, VERIFY-ONLY, for the rotation grace\n");
    printf("              window. Observations minted before a rotation and\n");
    printf("              registered after it would otherwise be refused by\n");
    printf("              chain_append and LOST. Never used to sign.\n");
    printf("              DO NOT USE if you rotated because the old key was\n");
    printf("              COMPROMISED — the window keeps honouring it.\n");
    printf("  -W <secs>   Grace window length (default 900). Only with -K.\n");
    printf("  -s <path>   Unix socket path (default: %s)\n", ONODE_SOCKET_PATH);
    printf("  -d <path>   Device config JSON file (required)\n");
    printf("  -n <hex>    Node ID in hex (default: 0x00000001)\n");
    printf("  -c <path>   Chain database path (enables Primitive 6 trust chain;\n");
    printf("              REQUIRED when approval mode is enabled — the daemon\n");
    printf("              refuses to start in approval mode without a chain)\n");
    printf("  -C <path>   Chain key path (32-byte key file, required with -c)\n");
    printf("  -a <path>   Approval store dir (default: /var/lib/virp/approvals)\n");
    printf("  -A <path>   Approver registry (default: /etc/virp/approvers.json)\n");
    printf("  -h          Show this help\n");
    printf("\n");
}

int main(int argc, char **argv)
{
    const char *okey_path = NULL;
    const char *prev_okey_path = NULL;
    uint32_t    prev_okey_window = 900;   /* 15 min; > the 5-min cycle */
    const char *socket_path = NULL;
    const char *devices_path = NULL;
    const char *chain_db_path = NULL;
    const char *chain_key_path = NULL;
    const char *approval_dir = "/var/lib/virp/approvals";
    const char *approvers_path = "/etc/virp/approvers.json";
    uint32_t node_id = 0x00000001;

    int opt;
    while ((opt = getopt(argc, argv, "k:K:W:s:d:n:c:C:a:A:h")) != -1) {
        switch (opt) {
        case 'k':
            okey_path = optarg;
            break;
        case 'K':
            prev_okey_path = optarg;
            break;
        case 'W':
            prev_okey_window = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 's':
            socket_path = optarg;
            break;
        case 'd':
            devices_path = optarg;
            break;
        case 'n':
            node_id = (uint32_t)strtoul(optarg, NULL, 16);
            break;
        case 'c':
            chain_db_path = optarg;
            break;
        case 'C':
            chain_key_path = optarg;
            break;
        case 'a':
            approval_dir = optarg;
            break;
        case 'A':
            approvers_path = optarg;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    if (!devices_path) {
        fprintf(stderr, "[O-Node] Error: -d <devices.json> is required\n");
        usage(argv[0]);
        return 1;
    }

    printf("\n");
    printf("================================================================\n");
    printf("  VIRP O-Node Daemon (Production) v0.2\n");
    printf("  Copyright (c) 2026 Third Level IT LLC\n");
    printf("================================================================\n\n");

/*
 * curl_global_init() for EVERY libcurl-backed driver, not just Wazuh.
 * This was #ifdef VIRP_DRIVER_WAZUH alone, so a build with LIBRENMS=1,
 * PBS=1 or ZAMMAD=1 and no WAZUH=1 left libcurl to initialize itself
 * lazily inside the first curl_easy_init(). Modern libcurl tolerates
 * that; relying on it is still a race the daemon does not need to run.
 */
#if defined(VIRP_DRIVER_WAZUH) || defined(VIRP_DRIVER_LIBRENMS) || \
    defined(VIRP_DRIVER_PBS)   || defined(VIRP_DRIVER_ZAMMAD)
    curl_global_init(CURL_GLOBAL_DEFAULT);
#endif

    /* Register drivers */
    virp_driver_mock_init();
#ifdef VIRP_DRIVER_CISCO
    virp_driver_cisco_init();
#endif
#ifdef VIRP_DRIVER_FORTINET
    virp_driver_fortinet_init();
#endif
#ifdef VIRP_DRIVER_LINUX
    virp_driver_linux_init();
#endif
#ifdef VIRP_DRIVER_PALOALTO
    virp_driver_paloalto_init();
#endif
#ifdef VIRP_DRIVER_CISCO_ASA
    virp_driver_asa_init();
#endif
#ifdef VIRP_DRIVER_WAZUH
    virp_driver_wazuh_init();
#endif
#ifdef VIRP_DRIVER_JUNIPER
    virp_driver_juniper_init();
#endif
#ifdef VIRP_DRIVER_LIBRENMS
    virp_driver_librenms_init();
#endif
#ifdef VIRP_DRIVER_PBS
    virp_driver_pbs_init();
#endif
#ifdef VIRP_DRIVER_ZAMMAD
    virp_driver_zammad_init();
#endif
    fprintf(stderr, "[O-Node] Registered %d driver(s)\n", virp_driver_count());

    /*
     * Harden the process before loading the key (see virp_onode_main.c
     * for rationale).
     */
    virp_crypto_harden_process();

    /* Initialize O-Node */
    virp_error_t err = onode_init(&g_state, node_id, okey_path, socket_path);
    if (err != VIRP_OK) {
        fprintf(stderr, "[O-Node] Initialization failed: %s\n",
                virp_error_str(err));
        return 1;
    }

    /*
     * Rotation grace window, if the operator asked for one. Fail the
     * START rather than run on silently: someone who passed -K believes
     * in-flight observations are protected, and a daemon that quietly
     * dropped the option would lose exactly the entries they were
     * trying to save.
     */
    if (prev_okey_path) {
        virp_error_t perr = onode_set_previous_okey(&g_state, prev_okey_path,
                                                    prev_okey_window);
        if (perr != VIRP_OK) {
            fprintf(stderr, "[O-Node] refusing to start: -K %s could not be "
                    "loaded (%s)\n", prev_okey_path, virp_error_str(perr));
            onode_destroy(&g_state);
            return 1;
        }
    }

    /*
     * Allocate the protocol context. main() owns it for the lifetime
     * of the process. virp_context_destroy() below will OPENSSL_cleanse
     * session_key / transcript state before freeing.
     */
    virp_context_t *ctx = virp_context_new();
    if (!ctx) {
        fprintf(stderr, "[O-Node] Failed to allocate protocol context\n");
        onode_destroy(&g_state);
        return 1;
    }
    g_state.ctx = ctx;

    /* Load devices from JSON config */
    int loaded = load_devices(&g_state, devices_path);
    if (loaded <= 0) {
        fprintf(stderr, "[O-Node] No devices loaded. Exiting.\n");
        onode_destroy(&g_state);
        virp_context_destroy(ctx);
        return 1;
    }

    /*
     * Trust chain (Primitive 6) + approval flow. Fatal if approval mode
     * is enabled without a working chain — see the function's comment.
     */
    err = onode_setup_chain_and_approvals(&g_state, node_id,
                                          chain_db_path, chain_key_path,
                                          approval_dir, approvers_path);
    if (err != VIRP_OK) {
        fprintf(stderr, "[O-Node] Startup aborted: approval mode requires "
                "a working trust chain (-c/-C). Exiting.\n");
        onode_destroy(&g_state);
        virp_context_destroy(ctx);
        return 1;
    }

    /* Install signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    /* A client closing before reading its response must not kill the
     * daemon: default SIGPIPE terminates the process. Sends also pass
     * MSG_NOSIGNAL (belt and suspenders). */
    signal(SIGPIPE, SIG_IGN);

    /* Start event loop (blocks) */
    err = onode_start(&g_state);

    /* Cleanup */
    onode_destroy(&g_state);
    virp_context_destroy(ctx);
    g_state.ctx = NULL;

    return (err == VIRP_OK) ? 0 : 1;
}

#endif  /* !VIRP_ONODE_PROD_NO_MAIN */
