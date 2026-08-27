/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Collector-side response body filtering — see virp_body_filter.h.
 *
 * Context: 2,211 chained librenms bodies carry SNMPv3 authpass /
 * cryptopass values plus contact-email PII because GET /api/v0/devices
 * returns the full device record and nothing filtered it before the
 * body was hashed into the chain. The chain is append-only; those
 * bytes are permanent. This module makes sure no successor joins them.
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "virp_body_filter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "cJSON.h"

#define VBF_DEFAULT_CONFIG_PATH "/etc/virp/body-filters.json"
#define VBF_CONFIG_MAX          (1024 * 1024)
#define VBF_ANNOTATION_KEY      "_virp_filtered"

/*
 * Built-in rules — the librenms device inventory. The item allowlist
 * is the availability/asset surface the autopilot and an auditor
 * actually read (the battery evaluator uses only the envelope's
 * status/count — autopilot/virp_autopilot.py:eval_librenms_count).
 * Everything else in a LibreNMS device record — SNMP community and v3
 * credential fields, sysContact PII, transport secrets present or
 * future — is dropped by not being named. deploy/body-filters.json
 * ships this same rule set; keep the two in sync.
 */
static const char VBF_BUILTIN_RULES[] =
    "{\"version\":1,\"rules\":[{"
    "\"name\":\"librenms-devices-v1\","
    "\"driver\":\"librenms\","
    "\"path\":\"/api/v0/devices\","
    "\"envelope_allow\":[\"status\",\"count\",\"message\"],"
    "\"array_key\":\"devices\","
    "\"item_allow\":[\"device_id\",\"hostname\",\"sysName\",\"ip\","
    "\"os\",\"type\",\"hardware\",\"version\",\"serial\",\"status\","
    "\"status_reason\",\"ignore\",\"disabled\",\"uptime\","
    "\"last_polled\",\"last_discovered\",\"last_ping\","
    "\"last_ping_timetaken\",\"location_id\",\"dependency_parent_id\"]"
    "}]}";

/* Loaded rule set: the parsed cJSON tree is read-only once loaded and
 * is replaced only by an explicit init() or the test reset, so apply()
 * only needs the mutex for the load-if-absent check. */
static cJSON          *vbf_rules_root = NULL;
static pthread_mutex_t vbf_init_mutex = PTHREAD_MUTEX_INITIALIZER;

static void sha256_hex(const void *data, size_t len, char out_hex[65])
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    EVP_Digest(data, len, md, &md_len, EVP_sha256(), NULL);
    for (unsigned int i = 0; i < md_len && i < 32; i++)
        snprintf(out_hex + i * 2, 3, "%02x", md[i]);
    out_hex[64] = '\0';
}

static cJSON *parse_rules(const char *text, const char *origin)
{
    cJSON *root = cJSON_Parse(text);
    if (!root || !cJSON_IsObject(root) ||
        !cJSON_IsArray(cJSON_GetObjectItemCaseSensitive(root, "rules"))) {
        fprintf(stderr, "[BodyFilter] %s is not a valid rule set\n", origin);
        cJSON_Delete(root);
        return NULL;
    }
    return root;
}

static cJSON *load_rules_file(const char *path)
{
    FILE *fh = fopen(path, "r");
    if (!fh) return NULL;

    char *buf = malloc(VBF_CONFIG_MAX);
    if (!buf) { fclose(fh); return NULL; }
    size_t n = fread(buf, 1, VBF_CONFIG_MAX - 1, fh);
    int trunc = !feof(fh);
    fclose(fh);
    buf[n] = '\0';

    cJSON *root = NULL;
    if (trunc)
        fprintf(stderr, "[BodyFilter] %s exceeds %d bytes; ignored\n",
                path, VBF_CONFIG_MAX);
    else
        root = parse_rules(buf, path);
    free(buf);
    return root;
}

/* Must be called with vbf_init_mutex held. */
static void vbf_load_locked(const char *config_path)
{
    if (vbf_rules_root) {
        cJSON_Delete(vbf_rules_root);
        vbf_rules_root = NULL;
    }

    const char *origin = NULL;
    if (!config_path) config_path = getenv("VIRP_BODY_FILTERS");
    if (config_path && config_path[0]) {
        vbf_rules_root = load_rules_file(config_path);
        origin = config_path;
    } else {
        vbf_rules_root = load_rules_file(VBF_DEFAULT_CONFIG_PATH);
        origin = VBF_DEFAULT_CONFIG_PATH;
    }

    if (vbf_rules_root) {
        fprintf(stderr, "[BodyFilter] rules loaded from %s\n", origin);
    } else {
        /* FAIL CLOSED: a missing or broken config never means "no
         * filtering" — the built-in set stays active. */
        vbf_rules_root = parse_rules(VBF_BUILTIN_RULES, "built-in rules");
        if (!vbf_rules_root)
            fprintf(stderr, "[BodyFilter] FATAL: built-in rules invalid\n");
        else
            fprintf(stderr, "[BodyFilter] using built-in rules\n");
    }
}

virp_error_t virp_body_filter_init(const char *config_path)
{
    pthread_mutex_lock(&vbf_init_mutex);
    vbf_load_locked(config_path);
    virp_error_t rc = vbf_rules_root ? VIRP_OK : VIRP_ERR_NULL_PTR;
    pthread_mutex_unlock(&vbf_init_mutex);
    return rc;
}

/* Lazy self-init for apply(): load-if-absent under the mutex. The tree
 * is never mutated after load (init/reset are explicit, test-time or
 * startup-time events), so returning the pointer out of the lock is
 * safe for the daemon's concurrent executors. */
static const cJSON *vbf_rules(void)
{
    pthread_mutex_lock(&vbf_init_mutex);
    if (!vbf_rules_root)
        vbf_load_locked(NULL);
    const cJSON *root = vbf_rules_root;
    pthread_mutex_unlock(&vbf_init_mutex);
    return root;
}

void virp_body_filter_reset_for_tests(void)
{
    pthread_mutex_lock(&vbf_init_mutex);
    cJSON_Delete(vbf_rules_root);
    vbf_rules_root = NULL;
    pthread_mutex_unlock(&vbf_init_mutex);
}

/* Extract the endpoint path from a gate-admitted command: skip blanks,
 * skip one leading method word ("GET ", "POST ", ...), stop the
 * comparison at '?' or whitespace. Returns NULL if no path present. */
static const char *command_path(const char *command, size_t *plen)
{
    if (!command) return NULL;
    while (*command == ' ') command++;
    if (*command != '/') {
        const char *sp = strchr(command, ' ');
        if (!sp) return NULL;
        command = sp;
        while (*command == ' ') command++;
    }
    if (*command != '/') return NULL;
    size_t n = strcspn(command, "? \t\r\n");
    *plen = n;
    return command;
}

static const cJSON *match_rule(const cJSON *rules_root,
                               const char *driver_name, const char *command)
{
    if (!rules_root || !driver_name) return NULL;
    size_t plen = 0;
    const char *path = command_path(command, &plen);
    if (!path) return NULL;

    const cJSON *rules = cJSON_GetObjectItemCaseSensitive(rules_root,
                                                          "rules");
    const cJSON *rule = NULL;
    cJSON_ArrayForEach(rule, rules) {
        const cJSON *rd = cJSON_GetObjectItemCaseSensitive(rule, "driver");
        const cJSON *rp = cJSON_GetObjectItemCaseSensitive(rule, "path");
        if (!cJSON_IsString(rd) || !cJSON_IsString(rp)) continue;
        if (strcmp(rd->valuestring, driver_name) != 0) continue;
        if (strlen(rp->valuestring) == plen &&
            strncmp(rp->valuestring, path, plen) == 0)
            return rule;
    }
    return NULL;
}

static bool allow_has(const cJSON *allow, const char *key)
{
    const cJSON *a = NULL;
    cJSON_ArrayForEach(a, allow) {
        if (cJSON_IsString(a) && strcmp(a->valuestring, key) == 0)
            return true;
    }
    return false;
}

static void removed_add(cJSON *removed, const char *key)
{
    if (!allow_has(removed, key))        /* same shape: string-in-array */
        cJSON_AddItemToArray(removed, cJSON_CreateString(key));
}

/* Delete every child of obj whose key is not in allow; removed key
 * names (names only, never values) accumulate in removed. */
static void filter_object(cJSON *obj, const cJSON *allow,
                          const char *extra_allowed_key, cJSON *removed)
{
    cJSON *child = obj->child;
    while (child) {
        cJSON *next = child->next;
        const char *key = child->string ? child->string : "";
        if (!allow_has(allow, key) &&
            !(extra_allowed_key && strcmp(key, extra_allowed_key) == 0)) {
            removed_add(removed, key);
            cJSON_DeleteItemFromObjectCaseSensitive(obj, key);
        }
        child = next;
    }
}

/* Write new payload bytes after the retained prefix, cleansing the
 * vacated tail so removed values do not linger in the buffer. */
static void replace_payload(virp_exec_result_t *result, size_t prefix_len,
                            const char *payload)
{
    size_t plen = strlen(payload);
    size_t new_len = prefix_len + plen;
    memcpy(result->output + prefix_len, payload, plen + 1);
    if (result->output_len > new_len)
        OPENSSL_cleanse(result->output + new_len,
                        result->output_len - new_len);
    result->output_len = new_len;
}

static void withhold(virp_exec_result_t *result, size_t prefix_len,
                     const char *rule_name, const char *reason)
{
    char orig_sha[65];
    sha256_hex(result->output + prefix_len,
               result->output_len - prefix_len, orig_sha);

    char stub[512];
    snprintf(stub, sizeof(stub),
             "{\"" VBF_ANNOTATION_KEY "\":{\"profile\":\"%s\","
             "\"mode\":\"withheld\",\"reason\":\"%s\","
             "\"original_len\":%zu,\"original_sha256\":\"%s\"}}",
             rule_name, reason, result->output_len - prefix_len, orig_sha);

    /* A pathological first line could leave no room for the stub after
     * the prefix; the stub is the part that must survive, so drop the
     * prefix rather than the record. */
    if (prefix_len + strlen(stub) >= sizeof(result->output))
        prefix_len = 0;
    replace_payload(result, prefix_len, stub);
}

virp_bf_outcome_t virp_body_filter_apply(const char *driver_name,
                                         const char *command,
                                         virp_exec_result_t *result)
{
    if (!result || result->output_len == 0)
        return VIRP_BF_UNTOUCHED;

    const cJSON *rule = match_rule(vbf_rules(), driver_name, command);
    if (!rule) return VIRP_BF_UNTOUCHED;

    const cJSON *rn = cJSON_GetObjectItemCaseSensitive(rule, "name");
    const char *rule_name = cJSON_IsString(rn) ? rn->valuestring : "unnamed";

    /* REST drivers frame the payload as "host>path [HTTP n]\n<json>".
     * The prefix is transport provenance, not device data: keep it. */
    const char *nl = memchr(result->output, '\n', result->output_len);
    size_t prefix_len = nl ? (size_t)(nl - result->output) + 1 : 0;
    const char *payload = result->output + prefix_len;

    if (result->output_len == prefix_len)
        return VIRP_BF_UNTOUCHED;      /* framing only, no payload bytes */

    cJSON *root = cJSON_ParseWithLength(payload,
                                        result->output_len - prefix_len);
    if (!root || !cJSON_IsObject(root)) {
        /* FAIL CLOSED — see header. A matched endpoint whose payload
         * cannot be understood is exactly the case that must not reach
         * the chain raw (a capture-truncated credential dump parses as
         * nothing but still contains everything). */
        cJSON_Delete(root);
        withhold(result, prefix_len, rule_name,
                 "payload did not parse as a JSON object; "
                 "withheld unfiltered");
        fprintf(stderr, "[BodyFilter] %s: unparseable payload WITHHELD "
                "(rule %s)\n", driver_name, rule_name);
        return VIRP_BF_WITHHELD;
    }

    const cJSON *env_allow = cJSON_GetObjectItemCaseSensitive(rule,
                                                     "envelope_allow");
    const cJSON *item_allow = cJSON_GetObjectItemCaseSensitive(rule,
                                                     "item_allow");
    const cJSON *ak = cJSON_GetObjectItemCaseSensitive(rule, "array_key");
    const char *array_key = cJSON_IsString(ak) ? ak->valuestring : NULL;

    cJSON *removed = cJSON_CreateArray();

    filter_object(root, env_allow, array_key, removed);

    if (array_key) {
        cJSON *arr = cJSON_GetObjectItemCaseSensitive(root, array_key);
        if (cJSON_IsArray(arr)) {
            cJSON *item = NULL;
            cJSON_ArrayForEach(item, arr) {
                if (cJSON_IsObject(item))
                    filter_object(item, item_allow, NULL, removed);
            }
        }
    }

    if (cJSON_GetArraySize(removed) == 0) {
        /* Nothing to remove: the body stays byte-identical to the raw
         * response and carries no annotation. */
        cJSON_Delete(removed);
        cJSON_Delete(root);
        return VIRP_BF_UNTOUCHED;
    }

    cJSON *ann = cJSON_CreateObject();
    cJSON_AddStringToObject(ann, "profile", rule_name);
    cJSON_AddStringToObject(ann, "mode", "allowlist");
    cJSON_AddItemToObject(ann, "removed", removed);
    cJSON_AddItemToObject(root, VBF_ANNOTATION_KEY, ann);

    int n_removed = cJSON_GetArraySize(removed);
    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!out || prefix_len + strlen(out) >= sizeof(result->output)) {
        /* Cannot store the filtered form — never fall back to raw. */
        free(out);
        withhold(result, prefix_len, rule_name,
                 "filtered payload could not be stored; withheld");
        fprintf(stderr, "[BodyFilter] %s: filtered payload unstorable, "
                "WITHHELD (rule %s)\n", driver_name, rule_name);
        return VIRP_BF_WITHHELD;
    }

    replace_payload(result, prefix_len, out);
    free(out);
    fprintf(stderr, "[BodyFilter] %s: %d field name(s) removed by rule %s "
            "(recorded in body)\n", driver_name, n_removed, rule_name);
    return VIRP_BF_FILTERED;
}
