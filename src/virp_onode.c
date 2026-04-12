/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * O-Node Daemon Implementation
 *
 * This process holds the O-Key and is the ONLY entity that can
 * produce signed observations. It listens on a Unix domain socket,
 * accepts requests, executes commands on devices through drivers,
 * and returns signed VIRP OBSERVATION messages.
 *
 * The R-Node (AI) talks to this process. It never touches SSH.
 * It never touches the O-Key. Channel separation is enforced
 * by process isolation.
 */

#define _POSIX_C_SOURCE 200809L

#include "virp_onode.h"
#include "virp_message.h"
#include "virp_handshake.h"
#include "virp_transcript.h"
#include "virp_context.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/crypto.h>

/* =========================================================================
 * JSON Request Parsing (minimal, no dependencies)
 *
 * We parse just enough JSON to extract action, device, and command.
 * No dynamic allocation. No external library. Fixed buffers.
 * ========================================================================= */

typedef struct {
    onode_action_t  action;
    char            device[64];
    char            command[1024];
    /* Chain fields (Primitive 6) */
    char            session_id[64];
    char            artifact_type[16];
    char            artifact_id[128];
    char            artifact_hash[65];
    char            artifact_content[8192]; /* Raw payload for artifact store */
    int64_t         from_sequence;
    int64_t         to_sequence;
    /* Intent fields (durable intent store) */
    char            intent_id[128];
    char            intent_hash[65];
    char            confidence[16];
    int64_t         expires_at_ns;
    int32_t         max_commands;
    char            intent_json[4096];      /* Canonical JSON */
    char            proposed_actions[2048];  /* JSON array */
    char            constraints[512];       /* JSON object */
    /* Handshake fields */
    char            client_id[64];
    char            client_nonce[17];       /* hex string (8 bytes = 16 hex chars) */
    char            server_nonce[17];
    char            versions[32];           /* comma-separated, e.g. "2,1" */
    char            algorithms[32];
    int64_t         supported_channels;
} onode_request_t;

bool json_extract_string(const char *json, const char *key,
                         char *out, size_t out_len)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);

    const char *pos = strstr(json, search);
    if (!pos) return false;

    /* Find the colon after the key */
    pos = strchr(pos + strlen(search), ':');
    if (!pos) return false;
    pos++;

    /* Skip whitespace */
    while (*pos == ' ' || *pos == '\t') pos++;

    /* Find opening quote */
    if (*pos != '"') return false;
    pos++;

    /* Copy until unescaped closing quote, decoding JSON escapes */
    size_t i = 0;
    while (*pos && i < out_len - 1) {
        if (*pos == '"') break;          /* unescaped quote = end of string */
        if (*pos == '\\' && *(pos + 1)) {
            pos++;  /* skip backslash */
            switch (*pos) {
            case 'n':  out[i++] = '\n'; pos++; break;
            case 't':  out[i++] = '\t'; pos++; break;
            case 'r':  out[i++] = '\r'; pos++; break;
            case '\\': out[i++] = '\\'; pos++; break;
            case '"':  out[i++] = '"';  pos++; break;
            case '/':  out[i++] = '/';  pos++; break;
            case 'b':  out[i++] = '\b'; pos++; break;
            case 'f':  out[i++] = '\f'; pos++; break;
            case 'u': {
                /* \uXXXX — BMP only, surrogates replaced with '?' */
                pos++;  /* skip 'u' */
                if (pos[0] && pos[1] && pos[2] && pos[3]) {
                    char hex[5] = { pos[0], pos[1], pos[2], pos[3], '\0' };
                    unsigned long cp = strtoul(hex, NULL, 16);
                    pos += 4;
                    if (cp >= 0xD800 && cp <= 0xDFFF) {
                        /* Surrogate pair — replace with '?' */
                        if (i < out_len - 1) out[i++] = '?';
                    } else if (cp <= 0x7F) {
                        if (i < out_len - 1) out[i++] = (char)cp;
                    } else if (cp <= 0x7FF) {
                        if (i + 1 < out_len - 1) {
                            out[i++] = (char)(0xC0 | (cp >> 6));
                            out[i++] = (char)(0x80 | (cp & 0x3F));
                        }
                    } else {
                        if (i + 2 < out_len - 1) {
                            out[i++] = (char)(0xE0 | (cp >> 12));
                            out[i++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                            out[i++] = (char)(0x80 | (cp & 0x3F));
                        }
                    }
                } else {
                    /* Incomplete \u sequence — copy '?' */
                    if (i < out_len - 1) out[i++] = '?';
                }
                break;
            }
            default:
                out[i++] = *pos++;        /* unknown escape: copy as-is */
                break;
            }
        } else {
            out[i++] = *pos++;
        }
    }
    out[i] = '\0';
    return true;
}

bool json_extract_int64(const char *json, const char *key, int64_t *out)
{
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);

    const char *pos = strstr(json, search);
    if (!pos) return false;

    pos = strchr(pos + strlen(search), ':');
    if (!pos) return false;
    pos++;

    while (*pos == ' ' || *pos == '\t') pos++;
    if (*pos == '\0') return false;

    char *end;
    *out = strtoll(pos, &end, 10);
    return (end != pos);
}

static bool parse_request(const char *json, onode_request_t *req)
{
    if (!json || !req) return false;

    memset(req, 0, sizeof(*req));

    char action_str[32];
    if (!json_extract_string(json, "action", action_str, sizeof(action_str)))
        return false;

    if (strcmp(action_str, "execute") == 0)
        req->action = ONODE_ACTION_EXECUTE;
    else if (strcmp(action_str, "health") == 0)
        req->action = ONODE_ACTION_HEALTH;
    else if (strcmp(action_str, "heartbeat") == 0)
        req->action = ONODE_ACTION_HEARTBEAT;
    else if (strcmp(action_str, "list_devices") == 0)
        req->action = ONODE_ACTION_LIST;
    else if (strcmp(action_str, "sign_intent") == 0)
        req->action = ONODE_ACTION_SIGN_INTENT;
    else if (strcmp(action_str, "sign_outcome") == 0)
        req->action = ONODE_ACTION_SIGN_OUTCOME;
    else if (strcmp(action_str, "chain_append") == 0)
        req->action = ONODE_ACTION_CHAIN_APPEND;
    else if (strcmp(action_str, "chain_verify") == 0)
        req->action = ONODE_ACTION_CHAIN_VERIFY;
    else if (strcmp(action_str, "intent_store") == 0)
        req->action = ONODE_ACTION_INTENT_STORE;
    else if (strcmp(action_str, "intent_get") == 0)
        req->action = ONODE_ACTION_INTENT_GET;
    else if (strcmp(action_str, "intent_execute") == 0)
        req->action = ONODE_ACTION_INTENT_EXECUTE;
    else if (strcmp(action_str, "batch_execute") == 0)
        req->action = ONODE_ACTION_BATCH_EXECUTE;
    else if (strcmp(action_str, "session_hello") == 0)
        req->action = ONODE_ACTION_SESSION_HELLO;
    else if (strcmp(action_str, "session_bind") == 0)
        req->action = ONODE_ACTION_SESSION_BIND;
    else if (strcmp(action_str, "session_close") == 0)
        req->action = ONODE_ACTION_SESSION_CLOSE;
    else if (strcmp(action_str, "shutdown") == 0)
        req->action = ONODE_ACTION_SHUTDOWN;
    else
        return false;

    /* Extract optional fields */
    json_extract_string(json, "device", req->device, sizeof(req->device));
    json_extract_string(json, "command", req->command, sizeof(req->command));

    /* Chain fields */
    json_extract_string(json, "session_id", req->session_id,
                        sizeof(req->session_id));
    json_extract_string(json, "artifact_type", req->artifact_type,
                        sizeof(req->artifact_type));
    json_extract_string(json, "artifact_id", req->artifact_id,
                        sizeof(req->artifact_id));
    json_extract_string(json, "artifact_hash", req->artifact_hash,
                        sizeof(req->artifact_hash));
    json_extract_string(json, "artifact_content", req->artifact_content,
                        sizeof(req->artifact_content));
    json_extract_int64(json, "from_sequence", &req->from_sequence);
    json_extract_int64(json, "to_sequence", &req->to_sequence);

    /* Intent fields */
    json_extract_string(json, "intent_id", req->intent_id,
                        sizeof(req->intent_id));
    json_extract_string(json, "intent_hash", req->intent_hash,
                        sizeof(req->intent_hash));
    json_extract_string(json, "confidence", req->confidence,
                        sizeof(req->confidence));
    json_extract_int64(json, "expires_at_ns", &req->expires_at_ns);
    {
        int64_t mc = 0;
        json_extract_int64(json, "max_commands", &mc);
        req->max_commands = (int32_t)mc;
    }
    json_extract_string(json, "intent_json", req->intent_json,
                        sizeof(req->intent_json));
    json_extract_string(json, "proposed_actions", req->proposed_actions,
                        sizeof(req->proposed_actions));
    json_extract_string(json, "constraints", req->constraints,
                        sizeof(req->constraints));

    /* Handshake fields */
    json_extract_string(json, "client_id", req->client_id,
                        sizeof(req->client_id));
    json_extract_string(json, "client_nonce", req->client_nonce,
                        sizeof(req->client_nonce));
    json_extract_string(json, "server_nonce", req->server_nonce,
                        sizeof(req->server_nonce));
    json_extract_string(json, "versions", req->versions,
                        sizeof(req->versions));
    json_extract_string(json, "algorithms", req->algorithms,
                        sizeof(req->algorithms));
    json_extract_int64(json, "supported_channels", &req->supported_channels);

    return true;
}

/* =========================================================================
 * Sequence Number
 * ========================================================================= */

uint32_t onode_next_seq(onode_state_t *state)
{
    pthread_mutex_lock(&state->state_mutex);
    uint32_t seq = ++state->seq_num;
    pthread_mutex_unlock(&state->state_mutex);
    return seq;
}

/* =========================================================================
 * Device Lookup
 * ========================================================================= */

static int find_device(onode_state_t *state, const char *hostname)
{
    for (int i = 0; i < state->device_count; i++) {
        if (strcmp(state->devices[i].hostname, hostname) == 0)
            return i;
    }
    return -1;
}

static void drop_connection(onode_state_t *state, int dev_idx)
{
    pthread_mutex_lock(&state->conn_mutex);
    virp_conn_t *conn = state->connections[dev_idx];
    state->connections[dev_idx] = NULL;

    /* Arm reconnect backoff — watchdog will pick this up */
    onode_reconnect_t *ri = &state->reconnect[dev_idx];
    if (ri->backoff_sec == 0)
        ri->backoff_sec = ONODE_RECONNECT_BACKOFF_INIT;
    ri->last_attempt = time(NULL);
    pthread_mutex_unlock(&state->conn_mutex);

    /* disconnect may block on SSH teardown — run outside the lock */
    if (conn) {
        const virp_driver_t *drv = virp_driver_lookup(state->devices[dev_idx].vendor);
        if (drv && drv->disconnect)
            drv->disconnect(conn);
    }

    fprintf(stderr, "[O-Node] Connection dropped: %s (backoff %ds)\n",
            state->devices[dev_idx].hostname, ri->backoff_sec);
}

static virp_conn_t *get_connection(onode_state_t *state, int dev_idx)
{
    pthread_mutex_lock(&state->conn_mutex);
    if (state->connections[dev_idx]) {
        virp_conn_t *conn = state->connections[dev_idx];
        pthread_mutex_unlock(&state->conn_mutex);
        return conn;
    }

    /* If watchdog is already reconnecting this device, don't double-connect */
    if (state->reconnect[dev_idx].reconnecting) {
        pthread_mutex_unlock(&state->conn_mutex);
        return NULL;
    }
    pthread_mutex_unlock(&state->conn_mutex);

    /* Lazy connect — may block, runs outside the lock */
    const virp_device_t *dev = &state->devices[dev_idx];
    const virp_driver_t *drv = virp_driver_lookup(dev->vendor);
    if (!drv) return NULL;

    virp_conn_t *new_conn = drv->connect(dev);

    /* Store result and track reconnect state */
    pthread_mutex_lock(&state->conn_mutex);
    onode_reconnect_t *ri = &state->reconnect[dev_idx];

    /* Another thread may have connected while we were blocked */
    if (state->connections[dev_idx]) {
        pthread_mutex_unlock(&state->conn_mutex);
        if (new_conn) {
            drv->disconnect(new_conn);
        }
        return state->connections[dev_idx];
    }

    state->connections[dev_idx] = new_conn;
    if (new_conn) {
        ri->backoff_sec = 0;
        ri->consecutive_fails = 0;
        ri->last_success = time(NULL);
    } else {
        ri->consecutive_fails++;
        ri->last_attempt = time(NULL);
        if (ri->backoff_sec == 0)
            ri->backoff_sec = ONODE_RECONNECT_BACKOFF_INIT;
    }
    pthread_mutex_unlock(&state->conn_mutex);

    return new_conn;
}

/* =========================================================================
 * O-Node Operations
 * ========================================================================= */

virp_error_t onode_execute(onode_state_t *state,
                           const char *device_name,
                           const char *command,
                           uint8_t *out_buf, size_t out_buf_len,
                           size_t *out_len)
{
    if (!state || !device_name || !command || !out_buf || !out_len)
        return VIRP_ERR_NULL_PTR;

    /* Find device */
    int dev_idx = find_device(state, device_name);
    if (dev_idx < 0) {
        /* Device not found — return error observation */
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "ERROR: device '%s' not found", device_name);
        return virp_build_observation(out_buf, out_buf_len, out_len,
                                      state->node_id, onode_next_seq(state),
                                      VIRP_OBS_DEVICE_OUTPUT, VIRP_SCOPE_LOCAL,
                                      (const uint8_t *)err_msg, (uint16_t)strlen(err_msg),
                                      &state->okey);
    }

    /*
     * Per-device execution lock — serializes all command execution on
     * this connection so that batch_execute threads targeting the same
     * device do not race on the libssh2 session.
     */
    pthread_mutex_lock(&state->exec_mutex[dev_idx]);

    /* Get or create connection */
    virp_conn_t *conn = get_connection(state, dev_idx);
    if (!conn) {
        pthread_mutex_unlock(&state->exec_mutex[dev_idx]);
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg),
                 "ERROR: cannot connect to '%s'", device_name);
        return virp_build_observation(out_buf, out_buf_len, out_len,
                                      state->devices[dev_idx].node_id,
                                      onode_next_seq(state),
                                      VIRP_OBS_DEVICE_OUTPUT, VIRP_SCOPE_LOCAL,
                                      (const uint8_t *)err_msg, (uint16_t)strlen(err_msg),
                                      &state->okey);
    }

    /* Execute command through driver */
    const virp_driver_t *drv = virp_driver_lookup(state->devices[dev_idx].vendor);
    if (!drv) {
        pthread_mutex_unlock(&state->exec_mutex[dev_idx]);
        return VIRP_ERR_INVALID_TYPE;
    }

    virp_exec_result_t result;
    virp_error_t err = drv->execute(conn, command, &result);
    if (err != VIRP_OK) {
        pthread_mutex_unlock(&state->exec_mutex[dev_idx]);
        return err;
    }

    /* On failure: drop stale connection, retry once with fresh connection */
    if (!result.success && result.output_len == 0) {
        drop_connection(state, dev_idx);
        conn = get_connection(state, dev_idx);
        if (conn) {
            memset(&result, 0, sizeof(result));
            err = drv->execute(conn, command, &result);
            if (err != VIRP_OK) {
                pthread_mutex_unlock(&state->exec_mutex[dev_idx]);
                return err;
            }
        }
    }

    pthread_mutex_unlock(&state->exec_mutex[dev_idx]);

    /* If still failed after retry, return error_msg as observation data */
    const uint8_t *obs_data;
    uint16_t data_len;
    if (!result.success && result.output_len == 0 && result.error_msg[0]) {
        obs_data = (const uint8_t *)result.error_msg;
        data_len = (uint16_t)strlen(result.error_msg);
    } else {
        obs_data = (const uint8_t *)result.output;
        data_len = (result.output_len > 65530) ?
                    65530 : (uint16_t)result.output_len;
    }

    err = virp_build_observation(out_buf, out_buf_len, out_len,
                                 state->devices[dev_idx].node_id,
                                 onode_next_seq(state),
                                 VIRP_OBS_DEVICE_OUTPUT,
                                 VIRP_SCOPE_LOCAL,
                                 obs_data, data_len,
                                 &state->okey);

    if (err == VIRP_OK) {
        pthread_mutex_lock(&state->state_mutex);
        state->observations_sent++;
        pthread_mutex_unlock(&state->state_mutex);
    }

    return err;
}

virp_error_t onode_heartbeat(onode_state_t *state,
                             uint8_t *out_buf, size_t out_buf_len,
                             size_t *out_len)
{
    if (!state || !out_buf || !out_len)
        return VIRP_ERR_NULL_PTR;

    uint32_t uptime = (uint32_t)(time(NULL) - state->uptime_start);

    return virp_build_heartbeat(out_buf, out_buf_len, out_len,
                                state->node_id, onode_next_seq(state),
                                uptime, true, true,
                                (uint16_t)state->observations_sent,
                                0,  /* R-Node tracks proposals */
                                &state->okey);
}

/* =========================================================================
 * List Devices — returns device inventory as observation
 * ========================================================================= */

static virp_error_t onode_list_devices(onode_state_t *state,
                                       uint8_t *out_buf, size_t out_buf_len,
                                       size_t *out_len)
{
    char listing[VIRP_OUTPUT_MAX];
    int offset = 0;

    offset += snprintf(listing + offset, sizeof(listing) - offset,
                       "VIRP O-Node Device Inventory (%d devices)\n"
                       "%-16s %-16s %-12s %-8s\n"
                       "-----------------------------------------------------\n",
                       state->device_count,
                       "Hostname", "Host", "Vendor", "NodeID");

    for (int i = 0; i < state->device_count && offset < (int)sizeof(listing) - 100; i++) {
        const char *vendor_str = "unknown";
        switch (state->devices[i].vendor) {
        case VIRP_VENDOR_CISCO_IOS: vendor_str = "cisco_ios"; break;
        case VIRP_VENDOR_FORTINET:  vendor_str = "fortinet"; break;
        case VIRP_VENDOR_LINUX:     vendor_str = "linux"; break;
        case VIRP_VENDOR_JUNIPER:   vendor_str = "juniper"; break;
        case VIRP_VENDOR_PALOALTO:  vendor_str = "paloalto"; break;
        case VIRP_VENDOR_WINDOWS:   vendor_str = "windows"; break;
        case VIRP_VENDOR_PROXMOX:   vendor_str = "proxmox"; break;
        case VIRP_VENDOR_CISCO_ASA: vendor_str = "cisco_asa"; break;
        case VIRP_VENDOR_MOCK:      vendor_str = "mock"; break;
        default: break;
        }

        offset += snprintf(listing + offset, sizeof(listing) - offset,
                           "%-16s %-16s %-12s %08x\n",
                           state->devices[i].hostname,
                           state->devices[i].host,
                           vendor_str,
                           state->devices[i].node_id);
    }

    return virp_build_observation(out_buf, out_buf_len, out_len,
                                  state->node_id, onode_next_seq(state),
                                  VIRP_OBS_RESOURCE_STATE, VIRP_SCOPE_LOCAL,
                                  (const uint8_t *)listing, (uint16_t)offset,
                                  &state->okey);
}

/* =========================================================================
 * Batch Parallel Execution (pthread-based)
 *
 * Each device gets its own thread. Connections are per-device indexed,
 * so threads never share connection state. The state_mutex protects
 * seq_num and observations_sent.
 * ========================================================================= */

typedef struct {
    onode_state_t   *state;
    char            device[64];
    char            command[1024];
    uint8_t         *resp_buf;      /* heap-allocated, VIRP_MAX_MESSAGE_SIZE */
    size_t          resp_len;
    virp_error_t    err;
} batch_thread_arg_t;

static void *batch_execute_thread(void *arg)
{
    batch_thread_arg_t *bta = (batch_thread_arg_t *)arg;
    bta->resp_len = 0;
    bta->err = onode_execute(bta->state, bta->device, bta->command,
                              bta->resp_buf, VIRP_MAX_MESSAGE_SIZE,
                              &bta->resp_len);
    return NULL;
}

/*
 * Parse batch commands from JSON "commands" array.
 * Returns count of commands parsed (0 on error/empty).
 */
static int parse_batch_commands(const char *json,
                                 batch_thread_arg_t *args,
                                 int max_cmds)
{
    const char *pos = strstr(json, "\"commands\"");
    if (!pos) return 0;

    pos = strchr(pos + 10, '[');
    if (!pos) return 0;
    pos++;

    int count = 0;
    while (count < max_cmds) {
        /* Skip whitespace and commas */
        while (*pos == ' ' || *pos == '\t' || *pos == '\n' ||
               *pos == '\r' || *pos == ',')
            pos++;

        if (*pos == ']' || *pos == '\0') break;
        if (*pos != '{') break;

        /* Find matching '}' with depth tracking */
        int depth = 0;
        bool in_string = false;
        const char *obj_start = pos;
        const char *p = pos;
        while (*p) {
            if (*p == '\\' && in_string) { p++; if (*p) p++; continue; }
            if (*p == '"') in_string = !in_string;
            if (!in_string) {
                if (*p == '{') depth++;
                if (*p == '}') { depth--; if (depth == 0) break; }
            }
            p++;
        }
        if (*p != '}') break;

        /* Extract object into temp buffer */
        size_t obj_len = (size_t)(p - obj_start + 1);
        char obj_buf[2048];
        if (obj_len >= sizeof(obj_buf)) { pos = p + 1; continue; }
        memcpy(obj_buf, obj_start, obj_len);
        obj_buf[obj_len] = '\0';

        if (json_extract_string(obj_buf, "device",
                                args[count].device,
                                sizeof(args[count].device)) &&
            json_extract_string(obj_buf, "command",
                                args[count].command,
                                sizeof(args[count].command))) {
            count++;
        }
        pos = p + 1;
    }

    return count;
}

/* =========================================================================
 * Client Request Handler
 * ========================================================================= */

/* Map a single hex character to its 4-bit value, or -1 if invalid. */
static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode hex string to bytes. Returns number of bytes written, or -1 on error.
 * Rejects any non-[0-9a-fA-F] character (no whitespace, signs, or 0x prefixes). */
int virp_hex_decode(const char *hex, uint8_t *out, size_t out_len)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > out_len)
        return -1;
    for (size_t i = 0; i < hex_len; i += 2) {
        int hi = hex_nibble(hex[i]);
        int lo = hex_nibble(hex[i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(hex_len / 2);
}

/* Encode bytes to lowercase hex. buf must hold 2*len+1 bytes. */
static void hex_encode(char *buf, size_t buf_size, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        snprintf(buf + i * 2, buf_size - i * 2, "%02x", data[i]);
    buf[len * 2] = '\0';
}

static void handle_client(onode_state_t *state, int client_fd)
{
    char recv_buf[ONODE_MAX_REQUEST_SIZE];
    uint8_t resp_buf[VIRP_MAX_MESSAGE_SIZE];
    size_t resp_len = 0;

    /* Set receive timeout */
    struct timeval tv = { .tv_sec = ONODE_RECV_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Read request */
    ssize_t n = recv(client_fd, recv_buf, sizeof(recv_buf) - 1, 0);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    recv_buf[n] = '\0';

    /* Parse request */
    onode_request_t req;
    if (!parse_request(recv_buf, &req)) {
        /* Bad request — send error code */
        uint32_t err_code = htonl((uint32_t)VIRP_ERR_INVALID_TYPE);
        send(client_fd, &err_code, 4, 0);
        close(client_fd);
        return;
    }

    virp_error_t err;

    switch (req.action) {
    case ONODE_ACTION_EXECUTE:
        if (req.device[0] == '\0' || req.command[0] == '\0') {
            uint32_t err_code = htonl((uint32_t)VIRP_ERR_NULL_PTR);
            send(client_fd, &err_code, 4, 0);
            break;
        }
        err = onode_execute(state, req.device, req.command,
                            resp_buf, sizeof(resp_buf), &resp_len);
        if (err == VIRP_OK && resp_len > 0)
            send(client_fd, resp_buf, resp_len, 0);
        else {
            uint32_t err_code = htonl((uint32_t)err);
            send(client_fd, &err_code, 4, 0);
        }
        break;

    case ONODE_ACTION_HEALTH:
        if (req.device[0] == '\0') {
            uint32_t err_code = htonl((uint32_t)VIRP_ERR_NULL_PTR);
            send(client_fd, &err_code, 4, 0);
            break;
        }
        /* Health check — execute a simple command */
        err = onode_execute(state, req.device, "show version",
                            resp_buf, sizeof(resp_buf), &resp_len);
        if (err == VIRP_OK && resp_len > 0)
            send(client_fd, resp_buf, resp_len, 0);
        else {
            uint32_t err_code = htonl((uint32_t)err);
            send(client_fd, &err_code, 4, 0);
        }
        break;

    case ONODE_ACTION_HEARTBEAT:
        err = onode_heartbeat(state, resp_buf, sizeof(resp_buf), &resp_len);
        if (err == VIRP_OK && resp_len > 0)
            send(client_fd, resp_buf, resp_len, 0);
        break;

    case ONODE_ACTION_LIST:
        err = onode_list_devices(state, resp_buf, sizeof(resp_buf), &resp_len);
        if (err == VIRP_OK && resp_len > 0)
            send(client_fd, resp_buf, resp_len, 0);
        break;

    case ONODE_ACTION_SIGN_INTENT:
        if (req.command[0] == '\0') {
            uint32_t err_code = htonl((uint32_t)VIRP_ERR_NULL_PTR);
            send(client_fd, &err_code, 4, 0);
            break;
        }
        /* req.command contains SHA256 hex of intent JSON (64 chars) */
        err = virp_build_observation(resp_buf, sizeof(resp_buf), &resp_len,
                                      state->node_id, onode_next_seq(state),
                                      VIRP_OBS_INTENT_SIGNED, VIRP_SCOPE_LOCAL,
                                      (const uint8_t *)req.command,
                                      (uint16_t)strlen(req.command),
                                      &state->okey);
        if (err == VIRP_OK && resp_len > 0) {
            send(client_fd, resp_buf, resp_len, 0);
            state->observations_sent++;
        } else {
            uint32_t err_code = htonl((uint32_t)err);
            send(client_fd, &err_code, 4, 0);
        }
        break;

    case ONODE_ACTION_SIGN_OUTCOME:
        if (req.command[0] == '\0') {
            uint32_t err_code = htonl((uint32_t)VIRP_ERR_NULL_PTR);
            send(client_fd, &err_code, 4, 0);
            break;
        }
        /* req.command contains SHA256 hex of outcome JSON (64 chars) */
        err = virp_build_observation(resp_buf, sizeof(resp_buf), &resp_len,
                                      state->node_id, onode_next_seq(state),
                                      VIRP_OBS_OUTCOME_SIGNED, VIRP_SCOPE_LOCAL,
                                      (const uint8_t *)req.command,
                                      (uint16_t)strlen(req.command),
                                      &state->okey);
        if (err == VIRP_OK && resp_len > 0) {
            send(client_fd, resp_buf, resp_len, 0);
            state->observations_sent++;
        } else {
            uint32_t err_code = htonl((uint32_t)err);
            send(client_fd, &err_code, 4, 0);
        }
        break;

    case ONODE_ACTION_CHAIN_APPEND:
        if (!state->chain_enabled) {
            uint32_t err_code = htonl((uint32_t)VIRP_ERR_CHAIN_DB);
            send(client_fd, &err_code, 4, 0);
            break;
        }
        if (req.session_id[0] == '\0' || req.artifact_type[0] == '\0' ||
            req.artifact_id[0] == '\0' || req.artifact_hash[0] == '\0') {
            uint32_t err_code = htonl((uint32_t)VIRP_ERR_NULL_PTR);
            send(client_fd, &err_code, 4, 0);
            break;
        }
        {
            virp_chain_entry_t chain_entry;
            err = virp_chain_append(&state->chain, req.session_id,
                                     req.artifact_type, req.artifact_id,
                                     req.artifact_hash, &chain_entry);
            if (err != VIRP_OK) {
                uint32_t err_code = htonl((uint32_t)err);
                send(client_fd, &err_code, 4, 0);
                break;
            }
            /* Store raw artifact content if provided */
            if (req.artifact_content[0] != '\0') {
                virp_chain_artifact_store(&state->chain,
                    req.artifact_id, req.artifact_type,
                    req.artifact_content, req.artifact_hash,
                    req.session_id);
            }
            /* JSON-encode the chain entry as observation payload */
            char json_buf[2048];
            int jlen = snprintf(json_buf, sizeof(json_buf),
                "{\"chain_entry_hash\":\"%s\","
                "\"previous_entry_hash\":\"%s\","
                "\"sequence\":%lld,"
                "\"session_id\":\"%s\","
                "\"signer_node_id\":%u,"
                "\"signer_org_id\":\"%s\"}",
                chain_entry.chain_entry_hash,
                chain_entry.previous_entry_hash,
                (long long)chain_entry.sequence,
                chain_entry.session_id,
                chain_entry.signer_node_id,
                chain_entry.signer_org_id);
            err = virp_build_observation(resp_buf, sizeof(resp_buf), &resp_len,
                                          state->node_id, onode_next_seq(state),
                                          VIRP_OBS_CHAIN_ENTRY, VIRP_SCOPE_LOCAL,
                                          (const uint8_t *)json_buf, (uint16_t)jlen,
                                          &state->okey);
            if (err == VIRP_OK && resp_len > 0) {
                send(client_fd, resp_buf, resp_len, 0);
                state->observations_sent++;
            } else {
                uint32_t err_code = htonl((uint32_t)err);
                send(client_fd, &err_code, 4, 0);
            }
        }
        break;

    case ONODE_ACTION_CHAIN_VERIFY:
        if (!state->chain_enabled) {
            uint32_t err_code = htonl((uint32_t)VIRP_ERR_CHAIN_DB);
            send(client_fd, &err_code, 4, 0);
            break;
        }
        if (req.session_id[0] == '\0') {
            uint32_t err_code = htonl((uint32_t)VIRP_ERR_NULL_PTR);
            send(client_fd, &err_code, 4, 0);
            break;
        }
        {
            virp_chain_verify_result_t vresult;
            err = virp_chain_verify(&state->chain, req.session_id,
                                     req.from_sequence, req.to_sequence,
                                     &vresult);
            if (err != VIRP_OK) {
                uint32_t err_code = htonl((uint32_t)err);
                send(client_fd, &err_code, 4, 0);
                break;
            }
            char json_buf[1024];
            int jlen = snprintf(json_buf, sizeof(json_buf),
                "{\"entries_checked\":%lld,"
                "\"first_broken\":%lld,"
                "\"from_sequence\":%lld,"
                "\"to_sequence\":%lld,"
                "\"valid\":%s}",
                (long long)vresult.entries_checked,
                (long long)vresult.first_broken,
                (long long)vresult.from_sequence,
                (long long)vresult.to_sequence,
                vresult.valid ? "true" : "false");
            err = virp_build_observation(resp_buf, sizeof(resp_buf), &resp_len,
                                          state->node_id, onode_next_seq(state),
                                          VIRP_OBS_CHAIN_VERIFY, VIRP_SCOPE_LOCAL,
                                          (const uint8_t *)json_buf, (uint16_t)jlen,
                                          &state->okey);
            if (err == VIRP_OK && resp_len > 0) {
                send(client_fd, resp_buf, resp_len, 0);
                state->observations_sent++;
            } else {
                uint32_t err_code = htonl((uint32_t)err);
                send(client_fd, &err_code, 4, 0);
            }
        }
        break;

    case ONODE_ACTION_INTENT_STORE:
        if (!state->chain_enabled) {
            uint32_t err_code = htonl((uint32_t)VIRP_ERR_CHAIN_DB);
            send(client_fd, &err_code, 4, 0);
            break;
        }
        if (req.intent_id[0] == '\0' || req.intent_hash[0] == '\0' ||
            req.intent_json[0] == '\0') {
            uint32_t err_code = htonl((uint32_t)VIRP_ERR_NULL_PTR);
            send(client_fd, &err_code, 4, 0);
            break;
        }
        {
            virp_intent_entry_t ie;
            memset(&ie, 0, sizeof(ie));
            snprintf(ie.intent_id, sizeof(ie.intent_id), "%s", req.intent_id);
            snprintf(ie.intent_hash, sizeof(ie.intent_hash), "%s", req.intent_hash);
            snprintf(ie.intent_json, sizeof(ie.intent_json), "%s", req.intent_json);
            snprintf(ie.confidence, sizeof(ie.confidence), "%s", req.confidence);
            ie.expires_at_ns = req.expires_at_ns;
            ie.max_commands = req.max_commands;
            snprintf(ie.proposed_actions, sizeof(ie.proposed_actions), "%s",
                     req.proposed_actions);
            snprintf(ie.constraints, sizeof(ie.constraints), "%s",
                     req.constraints);

            /* Sequence for the observation response */
            uint32_t seq = onode_next_seq(state);
            ie.signature_seq = seq;

            /* HMAC + timestamps computed inside virp_chain_intent_store */
            err = virp_chain_intent_store(&state->chain, &ie);
            if (err != VIRP_OK) {
                uint32_t err_code = htonl((uint32_t)err);
                send(client_fd, &err_code, 4, 0);
                break;
            }
            /* Store intent content as artifact */
            if (ie.intent_json[0] != '\0') {
                virp_chain_artifact_store(&state->chain,
                    ie.intent_id, "intent",
                    ie.intent_json, ie.intent_hash,
                    req.session_id[0] != '\0' ? req.session_id : "intent");
            }

            char json_buf[512];
            int jlen = snprintf(json_buf, sizeof(json_buf),
                "{\"commands_executed\":%d,"
                "\"intent_id\":\"%s\","
                "\"max_commands\":%d,"
                "\"signature_hmac\":\"%s\","
                "\"signature_seq\":%lld,"
                "\"signature_timestamp_ns\":%lld}",
                ie.commands_executed,
                ie.intent_id,
                ie.max_commands,
                ie.signature_hmac,
                (long long)ie.signature_seq,
                (long long)ie.signature_timestamp_ns);
            err = virp_build_observation(resp_buf, sizeof(resp_buf), &resp_len,
                                          state->node_id, seq,
                                          VIRP_OBS_INTENT_STORED, VIRP_SCOPE_LOCAL,
                                          (const uint8_t *)json_buf, (uint16_t)jlen,
                                          &state->okey);
            if (err == VIRP_OK && resp_len > 0) {
                send(client_fd, resp_buf, resp_len, 0);
                state->observations_sent++;
            } else {
                uint32_t err_code = htonl((uint32_t)err);
                send(client_fd, &err_code, 4, 0);
            }
        }
        break;

    case ONODE_ACTION_INTENT_GET:
        if (!state->chain_enabled) {
            uint32_t err_code = htonl((uint32_t)VIRP_ERR_CHAIN_DB);
            send(client_fd, &err_code, 4, 0);
            break;
        }
        if (req.intent_id[0] == '\0') {
            uint32_t err_code = htonl((uint32_t)VIRP_ERR_NULL_PTR);
            send(client_fd, &err_code, 4, 0);
            break;
        }
        {
            virp_intent_entry_t ie;
            err = virp_chain_intent_get(&state->chain, req.intent_id, &ie);
            if (err != VIRP_OK) {
                uint32_t err_code = htonl((uint32_t)err);
                send(client_fd, &err_code, 4, 0);
                break;
            }

            /* Return full intent data as JSON */
            char json_buf[6144];
            int jlen = snprintf(json_buf, sizeof(json_buf),
                "{\"commands_executed\":%d,"
                "\"confidence\":\"%s\","
                "\"constraints\":%s,"
                "\"created_at_ns\":%lld,"
                "\"expires_at_ns\":%lld,"
                "\"intent_hash\":\"%s\","
                "\"intent_id\":\"%s\","
                "\"intent_json\":%s,"
                "\"max_commands\":%d,"
                "\"proposed_actions\":%s,"
                "\"signature_hmac\":\"%s\","
                "\"signature_seq\":%lld,"
                "\"signature_timestamp_ns\":%lld}",
                ie.commands_executed,
                ie.confidence,
                ie.constraints,
                (long long)ie.created_at_ns,
                (long long)ie.expires_at_ns,
                ie.intent_hash,
                ie.intent_id,
                ie.intent_json,
                ie.max_commands,
                ie.proposed_actions,
                ie.signature_hmac,
                (long long)ie.signature_seq,
                (long long)ie.signature_timestamp_ns);
            /* Clamp payload to uint16 max */
            if (jlen > 65535) jlen = 65535;
            err = virp_build_observation(resp_buf, sizeof(resp_buf), &resp_len,
                                          state->node_id, onode_next_seq(state),
                                          VIRP_OBS_INTENT_FETCHED, VIRP_SCOPE_LOCAL,
                                          (const uint8_t *)json_buf, (uint16_t)jlen,
                                          &state->okey);
            if (err == VIRP_OK && resp_len > 0) {
                send(client_fd, resp_buf, resp_len, 0);
                state->observations_sent++;
            } else {
                uint32_t err_code = htonl((uint32_t)err);
                send(client_fd, &err_code, 4, 0);
            }
        }
        break;

    case ONODE_ACTION_INTENT_EXECUTE:
        if (!state->chain_enabled) {
            uint32_t err_code = htonl((uint32_t)VIRP_ERR_CHAIN_DB);
            send(client_fd, &err_code, 4, 0);
            break;
        }
        if (req.intent_id[0] == '\0') {
            uint32_t err_code = htonl((uint32_t)VIRP_ERR_NULL_PTR);
            send(client_fd, &err_code, 4, 0);
            break;
        }
        {
            virp_intent_entry_t ie;
            err = virp_chain_intent_execute(&state->chain, req.intent_id, &ie);
            if (err != VIRP_OK) {
                uint32_t err_code = htonl((uint32_t)err);
                send(client_fd, &err_code, 4, 0);
                break;
            }

            char json_buf[512];
            int jlen = snprintf(json_buf, sizeof(json_buf),
                "{\"commands_executed\":%d,"
                "\"intent_id\":\"%s\","
                "\"max_commands\":%d}",
                ie.commands_executed,
                ie.intent_id,
                ie.max_commands);
            err = virp_build_observation(resp_buf, sizeof(resp_buf), &resp_len,
                                          state->node_id, onode_next_seq(state),
                                          VIRP_OBS_INTENT_EXECUTED, VIRP_SCOPE_LOCAL,
                                          (const uint8_t *)json_buf, (uint16_t)jlen,
                                          &state->okey);
            if (err == VIRP_OK && resp_len > 0) {
                send(client_fd, resp_buf, resp_len, 0);
                state->observations_sent++;
            } else {
                uint32_t err_code = htonl((uint32_t)err);
                send(client_fd, &err_code, 4, 0);
            }
        }
        break;

    case ONODE_ACTION_BATCH_EXECUTE: {
        /* Parse batch commands from JSON array */
        batch_thread_arg_t args[ONODE_MAX_BATCH];
        memset(args, 0, sizeof(args));

        int cmd_count = parse_batch_commands(recv_buf, args, ONODE_MAX_BATCH);
        if (cmd_count <= 0) {
            uint32_t err_code = htonl((uint32_t)VIRP_ERR_NULL_PTR);
            send(client_fd, &err_code, 4, 0);
            break;
        }

        /*
         * Multiple batch items may target the same device. The per-device
         * exec_mutex in onode_execute serializes access to the shared
         * connection, so this is safe. Commands to different devices run
         * in parallel; commands to the same device run sequentially.
         */

        /* Allocate per-thread response buffers */
        bool alloc_ok = true;
        for (int i = 0; i < cmd_count; i++) {
            args[i].state = state;
            args[i].resp_buf = malloc(VIRP_MAX_MESSAGE_SIZE);
            if (!args[i].resp_buf) { alloc_ok = false; break; }
        }
        if (!alloc_ok) {
            for (int i = 0; i < cmd_count; i++)
                free(args[i].resp_buf);
            uint32_t err_code = htonl((uint32_t)VIRP_ERR_NULL_PTR);
            send(client_fd, &err_code, 4, 0);
            break;
        }

        /* Launch one thread per device */
        pthread_t threads[ONODE_MAX_BATCH];
        for (int i = 0; i < cmd_count; i++)
            pthread_create(&threads[i], NULL, batch_execute_thread, &args[i]);

        /* Wait for all threads to complete */
        for (int i = 0; i < cmd_count; i++)
            pthread_join(threads[i], NULL);

        /* Send response: 4-byte count, then per-result length-prefixed messages */
        uint32_t net_count = htonl((uint32_t)cmd_count);
        send(client_fd, &net_count, 4, 0);

        for (int i = 0; i < cmd_count; i++) {
            if (args[i].err == VIRP_OK && args[i].resp_len > 0) {
                uint32_t net_len = htonl((uint32_t)args[i].resp_len);
                send(client_fd, &net_len, 4, 0);
                send(client_fd, args[i].resp_buf, args[i].resp_len, 0);
            } else {
                /* Length 4 signals an error code follows */
                uint32_t net_len = htonl(4);
                send(client_fd, &net_len, 4, 0);
                uint32_t err_code = htonl((uint32_t)args[i].err);
                send(client_fd, &err_code, 4, 0);
            }
        }

        /* Cleanup */
        for (int i = 0; i < cmd_count; i++)
            free(args[i].resp_buf);

        break;
    }

    case ONODE_ACTION_SESSION_HELLO: {
        if (req.client_id[0] == '\0') {
            uint32_t err_code = htonl((uint32_t)VIRP_ERR_NULL_PTR);
            send(client_fd, &err_code, 4, 0);
            break;
        }

        /* Build SESSION_HELLO from request fields */
        virp_session_hello_t hello;
        memset(&hello, 0, sizeof(hello));
        hello.msg_type = VIRP_MSG_SESSION_HELLO;
        snprintf(hello.client_id, sizeof(hello.client_id), "%s", req.client_id);

        /* Parse versions: comma-separated string e.g. "2,1" */
        if (req.versions[0]) {
            char vtmp[32];
            snprintf(vtmp, sizeof(vtmp), "%s", req.versions);
            char *saveptr = NULL;
            char *tok = strtok_r(vtmp, ",", &saveptr);
            while (tok && hello.version_count < VIRP_MAX_VERSIONS) {
                hello.versions[hello.version_count++] = (uint8_t)atoi(tok);
                tok = strtok_r(NULL, ",", &saveptr);
            }
        } else {
            hello.versions[0] = 2;
            hello.versions[1] = 1;
            hello.version_count = 2;
        }

        /* Parse algorithms: comma-separated string */
        if (req.algorithms[0]) {
            char atmp[32];
            snprintf(atmp, sizeof(atmp), "%s", req.algorithms);
            char *saveptr = NULL;
            char *tok = strtok_r(atmp, ",", &saveptr);
            while (tok && hello.algorithm_count < VIRP_MAX_ALGORITHMS) {
                hello.algorithms[hello.algorithm_count++] = (uint8_t)atoi(tok);
                tok = strtok_r(NULL, ",", &saveptr);
            }
        } else {
            hello.algorithms[0] = VIRP_ALG_HMAC_SHA256;
            hello.algorithm_count = 1;
        }

        hello.supported_channels = (uint32_t)req.supported_channels;

        /* Parse client_nonce from hex (8 bytes = 16 hex chars) */
        if (req.client_nonce[0]) {
            virp_hex_decode(req.client_nonce, hello.client_nonce, 8);
        }

        {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            hello.timestamp_ns =
                (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
        }

        /* Process handshake */
        virp_session_hello_ack_t ack;
        err = virp_handle_hello(state->ctx, &hello, &ack);
        if (err != VIRP_OK) {
            uint32_t err_code = htonl((uint32_t)err);
            send(client_fd, &err_code, 4, 0);
            break;
        }

        /* Return HELLO_ACK as JSON */
        char sid_hex[33], cn_hex[17], sn_hex[17];
        hex_encode(sid_hex, sizeof(sid_hex), ack.session_id, 16);
        hex_encode(cn_hex, sizeof(cn_hex), ack.client_nonce, 8);
        hex_encode(sn_hex, sizeof(sn_hex), ack.server_nonce, 8);

        char json_resp[1024];
        int jlen = snprintf(json_resp, sizeof(json_resp),
            "{\"msg_type\":%u,"
            "\"server_id\":\"%s\","
            "\"selected_version\":%u,"
            "\"selected_algorithm\":%u,"
            "\"accepted_channels\":%u,"
            "\"session_id\":\"%s\","
            "\"client_nonce\":\"%s\","
            "\"server_nonce\":\"%s\"}",
            ack.msg_type, ack.server_id,
            ack.selected_version, ack.selected_algorithm,
            ack.accepted_channels,
            sid_hex, cn_hex, sn_hex);

        send(client_fd, json_resp, (size_t)jlen, 0);
        break;
    }

    case ONODE_ACTION_SESSION_BIND: {
        /* Build SESSION_BIND from request fields */
        virp_session_bind_t bind_msg;
        memset(&bind_msg, 0, sizeof(bind_msg));
        bind_msg.msg_type = VIRP_MSG_SESSION_BIND;

        snprintf(bind_msg.client_id, sizeof(bind_msg.client_id),
                 "%s", req.client_id);

        /* session_id from hex (reuse req.session_id, 16 bytes = 32 hex) */
        if (req.session_id[0]) {
            virp_hex_decode(req.session_id, bind_msg.session_id, 16);
        }

        if (req.client_nonce[0])
            virp_hex_decode(req.client_nonce, bind_msg.client_nonce, 8);
        if (req.server_nonce[0])
            virp_hex_decode(req.server_nonce, bind_msg.server_nonce, 8);

        {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            bind_msg.timestamp_ns =
                (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
        }

        err = virp_handle_session_bind(state->ctx, &bind_msg);
        if (err != VIRP_OK) {
            uint32_t err_code = htonl((uint32_t)err);
            send(client_fd, &err_code, 4, 0);
            break;
        }

        /* BIND succeeded → derive session key to reach ACTIVE */
        err = virp_session_derive_key(state->ctx, state->okey.key.key);
        if (err != VIRP_OK) {
            fprintf(stderr, "[O-Node] session key derivation failed: %d\n",
                    (int)err);
            uint32_t err_code = htonl((uint32_t)err);
            send(client_fd, &err_code, 4, 0);
            break;
        }

        const char *ok_resp = "{\"status\":\"bound\",\"active\":true}";
        send(client_fd, ok_resp, strlen(ok_resp), 0);
        break;
    }

    case ONODE_ACTION_SESSION_CLOSE:
        virp_handle_session_close(state->ctx);
        fprintf(stderr, "[O-Node] Session closed by client\n");
        {
            const char *close_resp = "{\"status\":\"closed\"}";
            send(client_fd, close_resp, strlen(close_resp), 0);
        }
        break;

    case ONODE_ACTION_SHUTDOWN:
        fprintf(stderr, "[O-Node] Shutdown requested\n");
        onode_shutdown(state);
        break;
    }

    close(client_fd);
}

/* =========================================================================
 * Auto-Reconnect Watchdog
 *
 * Background thread that periodically checks all device connections.
 * If a connection is NULL (dropped or never established) and the device
 * is enabled, it attempts to reconnect with exponential backoff:
 *   5s → 10s → 30s → 60s (max)
 *
 * If an existing connection fails health_check(), it drops and reconnects.
 * This means sessions recover without a full service restart.
 * ========================================================================= */

static int next_backoff(int current)
{
    if (current <= 5)  return 10;
    if (current <= 10) return 30;
    return ONODE_RECONNECT_BACKOFF_MAX;
}

/*
 * Attempt to connect a single device. Called by the watchdog for both
 * initial startup connections and reconnections after drops.
 * Caller must NOT hold conn_mutex.
 */
static void watchdog_try_connect(onode_state_t *state, int dev_idx,
                                 const virp_driver_t *drv, bool is_initial)
{
    const virp_device_t *dev = &state->devices[dev_idx];
    onode_reconnect_t *ri = &state->reconnect[dev_idx];

    if (is_initial) {
        fprintf(stderr, "[Watchdog] Connecting: %s (%s)\n",
                dev->hostname, dev->host);
    } else {
        fprintf(stderr, "[Watchdog] Reconnecting: %s (attempt %d, backoff was %ds)\n",
                dev->hostname, ri->consecutive_fails + 1, ri->backoff_sec);
    }

    /* connect() may block — runs outside the lock */
    virp_conn_t *new_conn = drv->connect(dev);

    pthread_mutex_lock(&state->conn_mutex);
    ri->reconnecting = false;

    /* Another thread may have connected while we were blocked */
    if (state->connections[dev_idx]) {
        pthread_mutex_unlock(&state->conn_mutex);
        if (new_conn)
            drv->disconnect(new_conn);
        return;
    }

    if (new_conn) {
        state->connections[dev_idx] = new_conn;
        ri->backoff_sec = 0;
        ri->consecutive_fails = 0;
        ri->last_success = time(NULL);
        pthread_mutex_unlock(&state->conn_mutex);

        pthread_mutex_lock(&state->state_mutex);
        if (!is_initial)
            state->reconnects++;
        pthread_mutex_unlock(&state->state_mutex);

        fprintf(stderr, "[Watchdog] Connected: %s\n", dev->hostname);
    } else {
        ri->consecutive_fails++;
        ri->last_attempt = time(NULL);
        ri->backoff_sec = (ri->backoff_sec == 0)
            ? ONODE_RECONNECT_BACKOFF_INIT
            : next_backoff(ri->backoff_sec);
        pthread_mutex_unlock(&state->conn_mutex);

        fprintf(stderr, "[Watchdog] Failed: %s — retrying in %ds\n",
                dev->hostname, ri->backoff_sec);
    }
}

static void *watchdog_thread_fn(void *arg)
{
    onode_state_t *state = (onode_state_t *)arg;

    /* Count enabled devices for logging */
    int enabled = 0;
    for (int i = 0; i < state->device_count; i++)
        if (state->devices[i].enabled) enabled++;

    fprintf(stderr, "[Watchdog] Started — connecting %d enabled devices\n", enabled);

    /* ---- Initial connect pass: reach every enabled device ---- */
    for (int i = 0; i < state->device_count; i++) {
        if (!state->watchdog_running) goto done;
        if (!state->devices[i].enabled) continue;

        const virp_driver_t *drv = virp_driver_lookup(state->devices[i].vendor);
        if (!drv) {
            fprintf(stderr, "[Watchdog] No driver for: %s (vendor=%d) — skipping\n",
                    state->devices[i].hostname, state->devices[i].vendor);
            continue;
        }

        pthread_mutex_lock(&state->conn_mutex);
        bool already = (state->connections[i] != NULL);
        if (!already) {
            state->reconnect[i].reconnecting = true;
            state->reconnect[i].last_attempt = time(NULL);
        }
        pthread_mutex_unlock(&state->conn_mutex);

        if (already) continue;

        watchdog_try_connect(state, i, drv, true);
    }

    /* Log initial pass summary */
    {
        int up = 0;
        for (int i = 0; i < state->device_count; i++)
            if (state->devices[i].enabled && state->connections[i]) up++;
        fprintf(stderr, "[Watchdog] Initial pass complete: connected=%d/%d\n", up, enabled);
    }

    /* ---- Steady-state loop: health checks + reconnects ---- */
    while (state->watchdog_running) {
        sleep(ONODE_WATCHDOG_INTERVAL_SEC);
        if (!state->watchdog_running) break;

        time_t now = time(NULL);

        for (int i = 0; i < state->device_count; i++) {
            if (!state->devices[i].enabled)
                continue;

            const virp_driver_t *drv = virp_driver_lookup(state->devices[i].vendor);
            if (!drv) continue;  /* logged in initial pass */

            pthread_mutex_lock(&state->conn_mutex);

            onode_reconnect_t *ri = &state->reconnect[i];
            virp_conn_t *conn = state->connections[i];

            /* Skip if another thread is already reconnecting this device */
            if (ri->reconnecting) {
                pthread_mutex_unlock(&state->conn_mutex);
                continue;
            }

            /* Case 1: Connection exists — probe with health_check */
            if (conn && drv->health_check) {
                virp_error_t hc = drv->health_check(conn);
                if (hc != VIRP_OK) {
                    fprintf(stderr, "[Watchdog] Health check failed: %s — dropping\n",
                            state->devices[i].hostname);
                    ri->reconnecting = true;
                    pthread_mutex_unlock(&state->conn_mutex);

                    /* Drop outside the lock (disconnect may block) */
                    drv->disconnect(conn);

                    pthread_mutex_lock(&state->conn_mutex);
                    state->connections[i] = NULL;
                    ri->last_attempt = now;
                    if (ri->backoff_sec == 0)
                        ri->backoff_sec = ONODE_RECONNECT_BACKOFF_INIT;
                    ri->reconnecting = false;
                    pthread_mutex_unlock(&state->conn_mutex);
                } else {
                    pthread_mutex_unlock(&state->conn_mutex);
                }
                continue;
            }

            /* Case 2: No connection — attempt reconnect if backoff has elapsed */
            if (!conn) {
                if (ri->backoff_sec > 0 && (now - ri->last_attempt) < ri->backoff_sec) {
                    pthread_mutex_unlock(&state->conn_mutex);
                    continue;  /* Not time yet */
                }

                ri->reconnecting = true;
                ri->last_attempt = now;
                pthread_mutex_unlock(&state->conn_mutex);

                watchdog_try_connect(state, i, drv, false);
                continue;
            }

            pthread_mutex_unlock(&state->conn_mutex);
        }
    }

done:
    fprintf(stderr, "[Watchdog] Stopped\n");
    return NULL;
}

/* =========================================================================
 * Lifecycle
 * ========================================================================= */

virp_error_t onode_init(onode_state_t *state,
                        uint32_t node_id,
                        const char *okey_path,
                        const char *socket_path)
{
    if (!state)
        return VIRP_ERR_NULL_PTR;

    memset(state, 0, sizeof(*state));
    state->node_id = node_id;
    state->seq_num = 0;
    state->listen_fd = -1;
    state->running = false;
    state->uptime_start = (uint32_t)time(NULL);
    state->watchdog_running = false;
    pthread_mutex_init(&state->state_mutex, NULL);
    pthread_mutex_init(&state->conn_mutex, NULL);
    for (int i = 0; i < ONODE_MAX_DEVICES; i++)
        pthread_mutex_init(&state->exec_mutex[i], NULL);

    /* Socket path */
    if (socket_path)
        snprintf(state->socket_path, sizeof(state->socket_path), "%s", socket_path);
    else
        snprintf(state->socket_path, sizeof(state->socket_path), "%s", ONODE_SOCKET_PATH);

    /* Load or generate O-Key */
    virp_error_t err;
    if (okey_path) {
        err = virp_key_load_file(&state->okey, VIRP_KEY_TYPE_OKEY, okey_path);
        if (err != VIRP_OK) {
            fprintf(stderr, "[O-Node] Failed to load O-Key from %s: %s\n",
                    okey_path, virp_error_str(err));
            return err;
        }
        fprintf(stderr, "[O-Node] Loaded O-Key from %s\n", okey_path);
    } else {
        err = virp_key_generate(&state->okey, VIRP_KEY_TYPE_OKEY);
        if (err != VIRP_OK)
            return err;
        fprintf(stderr, "[O-Node] Generated new O-Key\n");
    }

    fprintf(stderr, "[O-Node] Fingerprint: ");
    for (int i = 0; i < VIRP_HMAC_SIZE; i++)
        fprintf(stderr, "%02x", state->okey.fingerprint[i]);
    fprintf(stderr, "\n");

    return VIRP_OK;
}

virp_error_t onode_add_device(onode_state_t *state,
                              const virp_device_t *device)
{
    if (!state || !device)
        return VIRP_ERR_NULL_PTR;

    if (state->device_count >= ONODE_MAX_DEVICES)
        return VIRP_ERR_MESSAGE_TOO_LARGE;

    memcpy(&state->devices[state->device_count], device, sizeof(*device));
    state->connections[state->device_count] = NULL;
    state->device_count++;

    fprintf(stderr, "[O-Node] Added device: %s (%s) node_id=0x%08x\n",
            device->hostname, device->host, device->node_id);

    return VIRP_OK;
}

virp_error_t onode_start(onode_state_t *state)
{
    if (!state)
        return VIRP_ERR_NULL_PTR;

    /* Remove stale socket */
    unlink(state->socket_path);

    /* Create Unix domain socket */
    state->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (state->listen_fd < 0) {
        perror("[O-Node] socket");
        return VIRP_ERR_KEY_NOT_LOADED;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", state->socket_path);

    if (bind(state->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[O-Node] bind");
        close(state->listen_fd);
        return VIRP_ERR_KEY_NOT_LOADED;
    }

    /* Allow non-root users (e.g. Docker tliadmin) to connect */
    chmod(state->socket_path, 0660);

    if (listen(state->listen_fd, ONODE_MAX_CLIENTS) < 0) {
        perror("[O-Node] listen");
        close(state->listen_fd);
        return VIRP_ERR_KEY_NOT_LOADED;
    }

    fprintf(stderr, "[O-Node] Listening on %s\n", state->socket_path);
    fprintf(stderr, "[O-Node] Node ID: 0x%08x\n", state->node_id);
    fprintf(stderr, "[O-Node] Devices: %d\n", state->device_count);
    fprintf(stderr, "[O-Node] Ready.\n\n");

    state->running = true;

    /* Start auto-reconnect watchdog thread */
    state->watchdog_running = true;
    if (pthread_create(&state->watchdog_thread, NULL, watchdog_thread_fn, state) != 0) {
        perror("[O-Node] Failed to start watchdog thread");
        state->watchdog_running = false;
    }

    /* Event loop */
    while (state->running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(state->listen_fd, &readfds);

        /* Timeout for periodic heartbeat */
        struct timeval tv = { .tv_sec = ONODE_HEARTBEAT_SEC, .tv_usec = 0 };

        int ready = select(state->listen_fd + 1, &readfds, NULL, NULL, &tv);

        if (ready < 0) {
            if (errno == EINTR) continue;  /* Signal interrupted */
            perror("[O-Node] select");
            break;
        }

        if (ready == 0) {
            /* Timeout — periodic heartbeat (logged, not sent anywhere yet) */
            uint8_t hb_buf[256];
            size_t hb_len;
            if (onode_heartbeat(state, hb_buf, sizeof(hb_buf), &hb_len) == VIRP_OK) {
                uint32_t uptime = (uint32_t)(time(NULL) - state->uptime_start);
                int conn_up = 0, conn_total = 0;
                for (int ci = 0; ci < state->device_count; ci++) {
                    if (state->devices[ci].enabled) {
                        conn_total++;
                        if (state->connections[ci]) conn_up++;
                    }
                }
                fprintf(stderr, "[O-Node] Heartbeat: uptime=%us obs=%u seq=%u connected=%d/%d reconnects=%u\n",
                        uptime, state->observations_sent, state->seq_num,
                        conn_up, conn_total, state->reconnects);
            }
            continue;
        }

        if (FD_ISSET(state->listen_fd, &readfds)) {
            int client_fd = accept(state->listen_fd, NULL, NULL);
            if (client_fd < 0) {
                perror("[O-Node] accept");
                continue;
            }
            handle_client(state, client_fd);
        }
    }

    fprintf(stderr, "[O-Node] Shutting down...\n");
    return VIRP_OK;
}

void onode_shutdown(onode_state_t *state)
{
    if (!state) return;
    state->running = false;
    state->watchdog_running = false;
}

void onode_destroy(onode_state_t *state)
{
    if (!state) return;

    /* Stop watchdog thread */
    state->watchdog_running = false;
    if (state->watchdog_thread)
        pthread_join(state->watchdog_thread, NULL);

    /* Close all device connections */
    for (int i = 0; i < state->device_count; i++) {
        if (state->connections[i]) {
            const virp_driver_t *drv = virp_driver_lookup(state->devices[i].vendor);
            if (drv)
                drv->disconnect(state->connections[i]);
            state->connections[i] = NULL;
        }
    }

    /* Close listen socket */
    if (state->listen_fd >= 0) {
        close(state->listen_fd);
        unlink(state->socket_path);
    }

    /* Destroy trust chain */
    if (state->chain_enabled)
        virp_chain_destroy(&state->chain);

    /* Wipe device passwords from inventory */
    for (int i = 0; i < state->device_count; i++) {
        OPENSSL_cleanse(state->devices[i].password,
                        sizeof(state->devices[i].password));
        OPENSSL_cleanse(state->devices[i].enable_password,
                        sizeof(state->devices[i].enable_password));
        OPENSSL_cleanse(state->devices[i].api_token,
                        sizeof(state->devices[i].api_token));
    }

    /* Destroy mutexes */
    pthread_mutex_destroy(&state->state_mutex);
    pthread_mutex_destroy(&state->conn_mutex);
    for (int i = 0; i < state->device_count; i++)
        pthread_mutex_destroy(&state->exec_mutex[i]);

    /* Destroy the O-Key — zero it out */
    virp_key_destroy(&state->okey);

    fprintf(stderr, "[O-Node] Destroyed. %u observations signed, %u reconnects.\n",
            state->observations_sent, state->reconnects);
}
