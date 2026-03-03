/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Intent Routing Protocol
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
} onode_request_t;

static bool json_extract_string(const char *json, const char *key,
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

    /* Copy until closing quote */
    size_t i = 0;
    while (*pos && *pos != '"' && i < out_len - 1) {
        out[i++] = *pos++;
    }
    out[i] = '\0';
    return true;
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
    else if (strcmp(action_str, "shutdown") == 0)
        req->action = ONODE_ACTION_SHUTDOWN;
    else
        return false;

    /* Extract optional fields */
    json_extract_string(json, "device", req->device, sizeof(req->device));
    json_extract_string(json, "command", req->command, sizeof(req->command));

    return true;
}

/* =========================================================================
 * Sequence Number
 * ========================================================================= */

uint32_t onode_next_seq(onode_state_t *state)
{
    return ++state->seq_num;
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

static virp_conn_t *get_connection(onode_state_t *state, int dev_idx)
{
    if (state->connections[dev_idx])
        return state->connections[dev_idx];

    /* Lazy connect */
    const virp_device_t *dev = &state->devices[dev_idx];
    const virp_driver_t *drv = virp_driver_lookup(dev->vendor);
    if (!drv) return NULL;

    state->connections[dev_idx] = drv->connect(dev);
    return state->connections[dev_idx];
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

    /* Get or create connection */
    virp_conn_t *conn = get_connection(state, dev_idx);
    if (!conn) {
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
    if (!drv)
        return VIRP_ERR_INVALID_TYPE;

    virp_exec_result_t result;
    virp_error_t err = drv->execute(conn, command, &result);
    if (err != VIRP_OK)
        return err;

    /* Wrap output in signed OBSERVATION */
    uint16_t data_len = (result.output_len > 65530) ?
                        65530 : (uint16_t)result.output_len;

    err = virp_build_observation(out_buf, out_buf_len, out_len,
                                 state->devices[dev_idx].node_id,
                                 onode_next_seq(state),
                                 VIRP_OBS_DEVICE_OUTPUT,
                                 VIRP_SCOPE_LOCAL,
                                 (const uint8_t *)result.output, data_len,
                                 &state->okey);

    if (err == VIRP_OK)
        state->observations_sent++;

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
 * Client Request Handler
 * ========================================================================= */

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

    case ONODE_ACTION_SHUTDOWN:
        fprintf(stderr, "[O-Node] Shutdown requested\n");
        onode_shutdown(state);
        break;
    }

    close(client_fd);
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
    chmod(state->socket_path, 0777);

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
                fprintf(stderr, "[O-Node] Heartbeat: uptime=%us obs=%u seq=%u\n",
                        uptime, state->observations_sent, state->seq_num);
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
    if (state)
        state->running = false;
}

void onode_destroy(onode_state_t *state)
{
    if (!state) return;

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

    /* Destroy the O-Key — zero it out */
    virp_key_destroy(&state->okey);

    fprintf(stderr, "[O-Node] Destroyed. %u observations signed.\n",
            state->observations_sent);
}
