#define _POSIX_C_SOURCE 200809L
#include "virp_onode.h"
#include "virp_message.h"
#include <sys/time.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

static onode_state_t state;
static atomic_int calls, probes;
static atomic_bool fail_read, stop_on_probe;
static const char *sockpath = "/tmp/virp-operability-test.sock";
static virp_error_t execute(virp_conn_t *conn, const char *cmd, virp_exec_result_t *r)
{
    (void)conn;
    atomic_fetch_add(&calls, 1);
    memset(r, 0, sizeof(*r));
    r->success = !atomic_load(&fail_read);
    r->exit_code_trusted = true;
    r->exit_code = r->success ? 0 : 1;
    r->disposition = r->success ? VIRP_DISPOSITION_EXECUTED_CONFIRMED : VIRP_DISPOSITION_EXECUTED_FAILED;
    r->output_len = (size_t)snprintf(r->output, sizeof(r->output), "executed:%s", cmd);
    return VIRP_OK;
}
static virp_trust_tier_t route(const char *cmd)
{
    return strcmp(cmd, "forbidden") == 0 ? VIRP_TIER_RED : VIRP_TIER_GREEN;
}
static virp_error_t probe(virp_conn_t *conn)
{
    (void)conn;
    atomic_fetch_add(&probes, 1);
    if (atomic_load(&stop_on_probe)) onode_shutdown(&state);
    return VIRP_OK;
}
static void pause_ms(long ms)
{
    struct timespec t = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000 };
    nanosleep(&t, NULL);
}
static double now(void)
{
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
static void *serve(void *p) { assert(onode_start(p) == VIRP_OK); return NULL; }
static void request(const char *json, char *body, size_t cap)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0); assert(fd >= 0);
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sockpath);
    assert(connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    uint32_t len = htonl((uint32_t)strlen(json) + 1);
    uint8_t version = 2;
    assert(write(fd, &len, 4) == 4); assert(write(fd, &version, 1) == 1);
    assert(write(fd, json, strlen(json)) == (ssize_t)strlen(json));
    assert(recv(fd, &len, 4, MSG_WAITALL) == 4); len = ntohl(len);
    uint8_t buf[VIRP_MAX_MESSAGE_SIZE]; assert(len <= sizeof(buf));
    assert(recv(fd, buf, len, MSG_WAITALL) == (ssize_t)len); close(fd);
    if (len <= VIRP_HEADER_SIZE) { snprintf(body, cap, "typed-error"); return; }
    virp_header_t hdr; assert(virp_validate_message(buf, len, &state.okey, &hdr) == VIRP_OK);
    virp_observation_t obs; const uint8_t *data; uint16_t n;
    assert(virp_parse_observation(buf + VIRP_HEADER_SIZE, len - VIRP_HEADER_SIZE, &obs, &data, &n) == VIRP_OK);
    assert(n < cap); memcpy(body, data, n); body[n] = '\0';
}
int main(void)
{
    virp_driver_mock_init();
    struct { virp_vendor_t v; const char *cmd; } cases[] = {
        {VIRP_VENDOR_LINUX,"uptime"}, {VIRP_VENDOR_PROXMOX,"uptime"},
        {VIRP_VENDOR_FORTINET,"get system status"}, {VIRP_VENDOR_PALOALTO,"show system info"},
        {VIRP_VENDOR_WAZUH,"GET /manager/status"}, {VIRP_VENDOR_LIBRENMS,"GET /api/v0/devices"},
        {VIRP_VENDOR_PBS,"pbs op=backup.version.read"}, {VIRP_VENDOR_ZAMMAD,"GET /api/v1/ticket_states"},
        {VIRP_VENDOR_CISCO_IOS,"show version"}, {VIRP_VENDOR_CISCO_ASA,"show version"},
        {VIRP_VENDOR_CISCO_IOSXE,"show version"}, {VIRP_VENDOR_JUNIPER,"show version"}
    };
    assert(onode_init(&state, 12345, NULL, sockpath) == VIRP_OK);
    state.evidence_required = false;
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        virp_driver_t d = *virp_driver_lookup(VIRP_VENDOR_MOCK);
        d.vendor = cases[i].v; d.execute = execute; d.route_command = route; d.health_check = probe;
        assert(virp_driver_register(&d) == VIRP_OK);
        virp_device_t dev = { .vendor = cases[i].v, .enabled = true, .node_id = 100 + (uint32_t)i };
        snprintf(dev.hostname, sizeof(dev.hostname), "device-%zu", i);
        snprintf(dev.host, sizeof(dev.host), "127.0.0.1");
        assert(onode_add_device(&state, &dev) == VIRP_OK);
    }
    assert(onode_health_command(VIRP_VENDOR_WINDOWS) == NULL);
    assert(onode_health_command(VIRP_VENDOR_UNKNOWN) == NULL);
    pthread_t thread; assert(pthread_create(&thread, NULL, serve, &state) == 0);
    for (int i = 0; i < 100 && access(sockpath, F_OK); i++) pause_ms(10);
    char body[VIRP_MAX_MESSAGE_SIZE];
    request("{\"action\":\"list_fleet\"}", body, sizeof(body));
    assert(strstr(body, "read_verified") == NULL); /* Login alone is not readiness. */
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        char json[128]; snprintf(json, sizeof(json), "{\"action\":\"health\",\"device\":\"device-%zu\"}", i);
        request(json, body, sizeof(body)); assert(strstr(body, cases[i].cmd));
    }
    assert(atomic_load(&calls) == 12);
    request("{\"action\":\"list_fleet\"}", body, sizeof(body)); assert(strstr(body, "read_verified"));
    /* A known failed read cannot leave this target marked read_verified. */
    atomic_store(&fail_read, true);
    request("{\"action\":\"health\",\"device\":\"device-0\"}", body, sizeof(body));
    pthread_mutex_lock(&state.conn_mutex); assert(state.reconnect[0].last_read_success == 0);
    state.reconnect[1].last_read_success = time(NULL) - 301;
    pthread_mutex_unlock(&state.conn_mutex);
    request("{\"action\":\"list_fleet\"}", body, sizeof(body)); assert(strstr(body, "needs_health_check"));
    atomic_store(&fail_read, false);
    /* Shutdown during the first steady-state probe must not probe the rest. */
    atomic_store(&probes, 0); atomic_store(&stop_on_probe, true);
    double deadline = now() + 15;
    while (!atomic_load(&probes) && now() < deadline) pause_ms(10);
    assert(atomic_load(&probes) > 0);
    pthread_join(thread, NULL); onode_destroy(&state);
    assert(atomic_load(&probes) == 1);
    /* An idle watchdog's sleep must also be interruptible. */
    assert(onode_init(&state, 12345, NULL, sockpath) == VIRP_OK);
    assert(onode_watchdog_start(&state) == VIRP_OK); pause_ms(100);
    double start = now(); onode_destroy(&state); assert(now() - start < 0.8);
    puts("PASS: health dispatch, signed read readiness/freshness, shutdown scan and idle sleep");
    return 0;
}
