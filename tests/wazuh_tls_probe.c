#define _POSIX_C_SOURCE 200809L
#include "virp_driver.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
static void envstr(char *dest, size_t n, const char *name) {
    const char *s=getenv(name); snprintf(dest,n,"%s",s?s:"");
}
int main(void) {
    const char *opt_in = getenv("VIRP_LIVE_WAZUH_TLS_FIXTURE");
    if (!opt_in || strcmp(opt_in, "1") != 0) {
        puts("SKIP: set VIRP_LIVE_WAZUH_TLS_FIXTURE=1 for the local TLS fixture");
        return 0;
    }
    if (!getenv("TEST_HOST") || strcmp(getenv("TEST_HOST"), "127.0.0.1") != 0 ||
        !getenv("TEST_PORT")) return 4;

    virp_driver_wazuh_init();
    virp_device_t d={.vendor=VIRP_VENDOR_WAZUH,.enabled=true};
    snprintf(d.hostname,sizeof(d.hostname),"tls-test");
    envstr(d.host,sizeof(d.host),"TEST_HOST");
    envstr(d.tls_servername,sizeof(d.tls_servername),"TEST_TLS_NAME");
    envstr(d.username,sizeof(d.username),"TEST_USER");
    envstr(d.password,sizeof(d.password),"TEST_PASSWORD");
    d.api_port=(uint16_t)atoi(getenv("TEST_PORT"));
    const virp_driver_t *driver=virp_driver_lookup(d.vendor);
    virp_conn_t *c=driver->connect(&d); if(!c) return 2;
    virp_exec_result_t r={0};
    virp_error_t e=driver->execute(c,"GET /manager/status",&r);
    int good=e==VIRP_OK && r.success;
    driver->disconnect(c); puts(good?"PASS verified Wazuh read":"FAIL Wazuh read");
    return good?0:3;
}
