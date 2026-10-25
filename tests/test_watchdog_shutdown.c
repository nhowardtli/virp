#define _POSIX_C_SOURCE 200809L
#include "virp_onode.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
static onode_state_t state;
static atomic_int probes;
static virp_error_t probe(virp_conn_t *c) {
 (void)c;atomic_fetch_add(&probes,1);onode_shutdown(&state);return VIRP_OK;
}
static void pause_ms(long ms) { struct timespec t={ms/1000,(ms%1000)*1000000};nanosleep(&t,NULL); }
static double now(void) { struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9; }
int main(void) {
 virp_driver_mock_init();virp_driver_t d=*virp_driver_lookup(VIRP_VENDOR_MOCK);d.health_check=probe;d.vendor=VIRP_VENDOR_LINUX;
 assert(virp_driver_register(&d)==VIRP_OK);
 assert(onode_init(&state,12345,NULL,"/tmp/virp-home-watchdog-test.sock")==VIRP_OK);
 for(int i=0;i<12;i++) { virp_device_t v={.vendor=VIRP_VENDOR_LINUX,.enabled=true,.node_id=(uint32_t)i+1};snprintf(v.hostname,sizeof(v.hostname),"mock-%d",i);snprintf(v.host,sizeof(v.host),"127.0.0.1");assert(onode_add_device(&state,&v)==VIRP_OK); }
 assert(onode_watchdog_start(&state)==VIRP_OK);
 double deadline=now()+12;while(!atomic_load(&probes)&&now()<deadline)pause_ms(10);
 assert(atomic_load(&probes)>0);onode_destroy(&state);assert(atomic_load(&probes)==1);
 assert(onode_init(&state,12345,NULL,"/tmp/virp-home-watchdog-test.sock")==VIRP_OK);
 assert(onode_watchdog_start(&state)==VIRP_OK);pause_ms(100);double t=now();onode_destroy(&state);assert(now()-t<0.8);
 puts("PASS: stop during first probe prevents fleet traversal; idle shutdown <0.8 sec");
}
