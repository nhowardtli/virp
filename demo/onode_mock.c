/* Mock-only demonstration entrypoint. No real driver is registered here. */
#define _POSIX_C_SOURCE 200809L
#include "virp_onode.h"
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
static onode_state_t state;
int load_devices(onode_state_t *, const char *);
virp_error_t onode_setup_chain_and_approvals(onode_state_t *, uint32_t,
    const char *, const char *, const char *, const char *);
static void stop(int sig) { (void)sig; onode_shutdown(&state); }
int main(int argc, char **argv) {
    const char *key=NULL,*socket=NULL,*devices=NULL,*chain=NULL,*chain_key=NULL,*approvals=NULL,*registry=NULL;
    int c;
    while((c=getopt(argc,argv,"k:s:d:c:C:a:A:"))!=-1) {
        switch(c) {
        case 'k':key=optarg;break; case 's':socket=optarg;break;
        case 'd':devices=optarg;break; case 'c':chain=optarg;break;
        case 'C':chain_key=optarg;break; case 'a':approvals=optarg;break;
        case 'A':registry=optarg;break; default:return 2;
        }
    }
    if(!key||!socket||!devices||!chain||!chain_key||!approvals||!registry)return 2;
    fprintf(stderr,"DEMONSTRATION ONLY: mock targets, never a production executor\n");
    virp_driver_mock_init();
    if(onode_init(&state,1,key,socket)!=VIRP_OK)return 1;
    virp_context_t *ctx=virp_context_new();if(!ctx){onode_destroy(&state);return 1;}
    state.ctx=ctx;int rc=1;
    if(load_devices(&state,devices)<0)goto done;
    for(int i=0;i<state.device_count;i++) {
        if(state.devices[i].vendor!=VIRP_VENDOR_MOCK) {
            fprintf(stderr,"Refused non-mock target before any connection\n");goto done;
        }
    }
    if(onode_setup_chain_and_approvals(&state,1,chain,chain_key,approvals,registry)!=VIRP_OK)goto done;
    signal(SIGINT,stop);signal(SIGTERM,stop);
    rc=onode_start(&state)==VIRP_OK?0:1;
done:onode_destroy(&state);virp_context_destroy(ctx);return rc;
}
