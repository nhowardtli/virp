/* Test-only local C daemon. Device callbacks are in-memory simulations and
 * perform no network I/O. Only the production Cisco classifier is reused.
 * Never linked into a production binary or installed by install-prod. */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "virp.h"
#include "virp_onode.h"
#include "virp_driver.h"
#include "virp_chain.h"
#include "virp_crypto.h"
#include "virp_session.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct virp_conn { bool connected; };
static onode_state_t node;
static bool access_mode;
static unsigned writes;
static char state_path[256];
static virp_conn_t *fixture_connect(const virp_device_t *device)
{
    (void)device;
    virp_conn_t *c=calloc(1,sizeof(*c));
    if(c)c->connected=true;
    return c;
}
static void fixture_disconnect(virp_conn_t *c){free(c);}
static virp_error_t fixture_health(virp_conn_t *c){return c&&c->connected?VIRP_OK:VIRP_ERR_SESSION_INVALID;}
static void save_state(void)
{
    FILE *f=fopen(state_path,"w");assert(f);
    fprintf(f,"{\"access\":%s,\"writes\":%u}\n",access_mode?"true":"false",writes);
    assert(fflush(f)==0);assert(fsync(fileno(f))==0);assert(fclose(f)==0);
}
static virp_error_t fixture_execute(virp_conn_t *c,const char *cmd,virp_exec_result_t *r)
{
    assert(c&&c->connected);memset(r,0,sizeof(*r));
    char body[4096];body[0]='\0';
    if(!strcmp(cmd,"show running-config interface Ethernet0/1"))
        snprintf(body,sizeof(body),"interface Ethernet0/1\n%sshutdown\nend",access_mode?" switchport mode access\n ":" ");
    else if(!strcmp(cmd,"show interfaces Ethernet0/1 switchport"))
        snprintf(body,sizeof(body),"Name: Et0/1\nSwitchport: Enabled\nAdministrative Mode: %s\nOperational Mode: down\nAccess Mode VLAN: 1 (default)",access_mode?"static access":"dynamic auto");
    else if(!strcmp(cmd,"show mac address-table interface Ethernet0/1"))
        snprintf(body,sizeof(body),"Mac Address Table\n-------------------------------------------\nVlan Mac Address Type Ports\n---- ----------- -------- -----");
    else if(!strcmp(cmd,"show cdp neighbors Ethernet0/1 detail"))
        snprintf(body,sizeof(body),"Total cdp entries displayed : 0");
    else if(!strcmp(cmd,"show lldp neighbors Ethernet0/1 detail"))
        snprintf(body,sizeof(body),"Total entries displayed: 0");
    else if(!strcmp(cmd,"show etherchannel summary"))
        snprintf(body,sizeof(body),"Number of channel-groups in use: 0\nNumber of aggregators: 0");
    else if(!strcmp(cmd,"show vlan brief"))
        snprintf(body,sizeof(body),"VLAN Name Status Ports\n---- ---------------- -------- --------\n1 default active Et0/1\n10 lab active\n1002 fddi-default act/unsup");
    else if(!strcmp(cmd,"interface Ethernet0/1 switchport mode access")){
        access_mode=true;writes++;save_state();snprintf(body,sizeof(body),"configuration accepted");
    }else if(!strcmp(cmd,"interface Ethernet0/1 no switchport mode")){
        access_mode=false;writes++;save_state();snprintf(body,sizeof(body),"configuration accepted");
    }else{
        r->no_dispatch=true;r->disposition=VIRP_DISPOSITION_NOT_SENT;
        snprintf(r->error_msg,sizeof(r->error_msg),"unsupported local fixture command");return VIRP_OK;
    }
    int n=snprintf(r->output,sizeof(r->output),"canary#%s\n%s",cmd,body);
    assert(n>0&&(size_t)n<sizeof(r->output));r->output_len=(size_t)n;
    r->success=true;r->disposition=VIRP_DISPOSITION_EXECUTED_CONFIRMED;return VIRP_OK;
}
int main(int argc,char **argv)
{
    if(argc!=2||strlen(argv[1])>128)return 2;
    struct stat st;
    if(lstat(argv[1],&st)||!S_ISDIR(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&077))return 2;
    umask(077);
    char sock[160],db[160],chain_key[160],sign_key[160],pub[160],registry[160],approvals[160];
#define PATH(dst,name) assert(snprintf(dst,sizeof(dst),"%s/" name,argv[1])<(int)sizeof(dst))
    PATH(sock,"onode.sock");PATH(db,"chain.db");PATH(chain_key,"chain.key");
    PATH(sign_key,"sign.key");PATH(pub,"sign.pub");PATH(registry,"approvers.json");
    PATH(approvals,"approvals");PATH(state_path,"device-state.json");
#undef PATH
    virp_driver_cisco_init();
    const virp_driver_t *cisco=virp_driver_lookup(VIRP_VENDOR_CISCO_IOS);assert(cisco);
    virp_driver_t fixture={.name="local-port-fixture",.vendor=VIRP_VENDOR_MOCK,
        .connect=fixture_connect,.execute=fixture_execute,.disconnect=fixture_disconnect,
        .health_check=fixture_health,.route_command=cisco->route_command};
    assert(virp_driver_register(&fixture)==VIRP_OK);
    assert(onode_init(&node,260,NULL,sock)==VIRP_OK);
    node.gate_max_tier=VIRP_TIER_GREEN;node.execute_v3=true;
    node.ctx=virp_context_new();assert(node.ctx);
    virp_device_t dev;memset(&dev,0,sizeof(dev));
    snprintf(dev.hostname,sizeof(dev.hostname),"kestrel-ios");
    snprintf(dev.host,sizeof(dev.host),"192.168.255.10");
    dev.node_id=260;dev.port=22;dev.vendor=VIRP_VENDOR_MOCK;dev.enabled=true;
    assert(onode_add_device(&node,&dev)==VIRP_OK);
    virp_signing_key_t key;assert(virp_key_generate(&key,VIRP_KEY_TYPE_CHAIN)==VIRP_OK);
    assert(virp_key_save_file(&key,chain_key)==VIRP_OK);virp_key_destroy(&key);
    assert(virp_chain_init(&node.chain,db,chain_key,node.node_id,"local-test")==VIRP_OK);
    node.chain_enabled=true;
    assert(virp_obskey_generate(&node.obskey)==VIRP_OK);
    assert(virp_obskey_save(&node.obskey,sign_key,pub)==VIRP_OK);
    assert(virp_chain_enable_signing(&node.chain,sign_key)==VIRP_OK);
    assert(virp_chain_set_native_epoch(&node.chain,"port-test")==VIRP_OK);
    node.obskey_loaded=true;
    assert(onode_set_approvers(&node,approvals,registry)==VIRP_OK);
    save_state();virp_error_t result=onode_start(&node);onode_destroy(&node);
    return result==VIRP_OK?0:1;
}
