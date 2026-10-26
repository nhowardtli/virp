#define _POSIX_C_SOURCE 200809L
#include "virp_onode.h"
#include "virp_policy.h"
#include "virp_federation.h"
#include "virp_approval.h"
#include "virp_message.h"
#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/stat.h>
#include <time.h>
struct virp_conn { int unused; };
static onode_state_t node;
static atomic_uint dispatches;
static atomic_bool unknown;
static virp_conn_t *connect_mock(const virp_device_t *d){(void)d;return calloc(1,sizeof(virp_conn_t));}
static void disconnect_mock(virp_conn_t *c){free(c);}
static virp_trust_tier_t classify(const char *cmd){return !strcmp(cmd,"reboot")?VIRP_TIER_BLACK:VIRP_TIER_GREEN;}
static virp_error_t execute(virp_conn_t *c,const char *cmd,virp_exec_result_t *r){
    (void)c;atomic_fetch_add(&dispatches,1);memset(r,0,sizeof(*r));
    if(!strcmp(cmd,"reboot"))assert(virp_policy_reboot_permitted(cmd));
    assert(!virp_exec_passthrough);
    if(atomic_load(&unknown)){r->disposition=VIRP_DISPOSITION_EXECUTED_UNKNOWN;return VIRP_OK;}
    strcpy(r->output,"fixture observation");r->output_len=strlen(r->output);
    r->success=true;r->exit_code_trusted=true;r->disposition=VIRP_DISPOSITION_EXECUTED_CONFIRMED;return VIRP_OK;
}
static char *readall(const char *path){FILE *f=fopen(path,"r");assert(f);fseek(f,0,SEEK_END);long n=ftell(f);rewind(f);char *s=calloc(1,(size_t)n+1);assert(s);assert(fread(s,1,(size_t)n,f)==(size_t)n);fclose(f);return s;}
static virp_policy_t *policy(sqlite3 *db,const char *profile,bool protected){
    char text[4096];snprintf(text,sizeof(text),
      "{\"version\":1,\"max_calls\":100,\"max_disruptive\":10,\"max_inflight\":1,\"protected\":[%s],"
      "\"principals\":[{\"uid\":%u,\"profile\":\"%s\",\"expires\":4102444800,\"rules\":["
      "{\"device_id\":\"0000000000000011\",\"host\":\"127.0.0.1\",\"port\":22,\"vendor\":99,\"operation\":\"host.reboot\",\"resource\":\"host\"},"
      "{\"device_id\":\"0000000000000011\",\"host\":\"127.0.0.1\",\"port\":22,\"vendor\":99,\"operation\":\"system.read\",\"resource\":\"host\"}]}]}",
      protected?"{\"device_id\":\"0000000000000011\",\"resource\":\"host\",\"reason\":\"BLACK-04\"}":"",(unsigned)getuid(),profile);
    virp_policy_t *p=virp_policy_parse(text,db);assert(p);return p;
}
static void supervised_approval(sqlite3 *db,const char *temp) {
    virp_fed_keypair_t kp;assert(virp_fed_generate(&kp,1)==VIRP_OK);
    uint8_t spki[44];char entry[1024],registry[256],dir[256];
    virp_approver_ed25519_spki(kp.public_key,spki);
    assert(virp_approver_entry_json(spki,sizeof(spki),"independent-owner",true,entry,sizeof(entry))==VIRP_OK);
    snprintf(registry,sizeof(registry),"%s/approvers.json",temp);snprintf(dir,sizeof(dir),"%s/approvals",temp);
    FILE *f=fopen(registry,"w");assert(f);fprintf(f,"[%s]",entry);fclose(f);assert(!chmod(registry,0600));
    assert(onode_set_approvers(&node,dir,registry)==VIRP_OK);
    unsigned char output[VIRP_MAX_MESSAGE_SIZE];size_t len;
    assert(onode_execute_obs_ex(&node,"fixture","reboot",1,NULL,getuid(),output,sizeof(output),&len)==VIRP_OK);
    virp_observation_t obs;const uint8_t *data;uint16_t n;
    assert(virp_parse_observation(output+VIRP_HEADER_SIZE,len-VIRP_HEADER_SIZE,&obs,&data,&n)==VIRP_OK);
    char payload[4096];assert(n<sizeof(payload));memcpy(payload,data,n);payload[n]=0;
    const char *at=strstr(payload,"proposal_id=");assert(at);at+=strlen("proposal_id=");
    char id[VIRP_APPROVAL_ID_HEX_LEN+1];memcpy(id,at,VIRP_APPROVAL_ID_HEX_LEN);id[VIRP_APPROVAL_ID_HEX_LEN]=0;
    virp_approval_challenge_t ch;assert(virp_approval_challenge(dir,&node.chain,id,0,&ch)==VIRP_OK);
    uint8_t sig[VIRP_APPROVER_SIG_SIZE];assert(virp_fed_sign(&kp,ch.canonical,VIRP_APPROVAL_CANON_SIZE,sig)==VIRP_OK);
    char kid[33];for(int i=0;i<16;i++)snprintf(kid+2*i,3,"%02x",kp.key_id[i]);
    virp_approval_rec_t apr;assert(virp_approval_submit(dir,&node.approvers,&node.chain,id,kid,sig,sizeof(sig),&apr)==VIRP_OK);
    /* A genuine approval still cannot override Observe or protected resources. */
    virp_policy_close(node.policy);node.policy=policy(db,"observe",false);
    assert(onode_execute_obs_ex(&node,"fixture","reboot",1,id,getuid(),output,sizeof(output),&len)==VIRP_ERR_ACTION_FORBIDDEN);
    virp_policy_close(node.policy);node.policy=policy(db,"supervised",true);
    assert(onode_execute_obs_ex(&node,"fixture","reboot",1,id,getuid(),output,sizeof(output),&len)==VIRP_ERR_ACTION_FORBIDDEN);
    assert(atomic_load(&dispatches)==0);
    virp_policy_close(node.policy);node.policy=policy(db,"supervised",false);
    assert(onode_execute_obs_ex(&node,"fixture","reboot",1,id,getuid(),output,sizeof(output),&len)==VIRP_OK);
    assert(atomic_load(&dispatches)==1);
    assert(onode_execute_obs_ex(&node,"fixture","reboot",1,id,getuid(),output,sizeof(output),&len)==VIRP_OK);
    assert(atomic_load(&dispatches)==1); /* approval is single-use */
    atomic_store(&dispatches,0);
    memset(&kp,0,sizeof(kp));
}
static void *server(void *unused){(void)unused;assert(onode_start(&node)==VIRP_OK);return NULL;}
static void pause_ms(long ms){struct timespec t={ms/1000,(ms%1000)*1000000};nanosleep(&t,NULL);}
static void request(const char *socket_path,const char *json){
    int fd=socket(AF_UNIX,SOCK_STREAM,0);assert(fd>=0);struct sockaddr_un a={.sun_family=AF_UNIX};snprintf(a.sun_path,sizeof(a.sun_path),"%s",socket_path);
    assert(!connect(fd,(struct sockaddr *)&a,sizeof(a)));
    uint32_t n=htonl((uint32_t)strlen(json)+1);assert(send(fd,&n,4,0)==4);unsigned char version=VIRP_FRAME_VERSION;assert(send(fd,&version,1,0)==1);assert(send(fd,json,strlen(json),0)==(ssize_t)strlen(json));
    assert(recv(fd,&n,4,MSG_WAITALL)==4);n=ntohl(n);assert(n<2000000);char *buf=malloc(n);assert(buf);assert(recv(fd,buf,n,MSG_WAITALL)==(ssize_t)n);free(buf);close(fd);
}
int main(void){
    assert(getuid()!=0); /* fixture intentionally exercises a non-root peer */
    char temp[]="/tmp/virp-policy-daemon-XXXXXX";assert(mkdtemp(temp));
    char sock[108],dbpath[256],keypath[256];snprintf(sock,sizeof(sock),"%s/socket",temp);snprintf(dbpath,sizeof(dbpath),"%s/chain.db",temp);snprintf(keypath,sizeof(keypath),"%s/chain.key",temp);
    virp_driver_t driver={.name="policy-fixture",.vendor=VIRP_VENDOR_MOCK,.connect=connect_mock,.disconnect=disconnect_mock,.execute=execute,.route_command=classify};assert(virp_driver_register(&driver)==VIRP_OK);
    assert(onode_init(&node,17,NULL,sock)==VIRP_OK);
    virp_device_t d={.device_id=17,.node_id=17,.vendor=VIRP_VENDOR_MOCK,.enabled=true,.port=22};strcpy(d.hostname,"fixture");strcpy(d.host,"127.0.0.1");assert(onode_add_device(&node,&d)==VIRP_OK);
    virp_signing_key_t key;assert(virp_key_generate(&key,VIRP_KEY_TYPE_CHAIN)==VIRP_OK);assert(virp_key_save_file(&key,keypath)==VIRP_OK);virp_key_destroy(&key);
    assert(virp_chain_init(&node.chain,dbpath,keypath,17,"policy-fixture")==VIRP_OK);node.chain_enabled=true;
    sqlite3 *db;assert(sqlite3_open(":memory:",&db)==SQLITE_OK);char *schema=readall("deploy/policy-schema.sql");assert(sqlite3_exec(db,schema,NULL,NULL,NULL)==SQLITE_OK);free(schema);
    unsigned char output[VIRP_MAX_MESSAGE_SIZE];size_t len=0;
    node.policy=policy(db,"observe",false);node.gate_default_mode=GATE_MODE_SHADOW;node.gate_max_tier=VIRP_TIER_BLACK;
    assert(onode_execute_obs_ex(&node,"fixture","reboot",1,NULL,getuid(),output,sizeof(output),&len)==VIRP_ERR_ACTION_FORBIDDEN);assert(atomic_load(&dispatches)==0);
    virp_policy_close(node.policy);node.policy=policy(db,"supervised",false);
    assert(onode_execute_obs_ex(&node,"fixture","reboot",1,NULL,getuid(),output,sizeof(output),&len)==VIRP_OK);assert(atomic_load(&dispatches)==0);
    supervised_approval(db,temp);
    virp_policy_close(node.policy);node.policy=policy(db,"autonomous",true);
    assert(onode_execute_obs_ex(&node,"fixture","reboot",1,"pretend-approval",getuid(),output,sizeof(output),&len)==VIRP_ERR_ACTION_FORBIDDEN);assert(atomic_load(&dispatches)==0);
    virp_policy_close(node.policy);node.policy=policy(db,"autonomous",false);
    assert(onode_execute_obs_ex(&node,"fixture","reboot",1,NULL,getuid(),output,sizeof(output),&len)==VIRP_OK);assert(atomic_load(&dispatches)==1);
    assert(onode_execute_obs_ex(&node,"fixture","sudo reboot",1,NULL,getuid(),output,sizeof(output),&len)==VIRP_ERR_ACTION_FORBIDDEN);assert(atomic_load(&dispatches)==1);
    assert(onode_execute_obs_ex(&node,"fixture","reboot",1,NULL,getuid()+1,output,sizeof(output),&len)==VIRP_ERR_ACTION_FORBIDDEN);
    uid_t uid=getuid();assert(onode_set_allowed_uids(&node,&uid,1)==VIRP_OK);
    onode_action_t actions[]={ONODE_ACTION_EXECUTE,ONODE_ACTION_BATCH_EXECUTE,ONODE_ACTION_SHUTDOWN,ONODE_ACTION_SIGN_INTENT};assert(onode_set_uid_actions(&node,uid,actions,4)==VIRP_OK);
    pthread_t thread;assert(!pthread_create(&thread,NULL,server,NULL));for(int i=0;i<100&&access(sock,F_OK);i++)pause_ms(10);assert(!access(sock,F_OK));
    request(sock,"{\"action\":\"execute\",\"device\":\"fixture\",\"command\":\"uptime\"}");assert(atomic_load(&dispatches)==2);
    request(sock,"{\"action\":\"batch_execute\",\"commands\":[{\"device\":\"fixture\",\"command\":\"uptime\"},{\"device\":\"fixture\",\"command\":\"rm -rf /\"}]}");assert(atomic_load(&dispatches)==3);
    request(sock,"{\"action\":\"shutdown\"}");assert(node.running);
    request(sock,"{\"action\":\"sign_intent\",\"intent\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}");assert(atomic_load(&dispatches)==3);
    atomic_store(&unknown,true);
    request(sock,"{\"action\":\"execute\",\"device\":\"fixture\",\"command\":\"reboot\"}");assert(atomic_load(&dispatches)==4);
    request(sock,"{\"action\":\"execute\",\"device\":\"fixture\",\"command\":\"reboot\"}");assert(atomic_load(&dispatches)==4);
    onode_shutdown(&node);int wake=socket(AF_UNIX,SOCK_STREAM,0);struct sockaddr_un addr={.sun_family=AF_UNIX};strcpy(addr.sun_path,sock);(void)connect(wake,(struct sockaddr *)&addr,sizeof(addr));close(wake);pthread_join(thread,NULL);onode_destroy(&node);sqlite3_close(db);
    printf("PASS daemon: autonomous reboot, protected/unknown commands, observe/supervised, real peer identity, shadow bypass refusal, batch path, socket shutdown/signing refusal, UNKNOWN no replay; fixture %s\n",temp);return 0;
}
