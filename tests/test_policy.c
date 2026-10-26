#define _POSIX_C_SOURCE 200809L
#include "virp_policy.h"
#include "virp_onode.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>

static char *readall(const char *file) {
    FILE *f=fopen(file,"rb");assert(f);assert(!fseek(f,0,SEEK_END));long n=ftell(f);rewind(f);
    char *s=calloc(1,(size_t)n+1);assert(s);assert(fread(s,1,(size_t)n,f)==(size_t)n);fclose(f);return s;
}
static const char *config =
"{\"version\":1,\"max_calls\":3,\"max_disruptive\":1,\"max_inflight\":1,"
"\"protected\":[{\"device_id\":\"0000000000000011\",\"resource\":\"vm:105\",\"reason\":\"BLACK-03\"}],"
"\"principals\":[{\"uid\":1234,\"profile\":\"autonomous\",\"expires\":4102444800,\"rules\":["
"{\"device_id\":\"0000000000000011\",\"host\":\"127.0.0.1\",\"port\":22,\"vendor\":7,\"operation\":\"vm.delete\",\"resource\":\"vm:104\"},"
"{\"device_id\":\"0000000000000011\",\"host\":\"127.0.0.1\",\"port\":22,\"vendor\":7,\"operation\":\"vm.delete\",\"resource\":\"vm:105\"},"
"{\"device_id\":\"0000000000000011\",\"host\":\"127.0.0.1\",\"port\":22,\"vendor\":7,\"operation\":\"system.read\",\"resource\":\"host\"}]}]}";
static sqlite3 *database(void) {
    sqlite3 *db=NULL;assert(sqlite3_open(":memory:",&db)==SQLITE_OK);
    char *s=readall("deploy/policy-schema.sql");assert(sqlite3_exec(db,s,NULL,NULL,NULL)==SQLITE_OK);free(s);return db;
}
static char *replace(const char *s,const char *old,const char *value) {
    const char *at=strstr(s,old);assert(at);
    size_t n=strlen(s)+strlen(value)+1;char *out=calloc(1,n);assert(out);
    memcpy(out,s,(size_t)(at-s));strcat(out,value);strcat(out,at+strlen(old));return out;
}
static void classify_tests(void) {
    virp_policy_action_t a;
    const char *denied[]={"sudo shutdown -h now","sh -c reboot","nohup poweroff","kill -9 1","rm -rf /","cat /etc/shadow","curl example.com","qm destroy 104; qm destroy 105","qm destroy 00104","qm destroy 104 --purge","qm destroy 104\n","env X=1 reboot","reboot &","$(reboot)","python3 evil.py","systemctl stop virp","ssh other-host","dd if=/dev/zero of=/dev/sda"};
    for(size_t i=0;i<sizeof(denied)/sizeof(denied[0]);i++)assert(virp_policy_classify(VIRP_VENDOR_PROXMOX,denied[i],&a));
    assert(!virp_policy_classify(VIRP_VENDOR_CISCO_IOS," \tDo  ReLoAd ",&a));assert(a.effect==2&&!strcmp(a.command,"reload"));
    assert(!virp_policy_classify(VIRP_VENDOR_CISCO_ASA," RELOAD   NOCONFIRM ",&a));
    assert(!virp_policy_classify(VIRP_VENDOR_JUNIPER," request SYSTEM reboot ",&a));
    const char *netbad[]={"format flash0:","do do reload","interface Vlan999 description x","interface GigabitEthernet1/0/1 switchport mode dynamic auto","interface GigabitEthernet1/0/1.10 description x","interface range GigabitEthernet1/0/1 shutdown","interface GigabitEthernet1/0/1 switchport access vlan 010","interface GigabitEthernet1/0/1 switchport access vlan 4095"};
    for(size_t i=0;i<sizeof(netbad)/sizeof(netbad[0]);i++)assert(virp_policy_classify(VIRP_VENDOR_CISCO_IOS,netbad[i],&a));
    assert(!virp_policy_classify(VIRP_VENDOR_CISCO_IOS," interface GigabitEthernet1/0/1 DESCRIPTION Customer Port ",&a));
    assert(!strcmp(a.command,"interface GigabitEthernet1/0/1 description Customer Port"));
    assert(!virp_policy_classify(VIRP_VENDOR_CISCO_IOS,"interface GigabitEthernet1/0/1 switchport access vlan 81",&a));assert(a.vlan==81);
    assert(!virp_policy_reboot_permitted("reload"));
    virp_policy_dispatch_enter(&a);assert(!virp_policy_reboot_permitted(a.command));virp_policy_dispatch_leave();
    assert(!virp_policy_classify(VIRP_VENDOR_CISCO_IOS,"reload",&a));
    virp_policy_dispatch_enter(&a);assert(virp_policy_reboot_permitted("reload"));assert(!virp_policy_reboot_permitted("write erase"));virp_policy_dispatch_leave();
}
static void scope_tests(void) {
    sqlite3 *db=database();virp_policy_t *p=virp_policy_parse(config,db);assert(p);
    virp_device_t d={.vendor=VIRP_VENDOR_PROXMOX,.device_id=17,.port=22,.enabled=true};strcpy(d.host,"127.0.0.1");
    virp_policy_action_t a;const char *why=NULL;
    assert(!virp_policy_check(p,1234,&d,"qm destroy 104",&a,&why));assert(a.effect==2&&a.ceiling==VIRP_TIER_RED);
    assert(virp_policy_check(p,1234,&d,"qm destroy 105",&a,&why));assert(!strcmp(why,"BLACK-03"));
    assert(virp_policy_check(p,1235,&d,"qm destroy 104",&a,&why));
    assert(virp_policy_check(p,(uid_t)-1,&d,"qm destroy 104",&a,&why));
    d.port=23;assert(virp_policy_check(p,1234,&d,"qm destroy 104",&a,&why));d.port=22;
    d.device_id=18;assert(virp_policy_check(p,1234,&d,"qm destroy 104",&a,&why));d.device_id=17;
    assert(virp_policy_check(p,1234,&d,"qm destroy 106",&a,&why));
    assert(!virp_policy_check(p,1234,&d,"qm destroy 104",&a,&why));
    int64_t id=virp_policy_reserve(p,&a,&why);assert(id>0);
    assert(virp_policy_reserve(p,&a,&why)<0);
    assert(!virp_policy_finish(p,id,false));assert(virp_policy_reserve(p,&a,&why)<0);
    virp_policy_close(p);p=virp_policy_parse(config,db);assert(p);
    assert(virp_policy_reserve(p,&a,&why)<0); /* restart does not reset quota or uncertainty */
    assert(sqlite3_exec(db,"UPDATE policy_attempts SET state='reconciled'",NULL,NULL,NULL)==SQLITE_OK);
    assert(virp_policy_reserve(p,&a,&why)<0);assert(!strcmp(why,"BLACK-12"));
    assert(!virp_policy_check(p,1234,&d,"uptime",&a,&why));
    id=virp_policy_reserve(p,&a,&why);assert(id>0);assert(!virp_policy_finish(p,id,true));
    id=virp_policy_reserve(p,&a,&why);assert(id>0);assert(!virp_policy_finish(p,id,true));
    assert(virp_policy_reserve(p,&a,&why)<0);
    virp_policy_close(p);sqlite3_close(db);
    const char *profiles[]={"observe","supervised","autonomous"};
    for(int i=0;i<3;i++) {
        db=database();char *c=replace(config,"autonomous",profiles[i]);p=virp_policy_parse(c,db);assert(p);free(c);
        assert(!virp_policy_check(p,1234,&d,"uptime",&a,&why));assert(a.ceiling==(unsigned)i+1);
        virp_policy_close(p);sqlite3_close(db);
    }
}
struct job { virp_policy_t *p;virp_policy_action_t action;int64_t result; };
static void *reserve(void *v) { struct job *j=v;const char *why;j->result=virp_policy_reserve(j->p,&j->action,&why);return NULL; }
static void race_tests(void) {
    sqlite3 *db=database();virp_policy_t *p=virp_policy_parse(config,db);assert(p);
    virp_device_t d={.vendor=VIRP_VENDOR_PROXMOX,.device_id=17,.port=22,.enabled=true};strcpy(d.host,"127.0.0.1");
    struct job jobs[12];pthread_t threads[12];const char *why;
    for(int i=0;i<12;i++){jobs[i].p=p;assert(!virp_policy_check(p,1234,&d,"qm destroy 104",&jobs[i].action,&why));assert(!pthread_create(&threads[i],NULL,reserve,&jobs[i]));}
    int admitted=0;for(int i=0;i<12;i++){pthread_join(threads[i],NULL);admitted+=jobs[i].result>0;}assert(admitted==1);
    virp_policy_close(p);sqlite3_close(db);
}
static void malformed_tests(void) {
    const char *old[]={"\"version\":1","\"max_calls\":3","\"max_disruptive\":1","\"uid\":1234","autonomous","system.read","\"expires\":4102444800","\"protected\":"};
    const char *bad[]={"\"version\":1,\"version\":1","\"max_calls\":-1","\"max_disruptive\":1.5","\"uid\":0","passthrough","shell.exec","\"expires\":\"never\"","\"extra\":true,\"protected\":"};
    sqlite3 *db=database();for(size_t i=0;i<sizeof(old)/sizeof(old[0]);i++){char *s=replace(config,old[i],bad[i]);assert(!virp_policy_parse(s,db));free(s);}sqlite3_close(db);
    assert(virp_policy_secure_file("/tmp/untrusted-policy"));
    assert(virp_policy_secure_file("relative-policy"));
    assert(virp_policy_secure_file("/etc/../etc/passwd"));
}
static void stop_clock_failure_tests(void) {
    sqlite3 *db=database();virp_policy_t *p=virp_policy_parse(config,db);assert(p);
    virp_device_t d={.vendor=VIRP_VENDOR_PROXMOX,.device_id=17,.port=22,.enabled=true};strcpy(d.host,"127.0.0.1");
    virp_policy_action_t a;const char *why;assert(!virp_policy_check(p,1234,&d,"uptime",&a,&why));
    assert(sqlite3_exec(db,"UPDATE policy_control SET stopped=1",NULL,NULL,NULL)==SQLITE_OK);
    assert(virp_policy_reserve(p,&a,&why)<0);assert(!strcmp(why,"BLACK-01"));
    assert(sqlite3_exec(db,"UPDATE policy_control SET stopped=0,last_time=4102444800",NULL,NULL,NULL)==SQLITE_OK);
    assert(virp_policy_reserve(p,&a,&why)<0);assert(!strcmp(why,"BLACK-13"));
    assert(sqlite3_exec(db,"UPDATE policy_control SET last_time=0; PRAGMA query_only=ON",NULL,NULL,NULL)==SQLITE_OK);
    assert(virp_policy_reserve(p,&a,&why)<0);
    virp_policy_close(p);sqlite3_close(db);
}
static void containment_tests(void) {
    sqlite3 *db=database();const char *why;virp_policy_action_t a;
    virp_device_t d={.vendor=VIRP_VENDOR_PROXMOX,.device_id=17,.port=22,.enabled=true};strcpy(d.host,"127.0.0.1");
    char *c=replace(config,"vm.delete","host.reboot"),*next=replace(c,"vm:104","host");free(c);
    virp_policy_t *p=virp_policy_parse(next,db);assert(p);free(next);
    /* A protected VM also protects against rebooting its parent host. */
    assert(virp_policy_check(p,1234,&d,"reboot",&a,&why));assert(!strcmp(why,"BLACK-03"));
    virp_policy_close(p);sqlite3_close(db);
    db=database();c=replace(config,"autonomous","observe");p=virp_policy_parse(c,db);free(c);assert(p);
    assert(virp_policy_check(p,1234,&d,"qm destroy 104",&a,&why));
    virp_policy_close(p);sqlite3_close(db);
    db=database();c=replace(config,"\"max_disruptive\":1","\"max_disruptive\":10");p=virp_policy_parse(c,db);free(c);assert(p);
    assert(!virp_policy_check(p,1234,&d,"qm destroy 104",&a,&why));
    int64_t id=virp_policy_reserve(p,&a,&why);assert(id>0);assert(!virp_policy_finish(p,id,false));
    assert(virp_policy_reserve(p,&a,&why)<0);assert(!strcmp(why,"BLACK-14"));
    /* Read-only diagnosis remains possible while mutation is quarantined. */
    assert(!virp_policy_check(p,1234,&d,"uptime",&a,&why));id=virp_policy_reserve(p,&a,&why);assert(id>0);assert(!virp_policy_finish(p,id,true));
    virp_policy_close(p);sqlite3_close(db);
    db=database();const char *vlan="{\"version\":1,\"max_calls\":10,\"max_disruptive\":0,\"max_inflight\":1,\"protected\":[],\"principals\":[{\"uid\":1234,\"profile\":\"autonomous\",\"expires\":4102444800,\"rules\":[{\"device_id\":\"0000000000000011\",\"host\":\"127.0.0.1\",\"port\":22,\"vendor\":1,\"operation\":\"port.vlan\",\"resource\":\"port:GigabitEthernet1/0/1\",\"vlan_min\":80,\"vlan_max\":89}]}]}";
    p=virp_policy_parse(vlan,db);assert(p);d.vendor=VIRP_VENDOR_CISCO_IOS;
    assert(!virp_policy_check(p,1234,&d,"interface GigabitEthernet1/0/1 switchport access vlan 81",&a,&why));
    assert(virp_policy_check(p,1234,&d,"interface GigabitEthernet1/0/1 switchport access vlan 20",&a,&why));assert(!strcmp(why,"BLACK-09"));
    assert(virp_policy_check(p,1234,&d,"interface GigabitEthernet1/0/2 switchport access vlan 81",&a,&why));
    virp_policy_close(p);sqlite3_close(db);
}
static void crash_journal_test(void) {
    char path[]="/tmp/virp-policy-crash-XXXXXX";int fd=mkstemp(path);assert(fd>=0);close(fd);
    pid_t child=fork();assert(child>=0);
    if(!child) {
        sqlite3 *db=NULL;assert(sqlite3_open(path,&db)==SQLITE_OK);
        char *schema=readall("deploy/policy-schema.sql");assert(sqlite3_exec(db,schema,NULL,NULL,NULL)==SQLITE_OK);free(schema);
        virp_policy_t *p=virp_policy_parse(config,db);assert(p);
        virp_device_t d={.vendor=VIRP_VENDOR_PROXMOX,.device_id=17,.port=22,.enabled=true};strcpy(d.host,"127.0.0.1");
        virp_policy_action_t a;const char *why;
        assert(!virp_policy_check(p,1234,&d,"qm destroy 104",&a,&why));assert(virp_policy_reserve(p,&a,&why)>0);
        _exit(0); /* crash boundary: no finish, sqlite_close, or policy cleanup */
    }
    int status;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
    sqlite3 *db=NULL;assert(sqlite3_open(path,&db)==SQLITE_OK);
    sqlite3_stmt *st=NULL;assert(sqlite3_prepare_v2(db,"SELECT calls,disruptive,(SELECT COUNT(*) FROM policy_attempts WHERE state='pending') FROM policy_control",-1,&st,NULL)==SQLITE_OK);
    assert(sqlite3_step(st)==SQLITE_ROW);assert(sqlite3_column_int(st,0)==1&&sqlite3_column_int(st,1)==1&&sqlite3_column_int(st,2)==1);sqlite3_finalize(st);
    virp_policy_t *p=virp_policy_parse(config,db);assert(p);
    virp_device_t d={.vendor=VIRP_VENDOR_PROXMOX,.device_id=17,.port=22,.enabled=true};strcpy(d.host,"127.0.0.1");
    virp_policy_action_t a;const char *why;assert(!virp_policy_check(p,1234,&d,"qm destroy 104",&a,&why));assert(virp_policy_reserve(p,&a,&why)<0);
    virp_policy_close(p);sqlite3_close(db);unlink(path);
}
static void collector_tests(void) {
    sqlite3 *db=database();char *c=replace(config,"\"version\":1","\"trusted_appenders\":[{\"uid\":4321,\"types\":[\"evidence_item\"]}],\"version\":1");
    virp_policy_t *p=virp_policy_parse(c,db);assert(p);
    assert(virp_policy_can_append(p,4321,"evidence_item"));
    assert(!virp_policy_can_append(p,1234,"evidence_item"));
    assert(!virp_policy_can_append(p,4321,"observation"));
    assert(!virp_policy_can_append(p,4322,"evidence_item"));
    virp_device_t d={.vendor=VIRP_VENDOR_PROXMOX,.device_id=17,.port=22,.enabled=true};strcpy(d.host,"127.0.0.1");
    virp_policy_action_t a;const char *why;assert(virp_policy_check(p,4321,&d,"uptime",&a,&why));
    virp_policy_close(p);
    char *bad=replace(c,"4321","1234");assert(!virp_policy_parse(bad,db));free(bad);
    bad=replace(c,"evidence_item","observation");assert(!virp_policy_parse(bad,db));free(bad);
    free(c);sqlite3_close(db);
}
int main(void) {
    classify_tests();scope_tests();race_tests();malformed_tests();stop_clock_failure_tests();containment_tests();crash_journal_test();collector_tests();
    puts("PASS policy: closed grammar, identity/target scope, profiles, protected resources, quotas, concurrency, restart, STOP, uncertainty and storage failure");return 0;
}
