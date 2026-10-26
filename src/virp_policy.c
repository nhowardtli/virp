#define _POSIX_C_SOURCE 200809L
#include "virp_policy.h"
#include "third_party/cJSON.h"
#include <openssl/evp.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <limits.h>

struct virp_policy {
    cJSON *root;
    sqlite3 *db;
    pthread_mutex_t lock;
    bool owns_db;
    int custody_fd;
    time_t start_wall;
    struct timespec start_mono;
    char digest[65];
};
static _Thread_local const virp_policy_action_t *dispatch_action;
void virp_policy_dispatch_enter(const virp_policy_action_t *a) { dispatch_action=a; }
void virp_policy_dispatch_leave(void) { dispatch_action=NULL; }
bool virp_policy_reboot_permitted(const char *command) {
    return dispatch_action && !strcmp(dispatch_action->operation,"host.reboot") &&
        !strcmp(dispatch_action->command,command);
}

static int normalize(const char *in,char out[512]) {
    size_t n=0; bool space=false;
    if (!in || strlen(in)>=512) return -1;
    for (const unsigned char *s=(const unsigned char *)in;*s;s++) {
        if (*s==' ' || *s=='\t') { if(n) space=true; continue; }
        /* Shell operators, quoting, escapes, control/Unicode and expansion are
         * outside the supported grammar, including within descriptions. */
        if (*s<33 || *s>126 || strchr(";|&$`<>\\\"'{}[]!",*s)) return -1;
        if(space) out[n++]=' ';
        space=false; out[n++]=(char)*s;
    }
    out[n]=0; return n ? 0:-1;
}
static bool number(const char *s,unsigned *v) {
    if(!s || !*s || (*s=='0' && s[1])) return false;
    unsigned long x=0;
    for(;*s;s++) { if(*s<'0'||*s>'9')return false; x=x*10+(unsigned)(*s-'0'); if(x>100000000)return false; }
    *v=(unsigned)x;return true;
}
static bool physical(const char *s) {
    static const char *names[]={"Ethernet","GigabitEthernet"};
    for(size_t i=0;i<sizeof(names)/sizeof(names[0]);i++) {
        size_t n=strlen(names[i]); if(strncasecmp(s,names[i],n))continue;
        const char *t=s+n;bool digit=false;
        if(!isdigit((unsigned char)*t))return false;
        for(;*t;t++) { if(isdigit((unsigned char)*t))digit=true; else if(*t=='/'&&digit)digit=false;else return false; }
        return digit;
    }
    return false;
}
static int op(virp_policy_action_t *a,const char *name,unsigned effect) {
    snprintf(a->operation,sizeof(a->operation),"%s",name);a->effect=effect;return 0;
}
int virp_policy_classify(virp_vendor_t v,const char *cmd,virp_policy_action_t *a) {
    if(!a)return -1;
    memset(a,0,sizeof(*a)); if(normalize(cmd,a->command))return -1;
    snprintf(a->resource,sizeof(a->resource),"host");
    bool cisco=v==VIRP_VENDOR_CISCO_IOS||v==VIRP_VENDOR_CISCO_IOSXE;
    bool cli=cisco||v==VIRP_VENDOR_CISCO_ASA||v==VIRP_VENDOR_JUNIPER||v==VIRP_VENDOR_FORTINET;
    if(cli) {
        /* Normalize keywords consistently. Description payload case is kept. */
        char lower[512];
        for(size_t i=0;i<=strlen(a->command);i++)lower[i]=(char)tolower((unsigned char)a->command[i]);
        char *desc=strstr(lower," description ");
        size_t limit=desc?(size_t)(desc-lower)+13:strlen(lower);
        for(size_t i=0;i<limit;i++)a->command[i]=lower[i];
        if(cisco && !strncmp(a->command,"do ",3))memmove(a->command,a->command+3,strlen(a->command+3)+1);
    }
    const char *s=a->command;
    if((cli && (!strcmp(s,"show version")||!strcmp(s,"show clock")||!strcmp(s,"show interfaces")||!strcmp(s,"show interfaces status")||!strcmp(s,"show ip route"))) ||
       (v==VIRP_VENDOR_FORTINET && !strcmp(s,"get system status")) ||
       ((v==VIRP_VENDOR_LINUX||v==VIRP_VENDOR_PROXMOX||v==VIRP_VENDOR_MOCK) && (!strcmp(s,"uptime")||!strcmp(s,"hostname")||!strcmp(s,"uname -sr"))) ||
       (v==VIRP_VENDOR_MOCK && !strcmp(s,"show version")))return op(a,"system.read",0);
    if((cisco && !strcmp(s,"reload")) || (v==VIRP_VENDOR_CISCO_ASA && !strcmp(s,"reload noconfirm")) ||
       (v==VIRP_VENDOR_JUNIPER && !strcmp(s,"request system reboot")) ||
       (v==VIRP_VENDOR_FORTINET && !strcmp(s,"execute reboot")) ||
       ((v==VIRP_VENDOR_LINUX||v==VIRP_VENDOR_PROXMOX||v==VIRP_VENDOR_MOCK) && (!strcmp(s,"reboot")||!strcmp(s,"systemctl reboot"))))return op(a,"host.reboot",2);
    if(v==VIRP_VENDOR_LINUX||v==VIRP_VENDOR_PROXMOX) {
        char tool[8],verb[16],id[16],tail;unsigned vmid;
        if(sscanf(s,"%7s %15s %15s %c",tool,verb,id,&tail)==3 &&
           (!strcmp(tool,"qm")||!strcmp(tool,"pct"))&&number(id,&vmid)&&vmid>=100) {
            snprintf(a->resource,sizeof(a->resource),"%s:%u",!strcmp(tool,"qm")?"vm":"ct",vmid);
            if(!strcmp(verb,"status"))return op(a,"vm.read",0);
            if(!strcmp(verb,"reboot"))return op(a,"vm.reboot",2);
            if(!strcmp(verb,"destroy"))return op(a,"vm.delete",2);
            if(!strcmp(verb,"start"))return op(a,"vm.start",1);
        }
    }
    if(cisco && !strncmp(s,"interface ",10)) {
        const char *end=strchr(s+10,' ');if(!end || end-s-10>=80)return -1;
        char port[80];memcpy(port,s+10,(size_t)(end-s-10));port[end-s-10]=0;
        if(!physical(port))return -1;
        snprintf(a->resource,sizeof(a->resource),"port:%s",port);
        char line_copy[384];snprintf(line_copy,sizeof(line_copy),"%s",end+1);
        const char *line=line_copy;
        const char *prefix=!strncasecmp(port,"gigabitethernet",14)?"GigabitEthernet":"Ethernet";
        const char *suffix=port+strlen(prefix);
        snprintf(a->command,sizeof(a->command),"interface %s%s %s",prefix,suffix,line);
        if(!strncmp(line,"description ",12) && line[12] && strlen(line+12)<=128)return op(a,"port.description",1);
        if(!strncmp(line,"switchport access vlan ",23)&&number(line+23,&a->vlan)&&a->vlan>=1&&a->vlan<=4094)return op(a,"port.vlan",1);
        if(!strcmp(line,"switchport mode access"))return op(a,"port.access",1);
        /* DTP, trunk changes, interface creation and security weakening have
         * no executable representation in this catalog. */
    }
    return -1;
}
static cJSON *get(cJSON *o,const char *key) { return cJSON_GetObjectItemCaseSensitive(o,key); }
static const char *str(cJSON *o,const char *key) { cJSON *x=get(o,key);return cJSON_IsString(x)?x->valuestring:NULL; }
static bool integer(cJSON *o,const char *key,double min,double max) {
    cJSON *x=get(o,key);return cJSON_IsNumber(x)&&x->valuedouble>=min&&x->valuedouble<=max&&x->valuedouble==(double)(int64_t)x->valuedouble;
}
static int64_t num(cJSON *o,const char *key) { return (int64_t)get(o,key)->valuedouble; }
static bool fields(cJSON *o,const char *names) {
    if(!cJSON_IsObject(o))return false;
    for(cJSON *x=o->child;x;x=x->next) {
        if(!x->string)return false;
        char k[80];if(snprintf(k,sizeof(k),"|%s|",x->string)>=(int)sizeof(k)||!strstr(names,k))return false;
        for(cJSON *y=x->next;y;y=y->next)if(!strcmp(x->string,y->string))return false;
    }
    return true;
}
static bool ident(const char *s,size_t max) {
    if(!s || !*s || strlen(s)>=max)return false;
    for(;*s;s++)if(!isalnum((unsigned char)*s)&&!strchr("._:-/",*s))return false;
    return true;
}
static bool device_id(const char *s) {
    if(!s||strlen(s)!=16)return false;
    for(int i=0;i<16;i++)if(!isdigit((unsigned char)s[i])&&(s[i]<'a'||s[i]>'f'))return false;
    return strcmp(s,"0000000000000000")!=0;
}
static const char *operations[]={"system.read","host.reboot","vm.read","vm.reboot","vm.delete","vm.start","port.description","port.vlan","port.access"};
static bool valid_op(const char *s) { if(!s)return false;for(size_t i=0;i<sizeof(operations)/sizeof(operations[0]);i++)if(!strcmp(s,operations[i]))return true;return false; }
static bool valid_reason(const char *s) { return s&&strlen(s)==8&&!strncmp(s,"BLACK-",6)&&s[6]>='0'&&s[6]<='1'&&s[7]>='0'&&s[7]<='9'&&atoi(s+6)>=1&&atoi(s+6)<=14; }
virp_policy_t *virp_policy_parse(const char *json,sqlite3 *db) {
    if(!json||!db||strlen(json)>1024*1024||strstr(json,"\\u0000"))return NULL;
    cJSON *r=cJSON_ParseWithOpts(json,NULL,1);
    if(!fields(r,"|version||max_calls||max_disruptive||max_inflight||principals||protected||trusted_appenders|")||!integer(r,"version",1,1)||
       !integer(r,"max_calls",1,1000000)||!integer(r,"max_disruptive",0,1000000)||!integer(r,"max_inflight",1,64))goto bad;
    cJSON *ps=get(r,"principals"),*protected=get(r,"protected");
    if(!cJSON_IsArray(ps)||cJSON_GetArraySize(ps)>64||!cJSON_IsArray(protected)||cJSON_GetArraySize(protected)>512)goto bad;
    cJSON *x; cJSON_ArrayForEach(x,protected) {
        if(!fields(x,"|device_id||resource||reason|")||!device_id(str(x,"device_id"))||
           !(ident(str(x,"resource"),96)||(str(x,"resource")&&!strcmp(str(x,"resource"),"*")))||!valid_reason(str(x,"reason")))goto bad;
    }
    cJSON_ArrayForEach(x,ps) {
        const char *profile=str(x,"profile");
        if(!fields(x,"|uid||profile||expires||rules|")||!integer(x,"uid",1,UINT_MAX-1)||!integer(x,"expires",1,4102444800.0)||!profile||
           (strcmp(profile,"observe")&&strcmp(profile,"supervised")&&strcmp(profile,"autonomous")))goto bad;
        for(cJSON *y=x->next;y;y=y->next)if(cJSON_IsNumber(get(y,"uid"))&&num(y,"uid")==num(x,"uid"))goto bad;
        cJSON *rules=get(x,"rules"),*rule;
        if(!cJSON_IsArray(rules)||cJSON_GetArraySize(rules)>512)goto bad;
        cJSON_ArrayForEach(rule,rules) {
            if(!fields(rule,"|device_id||host||port||vendor||operation||resource||vlan_min||vlan_max|")||!device_id(str(rule,"device_id"))||
               !ident(str(rule,"host"),256)||!integer(rule,"port",1,65535)||!integer(rule,"vendor",1,99)||!valid_op(str(rule,"operation"))||!ident(str(rule,"resource"),96))goto bad;
            if(!strcmp(str(rule,"operation"),"port.vlan")) {
                if(!integer(rule,"vlan_min",1,4094)||!integer(rule,"vlan_max",1,4094)||num(rule,"vlan_min")>num(rule,"vlan_max"))goto bad;
            } else if(get(rule,"vlan_min")||get(rule,"vlan_max"))goto bad;
        }
    }
    cJSON *appenders=get(r,"trusted_appenders");
    if(appenders) {
        if(!cJSON_IsArray(appenders)||cJSON_GetArraySize(appenders)>16)goto bad;
        cJSON_ArrayForEach(x,appenders) {
            if(!fields(x,"|uid||types|")||!integer(x,"uid",1,UINT_MAX-1))goto bad;
            cJSON *types=get(x,"types"),*type;
            if(!cJSON_IsArray(types)||cJSON_GetArraySize(types)!=1)goto bad;
            cJSON_ArrayForEach(type,types)if(!cJSON_IsString(type)||strcmp(type->valuestring,"evidence_item"))goto bad;
            cJSON *principal;cJSON_ArrayForEach(principal,ps)if(num(principal,"uid")==num(x,"uid"))goto bad;
            for(cJSON *y=x->next;y;y=y->next)if(cJSON_IsNumber(get(y,"uid"))&&num(y,"uid")==num(x,"uid"))goto bad;
        }
    }
    sqlite3_stmt *st=NULL;
    if(sqlite3_prepare_v2(db,"SELECT version,stopped,calls,disruptive,last_time FROM policy_control WHERE id=1",-1,&st,NULL)!=SQLITE_OK)goto bad;
    bool schema=sqlite3_step(st)==SQLITE_ROW&&sqlite3_column_int(st,0)==1;
    sqlite3_finalize(st);if(!schema)goto bad;
    virp_policy_t *p=calloc(1,sizeof(*p));if(!p)goto bad;
    p->root=r;p->db=db;p->custody_fd=-1;p->start_wall=time(NULL);
    clock_gettime(CLOCK_MONOTONIC,&p->start_mono);pthread_mutex_init(&p->lock,NULL);
    unsigned char digest[32];unsigned n=0;
    if(!EVP_Digest(json,strlen(json),digest,&n,EVP_sha256(),NULL)||n!=32){virp_policy_close(p);return NULL;}
    for(unsigned i=0;i<32;i++)snprintf(p->digest+2*i,3,"%02x",digest[i]);
    return p;
bad:cJSON_Delete(r);return NULL;
}

/* Walk every component using directory FDs: no symlinks, writable ancestors,
 * hardlinks or non-root custody. Return an open descriptor, not a checked name. */
static int secure_open(const char *path,int flags,bool runtime) {
    if(!path||path[0]!='/'||strlen(path)>=PATH_MAX)return -1;
    char buf[PATH_MAX];snprintf(buf,sizeof(buf),"%s",path+1);
    int dir=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(dir<0)return -1;
    char *save=NULL,*part=strtok_r(buf,"/",&save);if(!part){close(dir);return -1;}
    while(part) {
        if(!strcmp(part,".")||!strcmp(part,"..")){close(dir);return -1;}
        char *next=strtok_r(NULL,"/",&save);
        int fd=openat(dir,part,(next?O_RDONLY|O_DIRECTORY:flags)|O_NOFOLLOW|O_CLOEXEC);
        close(dir);if(fd<0)return -1;
        struct stat st;
        if(fstat(fd,&st)||(st.st_uid!=0&&(!runtime||st.st_uid!=geteuid()))||(st.st_mode&022)||(!next&&(!S_ISREG(st.st_mode)||st.st_nlink!=1))){close(fd);return -1;}
        dir=fd;part=next;
    }
    return dir;
}
int virp_policy_secure_file(const char *path) { int fd=secure_open(path,O_RDONLY,false);if(fd<0)return -1;close(fd);return 0; }
int virp_policy_secure_runtime_file(const char *path) { int fd=secure_open(path,O_RDONLY,true);if(fd<0)return -1;close(fd);return 0; }
virp_policy_t *virp_policy_load(const char *path,const char *journal) {
    int fd=secure_open(path,O_RDONLY,false);if(fd<0)return NULL;
    struct stat st;if(fstat(fd,&st)||st.st_size<2||st.st_size>1024*1024){close(fd);return NULL;}
    char *s=calloc(1,(size_t)st.st_size+1);if(!s){close(fd);return NULL;}
    size_t used=0;
    while(used<(size_t)st.st_size){ssize_t n=read(fd,s+used,(size_t)st.st_size-used);if(n<=0)break;used+=(size_t)n;}
    close(fd);if(used!=(size_t)st.st_size||strlen(s)!=used){free(s);return NULL;}
    int jf=secure_open(journal,O_RDWR,true);if(jf<0){free(s);return NULL;}
    struct stat before,after;int sr=fstat(jf,&before);
    if(sr || (before.st_mode & 077) || flock(jf,LOCK_EX|LOCK_NB)){close(jf);free(s);return NULL;}
    sqlite3 *db=NULL;
    if(sr||sqlite3_open_v2(journal,&db,SQLITE_OPEN_READWRITE|SQLITE_OPEN_FULLMUTEX|SQLITE_OPEN_NOFOLLOW,NULL)!=SQLITE_OK){close(jf);sqlite3_close(db);free(s);return NULL;}
    /* Root-only ancestors prevent rename races by agent identities. */
    if(lstat(journal,&after)||before.st_dev!=after.st_dev||before.st_ino!=after.st_ino){close(jf);sqlite3_close(db);free(s);return NULL;}
    sqlite3_busy_timeout(db,5000);
    if(sqlite3_exec(db,"PRAGMA trusted_schema=OFF;PRAGMA synchronous=FULL;PRAGMA foreign_keys=ON;",NULL,NULL,NULL)!=SQLITE_OK){close(jf);sqlite3_close(db);free(s);return NULL;}
    virp_policy_t *p=virp_policy_parse(s,db);free(s);
    if(!p){sqlite3_close(db);close(jf);}else {
        p->owns_db=true;p->custody_fd=jf;
        cJSON *principal; cJSON_ArrayForEach(principal,get(p->root,"principals")) {
            if(num(principal,"uid")==geteuid()){virp_policy_close(p);return NULL;}
        }
        cJSON_ArrayForEach(principal,get(p->root,"trusted_appenders")) {
            if(num(principal,"uid")==geteuid()){virp_policy_close(p);return NULL;}
        }
        /* Exclusive custody proves no other production dispatcher owns these
         * pending attempts. A prior process may have acted before crashing. */
        if(sqlite3_exec(db,"UPDATE policy_attempts SET state='unknown' WHERE state='pending'",NULL,NULL,NULL)!=SQLITE_OK){virp_policy_close(p);return NULL;}
    }
    return p;
}
void virp_policy_close(virp_policy_t *p) { if(!p)return;cJSON_Delete(p->root);if(p->owns_db)sqlite3_close(p->db);if(p->custody_fd>=0)close(p->custody_fd);pthread_mutex_destroy(&p->lock);free(p); }
bool virp_policy_can_append(virp_policy_t *p,uid_t uid,const char *type) {
    if(!p||!type||strcmp(type,"evidence_item"))return false;
    cJSON *x;cJSON_ArrayForEach(x,get(p->root,"trusted_appenders"))
        if(num(x,"uid")==uid)return true;
    return false;
}
int virp_policy_check(virp_policy_t *p,uid_t uid,const virp_device_t *d,const char *command,virp_policy_action_t *a,const char **why) {
    *why="BLACK-13";
    if(!p||!d||!d->enabled||uid==(uid_t)-1||virp_policy_classify(d->vendor,command,a))return -1;
    a->uid=uid;a->device_id=d->device_id;
    char id[17];snprintf(id,sizeof(id),"%016llx",(unsigned long long)d->device_id);
    cJSON *x;if(a->effect)cJSON_ArrayForEach(x,get(p->root,"protected")) {
        if(!strcmp(id,str(x,"device_id"))&&(!strcmp(str(x,"resource"),"*")||!strcasecmp(str(x,"resource"),"host")||!strcasecmp(a->resource,str(x,"resource"))||(a->effect==2&&!strcmp(a->resource,"host")))){*why=str(x,"reason");return -1;}
    }
    cJSON_ArrayForEach(x,get(p->root,"principals")) {
        if(num(x,"uid")!=(int64_t)uid)continue;
        if((int64_t)time(NULL)>=num(x,"expires"))return -1;
        const char *profile=str(x,"profile");
        if(!strcmp(profile,"observe")&&a->effect)return -1;
        a->ceiling=!strcmp(profile,"observe")?VIRP_TIER_GREEN:!strcmp(profile,"supervised")?VIRP_TIER_YELLOW:VIRP_TIER_RED;
        cJSON *rule;cJSON_ArrayForEach(rule,get(x,"rules")) {
            if(strcmp(id,str(rule,"device_id"))||strcmp(d->host,str(rule,"host"))||d->port!=num(rule,"port")||d->vendor!=num(rule,"vendor")||
               strcmp(a->operation,str(rule,"operation"))||strcasecmp(a->resource,str(rule,"resource")))continue;
            if(a->vlan&&(a->vlan<num(rule,"vlan_min")||a->vlan>num(rule,"vlan_max"))){*why="BLACK-09";return -1;}
            *why=NULL;return 0;
        }
    }
    return -1;
}

int64_t virp_policy_reserve(virp_policy_t *p,const virp_policy_action_t *a,const char **why) {
    *why="BLACK-10";if(!p||!a)return -1;
    pthread_mutex_lock(&p->lock);sqlite3_stmt *st=NULL;int64_t id=-1;bool txn=false;
    if(sqlite3_exec(p->db,"BEGIN IMMEDIATE",NULL,NULL,NULL)!=SQLITE_OK)goto done;
    txn=true;
    if(sqlite3_prepare_v2(p->db,"SELECT stopped,calls,disruptive,last_time,(SELECT COUNT(*) FROM policy_attempts WHERE state='pending') FROM policy_control WHERE id=1",-1,&st,NULL)!=SQLITE_OK)goto done;
    if(sqlite3_step(st)!=SQLITE_ROW)goto done;
    int64_t now=(int64_t)time(NULL);bool expired=true;cJSON *x;
    struct timespec mono;
    if(clock_gettime(CLOCK_MONOTONIC,&mono) || now < p->start_wall + (mono.tv_sec-p->start_mono.tv_sec)-1){*why="BLACK-13";goto done;}
    cJSON_ArrayForEach(x,get(p->root,"principals"))if(num(x,"uid")==a->uid&&now<num(x,"expires"))expired=false;
    if(expired||now<sqlite3_column_int64(st,3)){*why="BLACK-13";goto done;}
    if(sqlite3_column_int(st,0)){*why="BLACK-01";goto done;}
    if(sqlite3_column_int64(st,1)>=num(p->root,"max_calls")||
       (a->effect==2&&sqlite3_column_int64(st,2)>=num(p->root,"max_disruptive"))){*why="BLACK-12";goto done;}
    if(sqlite3_column_int64(st,4)>=num(p->root,"max_inflight")){*why="BLACK-06";goto done;}
    sqlite3_finalize(st);st=NULL;
    /* Any ambiguous previous dispatch stops mutation, even when concurrency
     * allowance is greater than one. Reads cannot clear the uncertainty. */
    if(a->effect) {
        if(sqlite3_prepare_v2(p->db,"SELECT COUNT(*) FROM policy_attempts WHERE state='unknown' OR (state='pending' AND device_id=? AND (resource=? COLLATE NOCASE OR resource='host' OR ?='host'))",-1,&st,NULL)!=SQLITE_OK)goto done;
        sqlite3_bind_int64(st,1,(sqlite3_int64)a->device_id);sqlite3_bind_text(st,2,a->resource,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,3,a->resource,-1,SQLITE_TRANSIENT);
        if(sqlite3_step(st)!=SQLITE_ROW||sqlite3_column_int64(st,0)){*why="BLACK-14";goto done;}
        sqlite3_finalize(st);st=NULL;
    }
    if(sqlite3_prepare_v2(p->db,"INSERT INTO policy_attempts(uid,device_id,operation,resource,command,policy_hash,state,created) VALUES(?,?,?,?,?,?,'pending',?)",-1,&st,NULL)!=SQLITE_OK)goto done;
    sqlite3_bind_int64(st,1,a->uid);sqlite3_bind_int64(st,2,(sqlite3_int64)a->device_id);
    sqlite3_bind_text(st,3,a->operation,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,4,a->resource,-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(st,5,a->command,-1,SQLITE_TRANSIENT);sqlite3_bind_text(st,6,p->digest,-1,SQLITE_TRANSIENT);sqlite3_bind_int64(st,7,now);
    if(sqlite3_step(st)!=SQLITE_DONE)goto done;
    id=sqlite3_last_insert_rowid(p->db);sqlite3_finalize(st);st=NULL;
    if(sqlite3_prepare_v2(p->db,"UPDATE policy_control SET calls=calls+1,disruptive=disruptive+?,last_time=? WHERE id=1",-1,&st,NULL)!=SQLITE_OK){id=-1;goto done;}
    sqlite3_bind_int(st,1,a->effect==2);sqlite3_bind_int64(st,2,now);
    if(sqlite3_step(st)!=SQLITE_DONE){id=-1;goto done;}
    sqlite3_finalize(st);st=NULL;
    if(sqlite3_exec(p->db,"COMMIT",NULL,NULL,NULL)!=SQLITE_OK){id=-1;goto done;}
    txn=false;*why=NULL;
done:sqlite3_finalize(st);if(txn)sqlite3_exec(p->db,"ROLLBACK",NULL,NULL,NULL);pthread_mutex_unlock(&p->lock);return id;
}
int virp_policy_finish(virp_policy_t *p,int64_t id,bool known) {
    if(!p||id<=0)return -1;
    pthread_mutex_lock(&p->lock);sqlite3_stmt *st=NULL;int rc=-1;
    if(sqlite3_prepare_v2(p->db,"UPDATE policy_attempts SET state=? WHERE id=? AND state='pending'",-1,&st,NULL)==SQLITE_OK) {
        sqlite3_bind_text(st,1,known?"done":"unknown",-1,SQLITE_STATIC);sqlite3_bind_int64(st,2,id);
        if(sqlite3_step(st)==SQLITE_DONE&&sqlite3_changes(p->db)==1)rc=0;
    }
    sqlite3_finalize(st);pthread_mutex_unlock(&p->lock);return rc;
}
