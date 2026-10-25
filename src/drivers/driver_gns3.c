/* Third Level Lab: bounded GNS3 lifecycle via a private pinned-TLS controller.
 * No arbitrary URLs, project ids, templates, JSON or shell commands.
 * Observation and chain formats are unchanged: O-Node wraps all outcomes.
 */
#define _POSIX_C_SOURCE 200809L
#include "virp_driver.h"
#include "cJSON.h"
#include <curl/curl.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
struct virp_conn { virp_device_t device; };
static int uuid_ok(const char *s) {
    if (strlen(s)!=36) return 0;
    for (int i=0;i<36;i++) {
        if (i==8||i==13||i==18||i==23) { if(s[i]!='-') return 0; }
        else if (!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f'))) return 0;
    }
    return 1;
}
/* Exact operation and canonical UUID bytes only; no CLI abbreviations. */
int gns3_operation(const char *s) {
    if(!s) return 0;
    if(!strcmp(s,"lab health")) return 1;
    const char *prefix[]={"lab status ","lab create ","lab delete ","lab start ","lab stop ","lab configure ","lab test ","lab isolate ","lab repair "};
    for(int i=0;i<9;i++) if(!strncmp(s,prefix[i],strlen(prefix[i])) && uuid_ok(s+strlen(prefix[i]))) return i+2;
    return 0;
}
virp_trust_tier_t gns3_gate_tier(const char *s) {
    int op=gns3_operation(s);
    if(op==1||op==2||op==8) return VIRP_TIER_GREEN;
    if(op>=3&&op<=10&&op!=8) return VIRP_TIER_YELLOW;
    return VIRP_TIER_RED;
}
static const char *reason(const char *s) {
    switch(gns3_operation(s)) {
    case 1:return "Read controller health without exposing other sessions.";
    case 2:return "Read this evaluation's isolated lab state.";
    case 3:return "Create one fixed isolated lab, bounded by ownership and resource caps.";
    case 4:return "Remove only the isolated lab owned by this evaluation.";
    case 8:return "Test connectivity only between this lab's two fixed endpoints.";
    case 5:case 6:case 7:case 9:case 10:return "Manage only the fixed endpoints and links inside this evaluation's isolated lab.";
    default:return "No supported bounded lab operation matches these exact bytes.";
    }
}
static virp_conn_t *connect_controller(const virp_device_t *d) {
    if(!d || strcmp(d->host,"10.0.50.103") || d->port!=7443 || !d->api_token[0]) return NULL;
    struct virp_conn *c=calloc(1,sizeof(*c));if(c)c->device=*d;return c;
}
static size_t collect(char *ptr,size_t size,size_t n,void *ctx) {
    virp_exec_result_t *r=ctx;
    if(size && n>(size_t)-1/size) return 0;
    size_t bytes=size*n;
    if(bytes>=sizeof(r->output)-r->output_len){r->output_truncated=true;return 0;}
    memcpy(r->output+r->output_len,ptr,bytes);r->output_len+=bytes;r->output[r->output_len]=0;return bytes;
}
static virp_error_t execute(virp_conn_t *raw,const char *cmd,virp_exec_result_t *r) {
    if(!r) return VIRP_ERR_NULL_PTR;
    memset(r,0,sizeof(*r));r->no_dispatch=true;r->disposition=VIRP_DISPOSITION_NOT_SENT;r->exit_code=1;
    struct virp_conn *c=raw;int op=gns3_operation(cmd);
    if(!c||!op){snprintf(r->error_msg,sizeof(r->error_msg),"Unsupported lab operation");return VIRP_OK;}
    /* Write permission is per device, in addition to the native caller tier. */
    if((op>=3&&op<=10&&op!=8)&&strcmp(c->device.write_ops_allow,"isolated-lab-manage")) {
        snprintf(r->error_msg,sizeof(r->error_msg),"Lab lifecycle writes disabled on this controller");return VIRP_OK;
    }
    const char *ca=getenv("VIRP_GNS3_CA");
    if(!ca||ca[0]!='/'){snprintf(r->error_msg,sizeof(r->error_msg),"Controller trust anchor missing");return VIRP_OK;}
    cJSON *body=cJSON_CreateObject();if(!body)return VIRP_ERR_NULL_PTR;
    cJSON_AddStringToObject(body,"command",cmd);char *json=cJSON_PrintUnformatted(body);cJSON_Delete(body);
    CURL *curl=curl_easy_init();
    if(!curl||!json){if(curl)curl_easy_cleanup(curl);free(json);return VIRP_ERR_NULL_PTR;}
    char auth[512];int count=snprintf(auth,sizeof(auth),"Authorization: Bearer %s",c->device.api_token);
    if(count<0||(size_t)count>=sizeof(auth)){curl_easy_cleanup(curl);free(json);return VIRP_ERR_NULL_PTR;}
    struct curl_slist *headers=NULL;headers=curl_slist_append(headers,auth);headers=curl_slist_append(headers,"Content-Type: application/json");
    curl_easy_setopt(curl,CURLOPT_URL,"https://10.0.50.103:7443/execute");
    curl_easy_setopt(curl,CURLOPT_PROXY,"");curl_easy_setopt(curl,CURLOPT_FOLLOWLOCATION,0L);
    curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,1L);curl_easy_setopt(curl,CURLOPT_SSL_VERIFYHOST,2L);curl_easy_setopt(curl,CURLOPT_CAINFO,ca);
    curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);curl_easy_setopt(curl,CURLOPT_POSTFIELDS,json);
    curl_easy_setopt(curl,CURLOPT_CONNECTTIMEOUT,5L);curl_easy_setopt(curl,CURLOPT_TIMEOUT,45L);curl_easy_setopt(curl,CURLOPT_NOSIGNAL,1L);
    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,collect);curl_easy_setopt(curl,CURLOPT_WRITEDATA,r);
    r->no_dispatch=false;r->disposition=VIRP_DISPOSITION_EXECUTED_UNKNOWN;
    CURLcode rc=curl_easy_perform(curl);long status=0;curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&status);
    if(rc==CURLE_OK && !r->output_truncated) {
        cJSON *out=cJSON_Parse(r->output);cJSON *ok=out?cJSON_GetObjectItemCaseSensitive(out,"ok"):NULL;
        cJSON *echo=out?cJSON_GetObjectItemCaseSensitive(out,"command"):NULL;
        bool matched=echo&&cJSON_IsString(echo)&&!strcmp(echo->valuestring,cmd);
        r->success=status==200&&matched&&cJSON_IsTrue(ok);
        if(matched && status!=503 && (cJSON_IsTrue(ok)||cJSON_IsFalse(ok))){r->exit_code_trusted=true;r->exit_code=r->success?0:1;r->disposition=r->success?VIRP_DISPOSITION_EXECUTED_CONFIRMED:VIRP_DISPOSITION_EXECUTED_FAILED;}
        if(!r->success)snprintf(r->error_msg,sizeof(r->error_msg),"Controller did not confirm operation success");
        if(out)cJSON_Delete(out);
    } else snprintf(r->error_msg,sizeof(r->error_msg),"Controller transport incomplete; reconcile before retry");
    curl_slist_free_all(headers);curl_easy_cleanup(curl);free(json);OPENSSL_cleanse(auth,sizeof(auth));return VIRP_OK;
}
static void disconnect_controller(virp_conn_t *c){if(c){OPENSSL_cleanse(c,sizeof(struct virp_conn));free(c);}}
static virp_error_t health(virp_conn_t *c){return c?VIRP_OK:VIRP_ERR_NULL_PTR;}
static bool detect(virp_conn_t *c){return c!=NULL;}
void virp_driver_gns3_init(void) {
    static const virp_driver_t d={.name="gns3",.vendor=VIRP_VENDOR_GNS3,.connect=connect_controller,.execute=execute,.disconnect=disconnect_controller,.detect=detect,.health_check=health,.route_command=gns3_gate_tier,.route_reason=reason};
    virp_driver_register(&d);
}
