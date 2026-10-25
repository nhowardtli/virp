#include "virp_driver.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
extern int gns3_operation(const char *);
extern virp_trust_tier_t gns3_gate_tier(const char *);
int main(void) {
 const char *id="12345678-1234-1234-1234-123456789abc";
 const char *ops[]={"status","create","delete","start","stop","configure","test","isolate","repair"};
 char command[256],bad[512];int checks=0;
 assert(gns3_gate_tier(NULL)==VIRP_TIER_RED);checks++;
 for(int i=0;i<9;i++) {
  snprintf(command,sizeof(command),"lab %s %s",ops[i],id);
  assert(gns3_gate_tier(command)==(i==0||i==6?VIRP_TIER_GREEN:VIRP_TIER_YELLOW));checks++;
  const char *suffixes[]={" ","\n","\r",";reload","|x","&x","\t","?","$(x)","\342\200\213"};
  for(int j=0;j<10;j++){snprintf(bad,sizeof(bad),"%s%s",command,suffixes[j]);assert(gns3_gate_tier(bad)==VIRP_TIER_RED);checks++;}
  snprintf(bad,sizeof(bad),"%s",command);bad[strlen(bad)-1]='G';assert(gns3_gate_tier(bad)==VIRP_TIER_RED);checks++;
 }
 const char *unknown[]={"lab create ../../foreign","lab shell", "lab ping 12345678-1234-1234-1234-123456789abc","LAB health","lab health\n","lab delete","lab create 12345678-1234-1234-1234-123456789ABC"};
 for(int i=0;i<7;i++){assert(gns3_gate_tier(unknown[i])==VIRP_TIER_RED);checks++;}
 printf("GNS3 fixed-operation classifier: %d checks passed\n",checks);
 return 0;
}
