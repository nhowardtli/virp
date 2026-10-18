/* Typed access-port operations: parsing, risk tiers, no-dispatch refusal. */
#include "../src/drivers/driver_cisco.c"
#include <assert.h>
int main(void) {
 const char *good[]={"switchport mode access","switchport mode dynamic auto","no switchport mode","switchport access vlan 10","no switchport access vlan","spanning-tree portfast","no spanning-tree portfast","switchport port-security","no switchport port-security","switchport port-security maximum 2","no switchport port-security maximum","switchport port-security violation restrict","switchport port-security violation shutdown","no switchport port-security violation"};
 char cmd[256],ifn[64],line[128]; unsigned count=0;
 for(size_t i=0;i<sizeof(good)/sizeof(good[0]);i++) {
  snprintf(cmd,sizeof cmd,"interface GigabitEthernet1/0/22 %s",good[i]);
  assert(cisco_parse_port_operation(cmd,ifn,sizeof ifn,line,sizeof line));
  assert(!strcmp(ifn,"GigabitEthernet1/0/22") && !strcmp(line,good[i]));
  /* Exact routine grammar is YELLOW; security changes remain RED. */
  assert(cisco_gate_tier(cmd)==(strstr(good[i],"port-security") ? VIRP_TIER_RED : VIRP_TIER_YELLOW));
  virp_conn_t c; memset(&c,0,sizeof c);c.connected=true;c.current_mode=CISCO_MODE_USER;
  virp_exec_result_t r;memset(&r,0,sizeof r);
  assert(cisco_execute(&c,cmd,&r)==VIRP_OK && r.no_dispatch && !r.success);
  assert(r.disposition==VIRP_DISPOSITION_NOT_SENT);count++;
 }
 const char *bad[]={"switchport access vlan 0","switchport access vlan 4095","switchport access vlan 01","switchport access vlan +10","switchport access vlan 10;reload","switchport access vlan 10\nend","switchport access vlan 10 ","switchport mode trunk","switchport trunk allowed vlan all","spanning-tree portfast trunk","spanning-tree bpduguard disable","switchport port-security mac-address sticky","switchport port-security maximum 0","switchport port-security maximum 65536","switchport port-security violation protect","shutdown","no shutdown"};
 for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);i++) {
  snprintf(cmd,sizeof cmd,"interface GigabitEthernet1/0/22 %s",bad[i]);
  assert(!cisco_parse_port_operation(cmd,ifn,sizeof ifn,line,sizeof line));count++;
 }
 const char *ports[]={"Vlan10","Port-channel1","GigabitEthernet1/0/22.10","GigabitEthernet1/0/22,23","range","Gi1/0/22","GigabitEthernet1/0/22;end"};
 for(size_t i=0;i<sizeof(ports)/sizeof(ports[0]);i++) {
  snprintf(cmd,sizeof cmd,"interface %s switchport mode access",ports[i]);
  assert(!cisco_parse_port_operation(cmd,ifn,sizeof ifn,line,sizeof line));count++;
 }
 assert(!cisco_parse_port_operation(NULL,NULL,0,NULL,0));
 assert(!cisco_parse_port_operation("interface Ethernet0/1 switchport mode access",ifn,2,line,sizeof line));
 assert(!cisco_parse_port_operation("interface Ethernet0/1 switchport mode access",ifn,sizeof ifn,line,2));
 assert(cisco_parse_port_operation("interface Ethernet0/1 switchport mode access",ifn,sizeof ifn,line,sizeof line));
 printf("%u cases passed plus null/buffer/canary checks\n",count);return 0;
}
