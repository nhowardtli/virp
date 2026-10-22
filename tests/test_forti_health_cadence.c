#include "../src/drivers/driver_fortigate.c"
#include <assert.h>
int main(void) {
 int fd[2]; assert(socketpair(AF_UNIX,SOCK_STREAM,0,fd)==0);
 struct virp_conn c={0}; c.ssh_connected=true;c.ssh_socket=fd[0];
 struct timespec now;assert(clock_gettime(CLOCK_MONOTONIC,&now)==0);
 c.next_health_probe=now.tv_sec+300;
 assert(fg_health_check((virp_conn_t*)&c)==VIRP_OK);
 virp_exec_result_t result={0};
 assert(fg_ssh_execute(&c,"get system status",&result)==FG_ERR_NOT_CONNECTED);
 c.next_health_probe=0;
 assert(fg_health_check((virp_conn_t*)&c)!=VIRP_OK);
 c.next_health_probe=now.tv_sec+300;close(fd[1]);
 assert(fg_health_check((virp_conn_t*)&c)!=VIRP_OK);
 close(fd[0]);c.ssh_connected=false;
 assert(fg_health_check((virp_conn_t*)&c)==FG_ERR_NOT_CONNECTED);
 puts("PASS: throttle idle transport; explicit reads bypass; due probe executes; closed transport detected; disconnected refused");return 0;
}
