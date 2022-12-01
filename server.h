#ifndef __SERVER__
#define __SERVER__
#define NETATOP_SOCKET "/var/run/netatop-bpf-socket"
void serv_listen();
void gethup(int sig);
void sem_init();
void sem_deal();
#endif