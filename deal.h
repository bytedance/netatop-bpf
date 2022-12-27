#ifndef __DEAL__
#define __DEAL__
void deal(int, struct netpertask *);
void deal_exited_process(int, struct netpertask *npt);
extern int tgid_map_fd;
extern int tid_map_fd;
extern int nr_cpus;
#endif