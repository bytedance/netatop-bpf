#ifndef __DEAL__
#define __DEAL__
void deal(int, struct netpertask *);
void deal_exited_process(int, struct netpertask *npt);
int tgid_map_fd;
int tid_map_fd;
int nr_cpus;
int histfd;
struct naheader *nap;
#endif