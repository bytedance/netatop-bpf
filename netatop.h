#ifndef __NETATOP__
#define __NETATOP__
struct taskcount {
	unsigned long long	tcpsndpacks;
	unsigned long long	tcpsndbytes;
	unsigned long long	tcprcvpacks;
	unsigned long long	tcprcvbytes;

	unsigned long long	udpsndpacks;
	unsigned long long	udpsndbytes;
	unsigned long long	udprcvpacks;
	unsigned long long	udprcvbytes;

	/* space for future extensions */
};
#define	COMLEN	16

struct netpertask {
	char type; 	// tgid or tid or
	pid_t			id;	// tgid or tid (depending on command)
	struct taskcount	tc;
};

struct netatop_bpf *skel;
int semid;
int tgid_map_fd;
int tid_map_fd;
int nr_cpus;

#define	NUMCLIENTS	(semctl(semid, 1, GETVAL, 0))
#define SEMAKEY         1541962

void bpf_attach(struct netatop_bpf *);
void bpf_destroy(struct netatop_bpf *);
void cleanup(struct netatop_bpf *);
#endif