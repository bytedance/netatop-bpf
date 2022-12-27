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
	unsigned long		btime;
	char			command[COMLEN];

	struct taskcount	tc;
};

<<<<<<< HEAD
=======

#define	NUMCLIENTS	(semctl(semid, 1, GETVAL, 0))

extern struct kprobe_bpf *skel;
extern int semid;

>>>>>>> eb484c2... fix
#endif