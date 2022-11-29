#ifndef __NETATOP__
#define __NETATOP__

#define NETEXITFILE     "/var/run/netatop-bpf.log"
#define MYMAGIC         (unsigned int) 0xfeedb0b0

struct naheader {
        u_int32_t	magic;	// magic number MYMAGIC
        u_int32_t	curseq;	// sequence number of last netpertask
        u_int16_t	hdrlen;	// length of this header
        u_int16_t	ntplen;	// length of netpertask structure
        pid_t    	mypid;	// PID of netatopd itself
};

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

/*
** Semaphore-handling
**
** A semaphore-group with two semaphores is created. The first semaphore
** specifies the number of netatopd processes running (to be sure that only
** one daemon is active at the time) ) and the second reflects the number
** of processes using the log-file (inverted).
** This second semaphore is initialized at some high value and is
** decremented by every analysis process (like atop) that uses the log-file
** and incremented as soon as such analysis process stops again.
*/
#define SEMTOTAL        100
#define	NUMCLIENTS	(SEMTOTAL - semctl(semid, 1, GETVAL, 0))
#define SEMAKEY         1541962

#endif