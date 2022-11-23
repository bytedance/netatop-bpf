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

static int histopen(struct naheader **nahp);
// static void recstore(int fd, struct netpertask *np, socklen_t len);

#endif