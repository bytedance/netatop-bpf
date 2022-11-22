
struct taskcount {
	unsigned long net_tcp_rx;
	unsigned long net_tcp_rx_bytes;
	unsigned long net_tcp_tx;
	unsigned long net_tcp_tx_bytes;
	unsigned long net_udp_rx;
	unsigned long net_udp_rx_bytes;
	unsigned long net_udp_tx;
	unsigned long net_udp_tx_bytes;
};

#define NETEXITFILE     "/var/run/netatop-bpf.log"
#define MYMAGIC         (unsigned int) 0xfeedb0b0

struct naheader {
        u_int32_t	magic;	// magic number MYMAGIC
        u_int32_t	curseq;	// sequence number of last netpertask
        u_int16_t	hdrlen;	// length of this header
        u_int16_t	ntplen;	// length of netpertask structure
        pid_t    	mypid;	// PID of netatopd itself
};

#define	COMLEN	16

struct netpertask {
	pid_t			id;	// tgid or tid (depending on command)
	unsigned long		btime;
	char			command[COMLEN];

	struct taskcount	tc;
};

static int histopen(struct naheader **nahp);
// static void recstore(int fd, struct netpertask *np, socklen_t len);