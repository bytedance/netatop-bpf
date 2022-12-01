/*
** open history file
*/
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <errno.h>
#include <zlib.h>
#include <time.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/statvfs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <stdint.h>
#include <errno.h>
#include "netatop.h"
#include "deal.h"

int
histopen(struct naheader **nahp)
{
	int			fd;
	struct naheader 	nahdr = {MYMAGIC, 0,
					sizeof(struct naheader),
		                	sizeof(struct netpertask),
					getpid()};
	/*
 	** remove the old file; this way atop can detect that a
	** new file must be opened
	*/
	(void) unlink(NETEXITFILE);

	/*
 	** open new file
	*/
	if ( (fd = open(NETEXITFILE, O_RDWR|O_CREAT|O_TRUNC, 0644)) == -1)
	{
		// syslog(LOG_ERR, "cannot open %s for write\n", NETEXITFILE);
		exit(3);
	}

	/*
 	** write new header and mmap
	*/
	if ( write(fd, &nahdr, sizeof nahdr) != sizeof nahdr)
	{
		// syslog(LOG_ERR, "cannot write to %s\n", NETEXITFILE);
		exit(3);
	}

	*nahp = mmap((void *)0, sizeof *nahp, PROT_WRITE, MAP_SHARED, fd, 0);

	if (*nahp == (void *) -1)
	{
		// syslog(LOG_ERR, "mmap of %s failed\n", NETEXITFILE);
		exit(3);
	}
	return fd;
}

void
recstore(int fd, struct netpertask *np)
{
	Byte		compbuf[sizeof *np + 128];
	unsigned long	complen = sizeof compbuf -1;
	struct statvfs	statvfs;
	int		rv;

	/*
 	** check if the filesystem is not filled for more than 95%
	*/
	if ( fstatvfs(fd, &statvfs) != -1)
	{
		if (statvfs.f_bfree * 100 / statvfs.f_blocks < 5)
		{
			// syslog(LOG_ERR, "Filesystem > 95%% full; "
			//                 "write skipped\n");
			return;
		}
	}

	/*
 	** filesystem space sufficient
	** compress netpertask struct
	*/
	// rv = compress(compbuf+1, &complen, (Byte *)np,
	// 				(unsigned long)sizeof *np);
	// switch (rv)
	// {
    //        case Z_OK:
    //        case Z_STREAM_END:
    //        case Z_NEED_DICT:
	// 	break;

	//    default:
	// 	syslog(LOG_ERR, "compression failure\n");
	// 	exit(5);
	// }

	// compbuf[0] = (Byte)complen;

	/*
	** write compressed netpertask struct, headed by one byte
	** with the size of the compressed struct
	*/
	if ( write(fd, np, sizeof *np) <sizeof *np)
	{
		// syslog(LOG_ERR, "write failure\n");
		exit(5);
	}
}
