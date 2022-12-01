#include <error.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
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
#include "server.h"
#include "netatop.h"
#include "deal.h"

/*
* Create a server endpoint of a connection.
* Return fd if all ok, <0 on error. 
*/
void serv_listen()
{
    int            sock_fd, len, err, rval;
    struct sockaddr_un    un, cli_un;
	char *name = "netatop-bpf-socket";
    
    /* create a UNIX domain stream socket */
    if((sock_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
        return(-1);
    unlink(name);    /* in case it already exists */

    /* fill in socket address structure */
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, name);
    len = offsetof(struct sockaddr_un, sun_path) + strlen(name);

    /* bind the name to the descriptor */
    if(bind(sock_fd, (struct sockaddr *)&un, len) < 0)
    {
        rval = -2;
        goto errout;
    }
    if(listen(sock_fd, 10) < 0)    /* tell kernel we're a server */
    {
        rval = -3;
        goto errout;
    }
    // printf("listen success \n");

	struct epoll_event ev, events[1000];
	int epoll_fd = epoll_create(10000);//生成epoll句柄
    ev.data.fd = sock_fd;//设置与要处理事件相关的文件描述符
    ev.events = EPOLLIN;//设置要处理的事件类型
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_fd, &ev);//注册epoll事件
   
    while(1)
    {
        int fd_num = epoll_wait(epoll_fd, events, 10000, 1000);
        for (int i = 0; i < fd_num; i++)
        {
            if (events[i].data.fd == sock_fd)
            {
				len = sizeof(un);
				int conn_fd;
				if((conn_fd = accept(sock_fd, (struct sockaddr *)&cli_un, &len)) < 0)
					return(-4);    /* often errno=EINTR, if signal caught */
				ev.data.fd = conn_fd;
                ev.events = EPOLLIN;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_fd, &ev);
				// printf("accept success\n");

            }
            else if (events[i].events & EPOLLIN)
            {
                struct netpertask npt;
                int n = recv(events[i].data.fd, &npt, sizeof(npt), 0);
                if (n == 0) {
                    close(events[i].data.fd);
                    continue;
                } 
                deal(events[i].data.fd, &npt);
                send(events[i].data.fd, &npt, sizeof(npt), 0);
            }
        }
        // sem_deal();
    }


errout:
    err = errno;
    close(sock_fd);
    errno = err;
    // return(rval);
}

// void
// gethup(int sig)
// {
// }

// int semid;

// void sem_init()
// {
//     /*
// 	** create the semaphore group and initialize it;
// 	** if it already exists, verify if a netatopd daemon
// 	** is already running
// 	*/
// 	if ( (semid = semget(SEMAKEY, 0, 0)) >= 0)	// exists?
// 	{
// 		if ( semctl(semid, 0, GETVAL, 0) == 1)
// 		{
// 			fprintf(stderr, "Another netatopd is already running!");
// 			exit(3);
// 		}
// 	}
// 	else
// 	{
// 		if ( (semid = semget(SEMAKEY, 2, 0600|IPC_CREAT|IPC_EXCL)) >= 0)
// 		{
// 			(void) semctl(semid, 0, SETVAL, 0);
// 			(void) semctl(semid, 1, SETVAL, SEMTOTAL);
// 		}
// 		else
// 		{
// 			perror("cannot create semaphore");
// 			exit(3);
// 		}
// 	}
//     /*
//     ** the daemon can be woken up from getsockopt by receiving 
//     ** the sighup signal to verify if there are no clients any more
//     ** (truncate exitfile)
//     */
//     struct sigaction        sigact;

//     memset(&sigact, 0, sizeof sigact);
//     sigact.sa_handler = gethup;
//     sigaction(SIGHUP, &sigact, (struct sigaction *)0);
    
// }

// void sem_deal()
// {
//   if (NUMCLIENTS == 0 && nap->curseq != 0)
//     {
//         /*
//         ** destroy and reopen history file
//         */
//         munmap(nap, sizeof(struct naheader));
//         close(histfd);
//         syslog(LOG_INFO, "reopen history file\n");
//         histfd = histopen(&nap);
//     }
// }