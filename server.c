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
    printf("listen success \n");

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
					return(-1);    /* often errno=EINTR, if signal caught */
				ev.data.fd = conn_fd;
                ev.events = EPOLLIN;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_fd, &ev);
				printf("accept success\n");

            }
            else if (events[i].events & EPOLLIN)
            {
			    printf("recv ing\n");
			   char recv_t[100];
               int n = recv(events[i].data.fd, recv_t, 100, 0);
               send(events[i].data.fd, recv_t, sizeof(recv_t), 0);
			   if (n == 0)
			   		close(events[i].data.fd);
			   printf("%s\n", recv_t);
               // recv_t.data.send_fd = events[i].data.fd;
            }
        }
    }


errout:
    err = errno;
    close(sock_fd);
    errno = err;
    // return(rval);
}


/* obtain the client's uid from its calling address */
// len -= offsetof(struct sockaddr_un, sun_path);    /* len of pathname */
// un.sun_path[len] = 0;    /* null terminate */

// if(stat(un.sun_path, &statbuf) < 0)
// {
// 	rval = -2;
// 	goto errout;
// }
// #ifdef    S_ISSOCK    /* not defined fro SVR4 */
// if(S_ISSOCK(statbuf.st_mode) == 0)
// {
// 	rval = -3;    /* not a socket */
// 	goto errout;
// }
// #endif
// if((statbuf.st_mode & (S_IRWXG | S_IRWXO)) ||
// 	(statbuf.st_mode & S_IRWXU) != S_IRWXU)
// {
// 	rval = -4;    /* is not rwx------ */
// 	goto errout;
// }

// staletime = time(NULL) - STALE;
// if(statbuf.st_atime < staletime ||
// statbuf.st_ctime < staletime ||
// statbuf.st_mtime < staletime)
// {
// 	rval = -5;    /* i-node is too old */    
// 	goto errout;
// }

// if(uidptr != NULL)
// 	*uidptr = statbuf.st_uid;    /* return uid of caller */
// unlink(un.sun_path);    /* we're done with pathname now */
				// return(clifd);
