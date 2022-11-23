// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "kprobe.skel.h"
#include "netatop.h"
#include "server.h"
#include "deal.h"

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

static void recstore(int fd, struct netpertask *np, socklen_t len);
// void serv_listen();

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}

struct taskcount value_zero = {
	.tcpsndpacks = 0,
	.tcpsndbytes = 0,
	.tcprcvpacks = 0,
	.tcprcvbytes = 0,
	.udpsndpacks = 0
};

int main(int argc, char **argv)
{
	struct kprobe_bpf *skel;
	int err;
	nr_cpus = libbpf_num_possible_cpus();

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open load and verify BPF application */
	skel = kprobe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = kprobe_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}


	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		printf("can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	// int tgid_map_fd= bpf_map__fd(skel->obj->map.task_net_stat);
	tgid_map_fd = bpf_object__find_map_fd_by_name(skel->obj, "tgid_net_stat");
	tid_map_fd = bpf_object__find_map_fd_by_name(skel->obj, "tid_net_stat");

	// pthread_t tid;
	// int err = pthread_create(&tid, NULL, &doSomeThing, NULL);
	
	serv_listen();

	
	// struct taskcount *stats = calloc(nr_cpus, sizeof(struct taskcount));
	// if (!stats) {
	// 	fprintf(stderr, "calloc task_net_stat failed\n");
	// 	return -ENOMEM;
	// }
	// // if ( chdir("/proc") == -1)
	// // 	return -1;
	// while (!stop) {
	// 	fprintf(stderr, ".");
	// 	unsigned long long lookup_key, next_key;
	// 	// struct task_count stats;
	// 	// lookup_key.type = 'g';
	// 	lookup_key = 1;

	// 	/* trigger our BPF program */
	// 	// 首次查找, key 设置为不存在, 从头开始遍历
	// 	printf("%-6s %-16s %-6s %-16s %-6s\n","PID","TCPRCV", "TCPRBYTES", "UDPRCV", "UDPRBYTES");
	// 	while(bpf_map_get_next_key(tgid_map_fd, &lookup_key, &next_key) == 0) {
	// 		bpf_map_lookup_elem(tgid_map_fd, &next_key, stats);
	// 		// printf("%-6d %-16lld %-6lld %-16lld %-6lld\n", next_key.pid, task_count_process.tcprcvpacks, task_count_process.tcprcvbytes, task_count_process.udprcvpacks, task_count_process.udprcvbytes);

	// 		lookup_key = next_key;
	// 		struct taskcount data = {
	// 			.tcpsndpacks = 0,
	// 			.tcpsndbytes = 0,
	// 			.tcprcvpacks = 0,
	// 			.tcprcvbytes = 0,
	// 			.udpsndpacks = 0
	// 		};
			
	// 		// bpf_map_update_elem(tgid_map_fd, &next_key, &value_zero, BPF_EXIST);
	// 		// if (next_key == 522878)
	// 		// 	printf("%llu %ld %ld %ld %ld %ld\n",next_key, value_zero.tcpsndpacks);

	// 		for (int i = 0; i < nr_cpus; i++) {
	// 			data.tcpsndpacks += stats[i].tcpsndpacks;
	// 			data.tcpsndbytes += stats[i].tcpsndbytes;
	// 			data.tcprcvpacks += stats[i].tcprcvpacks;
	// 			data.tcprcvbytes += stats[i].tcprcvbytes;
	// 			data.udpsndpacks += stats[i].udpsndpacks;
	// 			data.udpsndbytes += stats[i].udpsndbytes;
	// 			data.udprcvpacks += stats[i].udprcvpacks;
	// 			data.udprcvbytes += stats[i].udprcvbytes;
	// 		}
	// 		// 如果字节数超过2^64?
	// 		// if (data.tcpsndbytes >  || data.tcprcvbytes || data.udpsndbytes|| data.udprcvbytes) 
	// 		// 	bpf_map_delete_elem(tgid_map_fd, &next_key);
	// 		// if (next_key == 554670)
	// 		printf("%llu %ld %ld %ld %ld %ld\n",next_key, data.tcpsndpacks, data.tcpsndbytes, data.tcprcvpacks, data.tcprcvbytes, data.udpsndpacks);
			
	// 		struct netpertask npt = {
	// 			.id = next_key,
	// 			// .command = 
	// 			.tc = data
	// 		};
	// 		socklen_t len = sizeof npt;
	// 		struct naheader 	*nap;
	// 		int histfd = histopen(&nap);
	// 		recstore(histfd, &npt, len);

	// 		if(kill(next_key, 0) && errno == ESRCH) 
	// 			bpf_map_delete_elem(tgid_map_fd, &next_key);
	// 	}
	// 	sleep(1);
	// }

cleanup:
	kprobe_bpf__destroy(skel);
	return -err;
}

// *
// * Create a server endpoint of a connection.
// * Return fd if all ok, <0 on error. 
// */
// void serv_listen()
// {
//     int            sock_fd, len, err, rval;
//     struct sockaddr_un    un, cli_un;
// 	char *name = "netatop-bpf-socket";
    
//     /* create a UNIX domain stream socket */
//     if((sock_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
//         return(-1);
//     unlink(name);    /* in case it already exists */

//     /* fill in socket address structure */
//     memset(&un, 0, sizeof(un));
//     un.sun_family = AF_UNIX;
//     strcpy(un.sun_path, name);
//     len = offsetof(struct sockaddr_un, sun_path) + strlen(name);

//     /* bind the name to the descriptor */
//     if(bind(sock_fd, (struct sockaddr *)&un, len) < 0)
//     {
//         rval = -2;
//         goto errout;
//     }
//     if(listen(sock_fd, 10) < 0)    /* tell kernel we're a server */
//     {
//         rval = -3;
//         goto errout;
//     }
//     printf("listen success \n");

// 	struct epoll_event ev, events[1000];
// 	int epoll_fd = epoll_create(10000);//生成epoll句柄
//     ev.data.fd = sock_fd;//设置与要处理事件相关的文件描述符
//     ev.events = EPOLLIN;//设置要处理的事件类型
//     epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_fd, &ev);//注册epoll事件
   
//     while(1)
//     {
//         int fd_num = epoll_wait(epoll_fd, events, 10000, 1000);
//         for (int i = 0; i < fd_num; i++)
//         {
//             if (events[i].data.fd == sock_fd)
//             {
// 				len = sizeof(un);
// 				int conn_fd;
// 				if((conn_fd = accept(sock_fd, (struct sockaddr *)&cli_un, &len)) < 0)
// 					return(-1);    /* often errno=EINTR, if signal caught */
// 				ev.data.fd = conn_fd;
//                 ev.events = EPOLLIN;
//                 epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_fd, &ev);
// 				printf("accept success\n");

//             }
//             else if (events[i].events & EPOLLIN)
//             {
// 			    printf("recv ing\n");
// 			   char recv_t[100];
//                int n = recv(events[i].data.fd, recv_t, 100, 0);
// 			   if (n == 0)
// 			   		close(events[i].data.fd);
// 			   printf("%s\n", recv_t);
//                // recv_t.data.send_fd = events[i].data.fd;
//             }
//         }
//     }


// errout:
//     err = errno;
//     close(sock_fd);
//     errno = err;
//     // return(rval);
// }

/*
** open history file
*/
static int
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


static void
recstore(int fd, struct netpertask *np, socklen_t len)
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
	rv = compress(compbuf+1, &complen, (Byte *)np,
					(unsigned long)sizeof *np);
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

	compbuf[0] = (Byte)complen;

	/*
	** write compressed netpertask struct, headed by one byte
	** with the size of the compressed struct
	*/
	if ( write(fd, compbuf, complen+1) < complen)
	{
		// syslog(LOG_ERR, "write failure\n");
		exit(5);
	}
}
