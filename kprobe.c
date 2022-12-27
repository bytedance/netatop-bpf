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

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;


struct taskcount value_zero = {
	.tcpsndpacks = 0,
	.tcpsndbytes = 0,
	.tcprcvpacks = 0,
	.tcprcvbytes = 0,
	.udpsndpacks = 0
};

<<<<<<< HEAD
int main(int argc, char **argv)
{
	struct kprobe_bpf *skel;
=======
int semid;
int tgid_map_fd;
int tid_map_fd;
int nr_cpus;
struct kprobe_bpf *skel;
static struct bpf_object_open_opts open_opts = {.sz = sizeof(struct bpf_object_open_opts)};

int main(int argc, char **argv)
{
	/*
	** create the semaphore group and initialize it;
	** if it already exists, verify if a netatop bpf 
	** program is already running. And 
	** 
	*/
	struct sembuf		semincr = {0, +1, SEM_UNDO};	
	if ( (semid = semget(SEMAKEY, 0, 0)) >= 0)	// exists?
	{
		if ( semctl(semid, 0, GETVAL, 0) == 1)
		{
			fprintf(stderr, "Another netatop bpf program is already running!");
			exit(3);
		}
	}
	else
	{
		if ( (semid = semget(SEMAKEY, 2, 0600|IPC_CREAT|IPC_EXCL)) >= 0)
		{
			// Initialize the number of netatop bpf program
			(void) semctl(semid, 0, SETVAL, 0);
			// Initialize the number of atop Clients
			(void) semctl(semid, 1, SETVAL, 0);
		}
		else
		{
			perror("cannot create semaphore");
			exit(3);
		}
	}

>>>>>>> eb484c2... fix
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

<<<<<<< HEAD

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		printf("can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

=======
>>>>>>> eb484c2... fix
	// printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	//        "to see output of the BPF programs.\n");

	// int tgid_map_fd= bpf_map__fd(skel->obj->map.task_net_stat);
	tgid_map_fd = bpf_object__find_map_fd_by_name(skel->obj, "tgid_net_stat");
	tid_map_fd = bpf_object__find_map_fd_by_name(skel->obj, "tid_net_stat");

	if ( fork() )
		exit(0);
<<<<<<< HEAD
=======
	setsid();
	/*
	** raise semaphore to define a busy netatop
	*/
	if ( semop(semid, &semincr, 1) == -1)
    {
		printf("cannot increment semaphore\n");
		exit(3);
	}
>>>>>>> eb484c2... fix

	serv_listen();

cleanup:
	kprobe_bpf__destroy(skel);
	return -err;
}