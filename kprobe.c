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

	// printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	//        "to see output of the BPF programs.\n");

	// int tgid_map_fd= bpf_map__fd(skel->obj->map.task_net_stat);
	tgid_map_fd = bpf_object__find_map_fd_by_name(skel->obj, "tgid_net_stat");
	tid_map_fd = bpf_object__find_map_fd_by_name(skel->obj, "tid_net_stat");

	if ( fork() )
		exit(0);

	serv_listen();

cleanup:
	kprobe_bpf__destroy(skel);
	return -err;
}