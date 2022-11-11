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
#include "kprobe.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}

struct task_net_stat value_zero = {
	.net_tcp_rx = 0,
	.net_tcp_rx_bytes = 0,
	.net_tcp_tx = 0,
	.net_tcp_tx_bytes = 0,
	.net_udp_rx = 0
};

int main(int argc, char **argv)
{
	struct kprobe_bpf *skel;
	int err;
	int nr_cpus = libbpf_num_possible_cpus();

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

	// int tasks_fd= bpf_map__fd(skel->obj->map.task_net_stat);
	int tasks_fd = bpf_object__find_map_fd_by_name(skel->obj, "tasks_net_stat");
	struct task_net_stat *stats = calloc(nr_cpus, sizeof(struct task_net_stat));
	if (!stats) {
		fprintf(stderr, "calloc task_net_stat failed\n");
		return -ENOMEM;
	}
	// if ( chdir("/proc") == -1)
	// 	return -1;
	while (!stop) {
		fprintf(stderr, ".");
		unsigned long long lookup_key, next_key;
		// struct task_count stats;
		// lookup_key.type = 'g';
		lookup_key = 1;

		/* trigger our BPF program */
		// 首次查找, key 设置为不存在, 从头开始遍历
		printf("%-6s %-16s %-6s %-16s %-6s\n","PID","TCPRCV", "TCPRBYTES", "UDPRCV", "UDPRBYTES");
		while(bpf_map_get_next_key(tasks_fd, &lookup_key, &next_key) == 0) {
			bpf_map_lookup_elem(tasks_fd, &next_key, stats);
			// printf("%-6d %-16lld %-6lld %-16lld %-6lld\n", next_key.pid, task_count_process.tcprcvpacks, task_count_process.tcprcvbytes, task_count_process.udprcvpacks, task_count_process.udprcvbytes);

			lookup_key = next_key;
			struct task_net_stat data = {
				.net_tcp_rx = 0,
				.net_tcp_rx_bytes = 0,
				.net_tcp_tx = 0,
				.net_tcp_tx_bytes = 0,
				.net_udp_rx = 0
			};
			
			// bpf_map_update_elem(tasks_fd, &next_key, &value_zero, BPF_EXIST);
			// if (next_key == 522878)
			// 	printf("%llu %ld %ld %ld %ld %ld\n",next_key, value_zero.net_tcp_rx);

			for (int i = 0; i < nr_cpus; i++) {
				data.net_tcp_rx += stats[i].net_tcp_rx;
				data.net_tcp_rx_bytes += stats[i].net_tcp_rx_bytes;
				data.net_tcp_tx += stats[i].net_tcp_tx;
				data.net_tcp_tx_bytes += stats[i].net_tcp_tx_bytes;
				data.net_udp_rx += stats[i].net_udp_rx;
				data.net_udp_rx_bytes += stats[i].net_udp_rx_bytes;
				data.net_udp_tx += stats[i].net_udp_tx;
				data.net_udp_tx_bytes += stats[i].net_udp_tx_bytes;
			}
			if (next_key == 554670)
				printf("%llu %ld %ld %ld %ld %ld\n",next_key, data.net_tcp_rx, data.net_tcp_rx_bytes, data.net_tcp_tx, data.net_tcp_tx_bytes, data.net_udp_rx);
			if(kill(next_key, 0) && errno == ESRCH) 
				bpf_map_delete_elem(tasks_fd, &next_key);
		}
		sleep(1);
	}
	// while (!stop) {
	// 	fprintf(stderr, ".");
	// 	/*
	// 	** read all subdirectory-names below the /proc directory
	// 	*/
	// 	if ( chdir("/proc") == -1)
	// 		return -1;
	// 	// 	// mcleanstop(54, "failed to change to /proc\n");

	// 	DIR	*dirp = opendir(".");
	// 	struct dirent *entp;
		
	// 	while ( (entp = readdir(dirp)) != NULL)
	// 	{
	// 		if (!isdigit(entp->d_name[0]))
	// 			continue;

	// 		if ( chdir(entp->d_name) != 0 )
	// 			continue;

	// 		FILE	*fp;
	// 		int	nr;
	// 		char	line[4096];
	// 		unsigned long long pid;


	// 		if ( (fp = fopen("stat", "r")) == NULL)
	// 			return 0;

	// 		if ( (nr = fread(line, 1, sizeof line-1, fp)) == 0)
	// 		{
	// 			fclose(fp);
	// 			return 0;
	// 		}
	// 		sscanf(line, "%llu", &pid); 
	// 		// printf("pid %d\n", pid);
	// 		chdir("..");
	// 		err = bpf_map_lookup_elem(tasks_fd, &pid, stats);
	// 		if (err) {
	// 			// printf("bpf_map_lookup_elem failed %lu\n", pid);
	// 			continue;
	// 			// err = bpf_map_update_elem(tasks_fd, &pid, stats, BPF_NOEXIST);
	// 			// if (err) {
	// 			// 	printf("task_net_stat update failed %lu\n", pid);
	// 			// }
	// 		}
	// 		// printf("%d\n", nr_cpus);
		// 	struct task_net_stat data = {
		// 		.net_tcp_rx = 0,
		// 		.net_tcp_rx_bytes = 0,
		// 		.net_tcp_tx = 0,
		// 		.net_tcp_tx_bytes = 0,
		// 		.net_udp_rx = 0
		// 	};

		// 	for (int i = 0; i < nr_cpus; i++) {
		// 		data.net_tcp_rx += stats[i].net_tcp_rx;
		// 		data.net_tcp_rx_bytes += stats[i].net_tcp_rx_bytes;
		// 		data.net_tcp_tx += stats[i].net_tcp_tx;
		// 		data.net_tcp_tx_bytes += stats[i].net_tcp_tx_bytes;
		// 		data.net_udp_rx += stats[i].net_udp_rx;
		// 		data.net_udp_rx_bytes += stats[i].net_udp_rx_bytes;
		// 		data.net_udp_tx += stats[i].net_udp_tx;
		// 		data.net_udp_tx_bytes += stats[i].net_udp_tx_bytes;
		// 	}
		// 	printf("%llu %ld %ld %ld %ld %ld\n",pid, data.net_tcp_rx, data.net_tcp_rx_bytes, data.net_tcp_tx, data.net_tcp_tx_bytes, data.net_udp_rx);

		// }
		// closedir(dirp);
		
		// sleep(10);
	// }

cleanup:
	kprobe_bpf__destroy(skel);
	return -err;
}
