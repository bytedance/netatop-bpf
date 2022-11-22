/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Bytedance */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <linux/version.h>
#include "kprobe.h"

#define TASK_MAX_ENTRIES 40960

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, TASK_MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct taskcount);
} tasks_net_stat SEC(".maps");

static __always_inline u64 current_net_stat()
{
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	// bpf_printk("bpf_get_current_pid_tgid %d\n", pid);
	return pid;
}

SEC("raw_tracepoint/udp_send_length")
int BPF_PROG(udp_send_length_k, struct sock *sk, int length, int error, int flags)
{
	struct taskcount *stat;

	if (error != 0)
		return 0;

	u64 pid = current_net_stat();
	stat = bpf_map_lookup_elem(&tasks_net_stat, &pid);
	if (stat) {
		stat->net_udp_tx++;
		stat->net_udp_tx_bytes += length;
	} else {
		struct taskcount data ={
			.net_udp_tx = 1,
			.net_udp_tx_bytes = length
		};
		
		long ret = bpf_map_update_elem(&tasks_net_stat, &pid, &data, BPF_ANY);
	}
	return 0;
}

SEC("raw_tracepoint/udp_recv_length")
int BPF_PROG(udp_recv_length_k, struct sock *sk, int length, int error, int flags)
{
	struct taskcount *stat;

	if (error != 0)
		return 0;

	u64 pid = current_net_stat();
	stat = bpf_map_lookup_elem(&tasks_net_stat, &pid);
	if (stat) {
		stat->net_udp_rx++;
		stat->net_udp_rx_bytes += length;
	} else {
		struct taskcount data ={
			.net_udp_rx = 1,
			.net_udp_rx_bytes = length
		};
		
		long ret = bpf_map_update_elem(&tasks_net_stat, &pid, &data, BPF_ANY);
	}
	return 0;
}

SEC("raw_tracepoint/tcp_send_length")
int BPF_PROG(tcp_send_length_k, struct sock *sk, int length, int error, int flags)
{
	struct taskcount *stat;
	int id;

	if (error != 0)
		return 0;

	u64 pid = current_net_stat(); 
	stat = bpf_map_lookup_elem(&tasks_net_stat, &pid);
	if (stat) {
		stat->net_tcp_tx++;
		stat->net_tcp_tx_bytes += length;
	} else {
		struct taskcount data ={
			.net_tcp_rx = 1,
			.net_tcp_rx_bytes = length
		};
		
		long ret = bpf_map_update_elem(&tasks_net_stat, &pid, &data, BPF_ANY);
	}
	return 0;
}

SEC("raw_tracepoint/tcp_recv_length")
int BPF_PROG(tcp_recv_length_k, void *sk, int length, int error, int flags)
{
	struct taskcount *stat;
	int id;

	if (error != 0)
		return 0;

	u64 pid = current_net_stat();
	stat = bpf_map_lookup_elem(&tasks_net_stat, &pid);
	// bpf_printk("current_net_stat %d %d\n", stat->net_tcp_rx, stat->net_tcp_rx_bytes);
	// if (pid != 993940) {
	// 	return 0;
	// }
	bpf_printk("length %d\n", length);

	if (stat) {
		stat->net_tcp_rx++;
		stat->net_tcp_rx_bytes += length;
		// bpf_printk("current_net_stattttttttt %d %d\n", stat->net_tcp_rx, stat->net_tcp_rx_bytes);
	} else {
		struct taskcount data ={
			.net_tcp_rx = 1,
			.net_tcp_rx_bytes = length
		};
		
		long ret = bpf_map_update_elem(&tasks_net_stat, &pid, &data, BPF_ANY);
		// bpf_printk("bpf_map_update_elem %d %d\n", data.net_tcp_rx, data.net_tcp_rx_bytes);
	}
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
