/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Bytedance */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <linux/version.h>
#include "netatop.h"

#define TASK_MAX_ENTRIES 40960

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, TASK_MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct taskcount);
} tgid_net_stat SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, TASK_MAX_ENTRIES);
	__type(key, u64);
	__type(value, struct taskcount);
} tid_net_stat SEC(".maps");

static __always_inline u64 current_tgid()
{
	u64 tgid = bpf_get_current_pid_tgid() >> 32;
	// bpf_printk("bpf_get_current_tgid_tgid %d\n", tgid);
	return tgid;
}

// static __always_inline u64 current_tid()
// {
// 	u64 tid = bpf_get_current_pid_tgid() & 0x00000000ffffffff;
// 	// bpf_printk("bpf_get_current_tgid_tgid %d\n", tgid);
// 	return tid;
// }

SEC("raw_tracepoint/udp_send_length")
int BPF_PROG(udp_send_length_k, struct sock *sk, int length, int error, int flags)
{
	struct taskcount *stat_tgid, *stat_tid;

	if (error != 0)
		return 0;

	u64 tgid = current_tgid();
	stat_tgid = bpf_map_lookup_elem(&tgid_net_stat, &tgid);
	if (stat_tgid) {
		stat_tgid->udpsndpacks++;
		stat_tgid->udpsndbytes += length;
	} else {
		struct taskcount data ={
			.udpsndpacks = 1,
			.udpsndbytes = length
		};
		
		long ret = bpf_map_update_elem(&tgid_net_stat, &tgid, &data, BPF_ANY);
	}
	// u64 tid = current_tid();
	// stat_tid = bpf_map_lookup_elem(&tid_net_stat, &tid);
	// if (stat_tid) {
	// 	stat_tid->udpsndpacks++;
	// 	stat_tid->udpsndbytes += length;
	// } else {
	// 	struct taskcount data ={
	// 		.udpsndpacks = 1,
	// 		.udpsndbytes = length
	// 	};
		
	// 	long ret = bpf_map_update_elem(&tid_net_stat, &tid, &data, BPF_ANY);
	// }
	return 0;
}

SEC("raw_tracepoint/udp_recv_length")
int BPF_PROG(udp_recv_length_k, struct sock *sk, int length, int error, int flags)
{
	struct taskcount *stat_tgid, *stat_tid;

	if (error != 0)
		return 0;

	u64 tgid = current_tgid();
	stat_tgid = bpf_map_lookup_elem(&tgid_net_stat, &tgid);
	if (stat_tgid) {
		stat_tgid->udprcvpacks++;
		stat_tgid->udprcvbytes += length;
	} else {
		struct taskcount data ={
			.udprcvpacks = 1,
			.udprcvbytes = length
		};
		
		long ret = bpf_map_update_elem(&tgid_net_stat, &tgid, &data, BPF_ANY);
	}
	// u64 tid = current_tid();
	// stat_tid = bpf_map_lookup_elem(&tid_net_stat, &tid);
	// if (stat_tid) {
	// 	stat_tid->udprcvpacks++;
	// 	stat_tid->udprcvbytes += length;
	// } else {
	// 	struct taskcount data ={
	// 		.udprcvpacks = 1,
	// 		.udprcvbytes = length
	// 	};
		
	// 	long ret = bpf_map_update_elem(&tid_net_stat, &tid, &data, BPF_ANY);
	// }
	return 0;
}

SEC("raw_tracepoint/tcp_send_length")
int BPF_PROG(tcp_send_length_k, struct sock *sk, int length, int error, int flags)
{
	struct taskcount *stat_tgid,*stat_tid;
	int id;

	if (error != 0)
		return 0;

	u64 tgid = current_tgid(); 
	stat_tgid = bpf_map_lookup_elem(&tgid_net_stat, &tgid);
	if (stat_tgid) {
		stat_tgid->tcpsndpacks++;
		stat_tgid->tcpsndbytes += length;
	} else {
		struct taskcount data ={
			.tcpsndpacks = 1,
			.tcpsndbytes = length
		};
		
		long ret = bpf_map_update_elem(&tgid_net_stat, &tgid, &data, BPF_ANY);
	}
	// u64 tid = current_tid(); 
	// stat_tid = bpf_map_lookup_elem(&tid_net_stat, &tid);
	// if (stat_tid) {
	// 	stat_tid->tcpsndpacks++;
	// 	stat_tid->tcpsndbytes += length;
	// } else {
	// 	struct taskcount data ={
	// 		.tcpsndpacks = 1,
	// 		.tcpsndbytes = length
	// 	};
		
	// 	long ret = bpf_map_update_elem(&tid_net_stat, &tid, &data, BPF_ANY);
	// }
	return 0;
}

SEC("raw_tracepoint/tcp_recv_length")
int BPF_PROG(tcp_recv_length_k, void *sk, int length, int error, int flags)
{
	struct taskcount *stat_tgid, *stat_tid;
	int id;

	if (error != 0)
		return 0;

	u64 tgid = current_tgid();
	// u64 tid = current_tid();
	stat_tgid = bpf_map_lookup_elem(&tgid_net_stat, &tgid);
	// stat_tid = bpf_map_lookup_elem(&tid_net_stat, &tid);

	if (stat_tgid) {
		stat_tgid->tcprcvpacks++;
		stat_tgid->tcprcvbytes += length;
		// bpf_printk("current_tgidtttttttt %d %d\n", stat_tgid->tcprcvpacks, stat_tgid->tcprcvbytes);
	} else {
		struct taskcount data ={
			.tcprcvpacks = 1,
			.tcprcvbytes = length
		};
		
		long ret = bpf_map_update_elem(&tgid_net_stat, &tgid, &data, BPF_ANY);
		// bpf_printk("bpf_map_update_elem %d %d\n", data.tcprcvpacks, data.tcprcvbytes);
	}

	// if (stat_tid) {
	// 	stat_tid->tcprcvpacks++;
	// 	stat_tid->tcprcvbytes += length;
	// 	// bpf_printk("current_tidtttttttt %llu %d %d\n", tid, stat_tid->tcprcvpacks, stat_tid->tcprcvbytes);
	// } else {
	// 	struct taskcount data ={
	// 		.tcprcvpacks = 1,
	// 		.tcprcvbytes = length
	// 	};
	// 	long ret = bpf_map_update_elem(&tid_net_stat, &tid, &data, BPF_ANY);
	// }
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
