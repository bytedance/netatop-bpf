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

// struct {
// 	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
// 	__uint(max_entries, TASK_MAX_ENTRIES);
// 	__type(key, u64);
// 	__type(value, struct taskcount);
// } tid_net_stat SEC(".maps");

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

struct sock_msg_length_args {
	unsigned long long common_tp_fields;
	struct sock *sk;
	__u16 family;
	__u16 protocol;
	int length;
	int error;
	int flags;
};

SEC("tracepoint/sock/sock_send_length")
int handle_tp_send(struct sock_msg_length_args *ctx)
{
	struct taskcount *stat_tgid, *stat_tid;
	int id;
	short family = ctx->family;
	short protocol = ctx->protocol;
	int length = ctx->length;
	int error = ctx->error;

	if (error != 0)
		return 0;

	// AF_INET = 2
	// AF_INET6 = 10
	if (family == 2 || family ==  10) {
		u64 tgid = current_tgid();
		// u64 tid = current_tid();
		stat_tgid = bpf_map_lookup_elem(&tgid_net_stat, &tgid);
		// stat_tid = bpf_map_lookup_elem(&tid_net_stat, &tid);
		if (protocol == IPPROTO_TCP) {
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
		} else if (protocol == IPPROTO_UDP) {
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
		}
	}
	return 0;
}

SEC("tracepoint/sock/sock_recv_length")
int handle_tp_recv(struct sock_msg_length_args *ctx)
{
	struct taskcount *stat_tgid, *stat_tid;
	int id;
	short family = ctx->family;
	short protocol = ctx->protocol;
	int length = ctx->length;
	int error = ctx->error;

	if (error != 0)
		return 0;
	if (family == 2 || family == 10) {
		u64 tgid = current_tgid();
		// u64 tid = current_tid();
		stat_tgid = bpf_map_lookup_elem(&tgid_net_stat, &tgid);
		// stat_tid = bpf_map_lookup_elem(&tid_net_stat, &tid);
		if (protocol == IPPROTO_TCP) {
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
			}
		} else if (protocol == IPPROTO_UDP) {
			if (stat_tgid) {
				stat_tgid->udprcvpacks++;
				stat_tgid->udprcvbytes += length;
				// bpf_printk("current_tgidtttttttt %d %d\n", stat_tgid->tcprcvpacks, stat_tgid->tcprcvbytes);
			} else {
				struct taskcount data ={
					.udprcvpacks = 1,
					.udprcvbytes = length
				};
				long ret = bpf_map_update_elem(&tgid_net_stat, &tgid, &data, BPF_ANY);
			}
		}
	}
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
