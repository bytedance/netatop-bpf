#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include "netatop.h"
#include "deal.h"

void deal(int fd, struct netpertask *npt)
{
    struct taskcount *stats = calloc(nr_cpus, sizeof(struct taskcount));
	if (!stats) {
		fprintf(stderr, "calloc task_net_stat failed\n");
		return;
	}
    unsigned long long pid = (unsigned long long)npt->id;
    memset(&npt->tc, 0, sizeof(npt->tc));
    if (npt->type == 'g') { 
        if (bpf_map_lookup_elem(tgid_map_fd, &pid, stats) != 0) {
            return;
        }
    } else if (npt->type == 't'){
        if (bpf_map_lookup_elem(tid_map_fd, &pid, stats) != 0) {
            return;
        }
    } else if (npt->type == 'd'){
        // if (bpf_map_lookup_elem(tid_map_fd, &pid, stats) != 0) {
        //     return;
        // }
        //遍历map 得到退出进程 写入文件
        deal_exited_process(fd, npt);
        return;
    }
    for (int i = 0; i < nr_cpus; i++) {
        npt->tc.tcpsndpacks += stats[i].tcpsndpacks;
        npt->tc.tcpsndbytes += stats[i].tcpsndbytes;
        npt->tc.tcprcvpacks += stats[i].tcprcvpacks;
        npt->tc.tcprcvbytes += stats[i].tcprcvbytes;
        npt->tc.udpsndpacks += stats[i].udpsndpacks;
        npt->tc.udpsndbytes += stats[i].udpsndbytes;
        npt->tc.udprcvpacks += stats[i].udprcvpacks;
        npt->tc.udprcvbytes += stats[i].udprcvbytes;
    }
    // printf("%c %llu %llu %ld %ld %ld %ld\n", npt->type, pid, npt->tc.tcpsndpacks, npt->tc.tcpsndbytes, npt->tc.tcprcvpacks, npt->tc.tcprcvbytes, npt->tc.udpsndpacks);
}

void deal_exited_process(int fd, struct netpertask *npt)
{
    unsigned long long lookup_key, next_key;

    struct taskcount *stats = calloc(nr_cpus, sizeof(struct taskcount));
	lookup_key = 1;
    // delete exited process
    while(bpf_map_get_next_key(tgid_map_fd, &lookup_key, &next_key) == 0) {
        lookup_key = next_key;
        if(kill(next_key, 0) && errno == ESRCH) {
            bpf_map_lookup_and_delete_elem(tgid_map_fd, &next_key, stats);
            // bpf_map_lookup_elem(tgid_map_fd, &next_key, stats);

            // printf("%-6d %-16lld %-6lld %-16lld %-6lld\n", next_key.pid, task_count_process.tcprcvpacks, task_count_process.tcprcvbytes, task_count_process.udprcvpacks, task_count_process.udprcvbytes);

            struct taskcount data = {
                .tcpsndpacks = 0,
                .tcpsndbytes = 0,
                .tcprcvpacks = 0,
                .tcprcvbytes = 0,
                .udpsndpacks = 0,
                .udpsndbytes = 0,
                .udprcvpacks = 0,
                .udprcvbytes = 0,
            };
            
            // bpf_map_update_elem(tgid_map_fd, &next_key, &value_zero, BPF_EXIST);
            // if (next_key == 522878)
            // 	printf("%llu %ld %ld %ld %ld %ld\n",next_key, value_zero.tcpsndpacks);

            for (int i = 0; i < nr_cpus; i++) {
                data.tcpsndpacks += stats[i].tcpsndpacks;
                data.tcpsndbytes += stats[i].tcpsndbytes;
                data.tcprcvpacks += stats[i].tcprcvpacks;
                data.tcprcvbytes += stats[i].tcprcvbytes;
                data.udpsndpacks += stats[i].udpsndpacks;
                data.udpsndbytes += stats[i].udpsndbytes;
                data.udprcvpacks += stats[i].udprcvpacks;
                data.udprcvbytes += stats[i].udprcvbytes;
            } 
            // 如果字节数超过2^64?
            // if (data.tcpsndbytes >  || data.tcprcvbytes || data.udpsndbytes|| data.udprcvbytes) 
            // 	bpf_map_delete_elem(tgid_map_fd, &next_key);            
            
            struct netpertask npt = {
                .id = next_key,
                // .command = 
                .tc = data
            };
    
            send(fd, &npt, sizeof(npt), 0);
            
            // bpf_map_delete_elem(tgid_map_fd, &next_key);
        }
    }

    // delete exited thread 
    lookup_key = 0;
    next_key = 0; 
    while(bpf_map_get_next_key(tid_map_fd, &lookup_key, &next_key) == 0) {
        lookup_key = next_key;

        if(kill(next_key, 0) && errno == ESRCH) {
            // delete exited thread
            bpf_map_lookup_and_delete_elem(tid_map_fd, &next_key);
        }
    }
}