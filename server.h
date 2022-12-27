#ifndef __SERVER__
#define __SERVER__
#define NETATOP_SOCKET "/var/run/netatop-bpf-socket"
int serv_listen();
extern void bpf_attach(struct kprobe_bpf *skel);
extern void bpf_destroy(struct kprobe_bpf *skel);
#endif