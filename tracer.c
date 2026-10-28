//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB ring buffer
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} restricted_uids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[64]);
    __type(value, __u8);
} blocked_binaries SEC(".maps");

struct event {
    __u32 pid;
    __u32 uid;
    __u8  blocked;
    char comm[16];
    char filename[64];
};

SEC("lsm/bprm_check_security")
int BPF_PROG(restrict_exec, struct linux_binprm *bprm) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->blocked = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), bprm->filename);

    __u8 *uid_restricted = bpf_map_lookup_elem(&restricted_uids, &e->uid);
    __u8 *bin_blocked = bpf_map_lookup_elem(&blocked_binaries, &e->filename);

    if (uid_restricted && bin_blocked) {
        e->blocked = 1;
        bpf_ringbuf_submit(e, 0);
        return -1; // -EPERM
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";