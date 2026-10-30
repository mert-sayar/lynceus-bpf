//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB ring buffer
} events SEC(".maps");

struct policy_key {
    __u64 ino;
    __u32 uid;
    __u32 dev;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct policy_key);
    __type(value, __u8);
} policy_map SEC(".maps");

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

    struct policy_key key = {};

    key.ino = BPF_CORE_READ(bprm, file, f_inode, i_ino);
    key.uid = e->uid;
    key.dev = BPF_CORE_READ(bprm, file, f_inode, i_sb, s_dev);

    __u8 *blocked = bpf_map_lookup_elem(&policy_map, &key);

    if (!blocked){
        key.uid = 0xFFFFFFFF;
        blocked = bpf_map_lookup_elem(&policy_map, &key);
    }

    if (blocked) {
        e->blocked = 1;
        bpf_ringbuf_submit(e, 0);
        return -1; // -EPERM
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";