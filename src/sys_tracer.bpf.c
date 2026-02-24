#include "vmlinux.h"

#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "sys_tracer.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct proc_data_t);
} proc_data SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct syscall_stats_key_t);
    __type(value, union syscall_data_t);
} syscall_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 0x10000);
} out_ringbuf SEC(".maps");

struct proc_data_t empty_proc_data = {};
union syscall_data_t empty_syscall_data = {};

SEC("tp/syscalls/sys_enter_execve")
int handle_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    int err;
    struct proc_data_t *data;

    err = bpf_map_update_elem(&proc_data, &id, &empty_proc_data, BPF_NOEXIST);
    if (err < 0) {
        return 0;
    }

    data = bpf_map_lookup_elem(&proc_data, &id);
    if (!data) {
        return 0;
    }

    data->enter_ns = bpf_ktime_get_ns();

    /* Kernel never copies these into kernel memory, they remain in userspace memory */
    err = bpf_probe_read_user_str(data->proc_name, sizeof(data->proc_name), (const char *) ctx->args[0]);

    if (err < 0) {
        bpf_map_delete_elem(&proc_data, &id);
        return 0;
    }

    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct proc_data_t *data;

    data = bpf_map_lookup_elem(&proc_data, &id);
    if (!data) {
        return 0;
    }

    struct output_data_t *out_data = bpf_ringbuf_reserve(&out_ringbuf, sizeof(struct output_data_t), 0);
    if (!out_data) {
        return 0;
    }

    __builtin_memcpy(&out_data->proc_data, data, sizeof(struct proc_data_t));
    out_data->proc_data.exit_ns = bpf_ktime_get_ns();
    out_data->syscall = -1;

    bpf_ringbuf_submit(out_data, 0);

    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int handle_enter_read(struct trace_event_raw_sys_enter *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    int err;
    struct proc_data_t *data;
    struct syscall_stats_key_t key;
    union syscall_data_t *syscall_data;

    data = bpf_map_lookup_elem(&proc_data, &id);
    if (!data) {
        return 0;
    }

    key.id = id;
    key.syscall = SYS_READ;

    err = bpf_map_update_elem(&syscall_stats, &key, &empty_syscall_data, BPF_NOEXIST);
    if (err < 0) {
        return 0;
    }

    syscall_data = bpf_map_lookup_elem(&syscall_stats, &key);
    if (!syscall_data) {
        return 0;
    }

    syscall_data->read.count++;
    syscall_data->read.bytes_total += ctx->args[2];

    struct output_data_t *out_data = bpf_ringbuf_reserve(&out_ringbuf, sizeof(struct output_data_t), 0);
    if (!out_data) {
        return 0;
    }

    __builtin_memcpy(&out_data->proc_data, data, sizeof(struct proc_data_t));
    out_data->syscall = SYS_READ;
    __builtin_memcpy(&out_data->syscall_data, syscall_data, sizeof(union syscall_data_t));


    bpf_ringbuf_submit(out_data, 0);

    return 0;
}

SEC("tp/syscalls/sys_enter_write")
int handle_enter_write(struct trace_event_raw_sys_enter *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    int err;
    struct proc_data_t *data;
    struct syscall_stats_key_t key;
    union syscall_data_t *syscall_data;

    data = bpf_map_lookup_elem(&proc_data, &id);
    if (!data) {
        return 0;
    }

    key.id = id;
    key.syscall = SYS_WRITE;

    err = bpf_map_update_elem(&syscall_stats, &key, &empty_syscall_data, BPF_NOEXIST);
    if (err < 0) {
        return 0;
    }

    syscall_data = bpf_map_lookup_elem(&syscall_stats, &key);
    if (!syscall_data) {
        return 0;
    }

    syscall_data->write.count++;
    syscall_data->write.bytes_total += ctx->args[2];

    struct output_data_t *out_data = bpf_ringbuf_reserve(&out_ringbuf, sizeof(struct output_data_t), 0);
    if (!out_data) {
        return 0;
    }

    __builtin_memcpy(&out_data->proc_data, data, sizeof(struct proc_data_t));
    out_data->syscall = SYS_WRITE;
    __builtin_memcpy(&out_data->syscall_data, syscall_data, sizeof(union syscall_data_t));


    bpf_ringbuf_submit(out_data, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
