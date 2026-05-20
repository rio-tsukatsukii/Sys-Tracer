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

struct enter_exec_params_t {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int __syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

SEC("tp/syscalls/sys_enter_execve")
int handle_enter_execve(struct enter_exec_params_t *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    int err;
    struct proc_data_t *data;
    const char *const *argv = ctx->argv + 1;

    err = bpf_map_update_elem(&proc_data, &id, &empty_proc_data, BPF_NOEXIST);
    if (err < 0) {
        return 0;
    }

    data = bpf_map_lookup_elem(&proc_data, &id);
    if (!data) {
        goto ret;
    }

    data->enter_ns = bpf_ktime_get_ns();

    /* Kernel never copies these into kernel memory, they remain in userspace memory */
    err = bpf_probe_read_user_str(data->proc_name, PROC_NAME_SIZE, ctx->filename);

    if (err < 0) {
        bpf_map_delete_elem(&proc_data, &id);
        goto ret;
    }

    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;

        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);

        if (!argp)
            break;

        err = bpf_probe_read_user_str(&data->proc_args[i], ARG_SIZE, argp);

        if (err < 0) {
            bpf_map_delete_elem(&proc_data, &id);
            goto ret;
        }
    }

    struct syscall_stats_key_t key;

    key.id = id;
    key.syscall = SYS_READ;

    err = bpf_map_update_elem(&syscall_stats, &key, &empty_syscall_data, BPF_NOEXIST);
    if (err < 0) {
        bpf_map_delete_elem(&proc_data, &id);
        goto ret;
    }

    key.syscall = SYS_WRITE;

    err = bpf_map_update_elem(&syscall_stats, &key, &empty_syscall_data, BPF_NOEXIST);
    if (err < 0)
        bpf_map_delete_elem(&proc_data, &id);

ret:
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_process_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct proc_data_t *data;

    data = bpf_map_lookup_elem(&proc_data, &id);
    if (!data) {
        goto ret;
    }

    data->exit_ns = bpf_ktime_get_ns();

    __u64 *key = bpf_ringbuf_reserve(&out_ringbuf, sizeof(__u64), 0);

    if (!key) {
        goto ret;
    }

    *key = id;

    bpf_ringbuf_submit(key, 0);

    (void) ctx;
ret:
    return 0;
}

struct exit_read_write_params_t {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int __syscall_nr;
    long ret;
};

SEC("tp/syscalls/sys_enter_read")
int handle_enter_read(struct trace_event_raw_sys_enter *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct syscall_stats_key_t key = {0};
    union syscall_data_t *syscall_data;

    key.id = id;
    key.syscall = SYS_READ;

    syscall_data = bpf_map_lookup_elem(&syscall_stats, &key);
    if (!syscall_data)
        goto ret;

    syscall_data->read.count++;

    (void) ctx;
ret:
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_exit_read(struct exit_read_write_params_t *ctx) {
    if (ctx->ret < 0)
        goto ret;

    __u64 id = bpf_get_current_pid_tgid();
    struct syscall_stats_key_t key = {0};
    union syscall_data_t *syscall_data;

    key.id = id;
    key.syscall = SYS_READ;

    syscall_data = bpf_map_lookup_elem(&syscall_stats, &key);
    if (!syscall_data)
        goto ret;

    syscall_data->read.bytes_total += ctx->ret;
ret:
    return 0;
}

SEC("tp/syscalls/sys_enter_write")
int handle_enter_write(struct trace_event_raw_sys_enter *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct syscall_stats_key_t key = {0};
    union syscall_data_t *syscall_data;

    key.id = id;
    key.syscall = SYS_WRITE;

    syscall_data = bpf_map_lookup_elem(&syscall_stats, &key);
    if (!syscall_data)
        goto ret;

    syscall_data->write.count++;

    (void) ctx;
ret:
    return 0;
}

SEC("tp/syscalls/sys_exit_write")
int handle_exit_write(struct exit_read_write_params_t *ctx) {
    if (ctx->ret < 0)
        goto ret;

    __u64 id = bpf_get_current_pid_tgid();
    struct syscall_stats_key_t key = {0};
    union syscall_data_t *syscall_data;

    key.id = id;
    key.syscall = SYS_WRITE;

    syscall_data = bpf_map_lookup_elem(&syscall_stats, &key);
    if (!syscall_data)
        goto ret;

    syscall_data->write.bytes_total += ctx->ret;
ret:
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
