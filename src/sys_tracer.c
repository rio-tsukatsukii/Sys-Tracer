#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>

#include "sys_tracer.h"
#include "sys_tracer.skel.h"

struct cleanup_ctx {
    struct bpf_map *proc_data;
    struct bpf_map *syscall_stats;
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level >= LIBBPF_DEBUG) return 0;

    return vfprintf(stderr, format, args);
}

int print_proc_data(void *ctx, void *data, size_t size) {
    __u64 *id = data;
    struct cleanup_ctx *c_ctx = ctx;
    struct proc_data_t proc_data;
    int err;
    err = bpf_map__lookup_and_delete_elem(c_ctx->proc_data, id, sizeof(__u64), &proc_data, sizeof(struct proc_data_t), 0);

    if (err < 0) {
        fprintf(stderr, "%llu could not be found in proc_data\n", *id);
        return 0;
    }

    printf("[exec]      %s", proc_data.proc_name);

    for (int i = 0; proc_data.proc_args[i][0] != '\0' && i < MAX_ARGS; i++) {
        printf(" %s", proc_data.proc_args[i]);
    }
    putchar('\n');

    struct syscall_stats_key_t key;
    union syscall_data_t syscall_data;

    key.id = *id;
    for (__u64 i = 0; i < SYSCALLS_MAX; i++) {
        key.syscall = i;
        err = bpf_map__lookup_and_delete_elem(c_ctx->syscall_stats, &key, sizeof(struct syscall_stats_key_t), &syscall_data, sizeof(union syscall_data_t), 0);

        if (err < 0) {
            continue;
        }

        switch (i) {
            case SYS_READ:
                if (syscall_data.read.count > 0) {
                    printf("[sys_read]  %llu bytes over %llu calls\n", syscall_data.read.bytes_total, syscall_data.read.count);
                }
                break;
            case SYS_WRITE:
                if (syscall_data.write.count > 0) {
                    printf("[sys_write] %llu bytes over %llu calls\n", syscall_data.write.bytes_total, syscall_data.write.count);
                }
                break;
        }
    }

    printf("[exec]      took %.3Lf ms\n\n", proc_data.runtime / 1e6L);

    (void) size;

    return 0;
}

int main() {
    struct sys_tracer_bpf *skel;
    int err;
    struct ring_buffer *rb = NULL;

    libbpf_set_print(libbpf_print_fn);

    skel = sys_tracer_bpf__open_and_load();
    if (!skel) {
        printf("Failed to open BPF object\n");
        return 1;
    }

    err = sys_tracer_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        sys_tracer_bpf__destroy(skel);
        return 1;
    }

    struct cleanup_ctx ctx;
    ctx.proc_data = skel->maps.proc_data;
    ctx.syscall_stats = skel->maps.syscall_stats;

    rb = ring_buffer__new(bpf_map__fd(skel->maps.out_ringbuf), print_proc_data, &ctx, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        sys_tracer_bpf__destroy(skel);
        return 1;
    }

    while (true) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        // Ctrl-C gives -EINTR
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    sys_tracer_bpf__destroy(skel);
    return -err;
}
