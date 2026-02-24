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

void cleanup_maps(__u64 id, struct bpf_map *proc_data, struct bpf_map *syscall_stats) {
    struct syscall_stats_key_t key;
    key.id = id;
    for (int i = 0; i < SYSCALLS_MAX; i++) {
        key.syscall = i;
        bpf_map__lookup_and_delete_elem(syscall_stats, &key, sizeof(struct syscall_stats_key_t), NULL, sizeof(union syscall_data_t), 0);
    }

    bpf_map__lookup_and_delete_elem(proc_data, &id, sizeof(id), NULL, sizeof(struct proc_data_t), 0);
}

int print_execve(void *ctx, void *data, size_t size) {
    struct output_data_t *p = data;
    struct cleanup_ctx *c_ctx = ctx;

    switch (p->syscall) {
        case SYS_READ:
            printf("%s attempted to read %llu\n", p->proc_data.proc_name, p->syscall_data.read.bytes_total);
            break;
        case SYS_WRITE:
            printf("%s attempted to read %llu\n", p->proc_data.proc_name, p->syscall_data.write.bytes_total);
            break;
        case -1:
            printf("%s ran for %.3f ms\n", p->proc_data.proc_name, (p->proc_data.exit_ns - p->proc_data.enter_ns) / 1e6);
            cleanup_maps(p->id, c_ctx->proc_data, c_ctx->syscall_stats);
            break;
    }

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

    rb = ring_buffer__new(bpf_map__fd(skel->maps.out_ringbuf), print_execve, &ctx, NULL);
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
