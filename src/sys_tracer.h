#ifndef SYS_TRACER_H
#define SYS_TRACER_H

#define PROC_NAME_SIZE 32
#define MAX_ARGS 8
#define ARG_SIZE 80

enum syscalls {
    SYS_READ,
    SYS_WRITE,
    SYS_OPEN,
    SYS_CLOSE,
    SYS_EXECVE = 0x3b,
    SYSCALLS_MAX,
};

struct proc_data_t {
    __u64 runtime;
    char proc_name[PROC_NAME_SIZE];
    char proc_args[MAX_ARGS][ARG_SIZE];
};

struct syscall_stats_key_t {
    __u64 id;
    enum syscalls syscall;
};

union syscall_data_t {
    struct {
        __u64 count;
        __u64 bytes_total;
    } read;
    struct {
        __u64 count;
        __u64 bytes_total;
    } write;
    struct {
        __u64 count;
    } open;
    struct {
        __u64 count;
    } close;
};

#endif
