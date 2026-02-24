#ifndef SYS_TRACER_H
#define SYS_TRACER_H

#define PROC_NAME_SIZE 25

enum syscalls {
    SYS_READ,
    SYS_WRITE,
    SYS_OPEN,
    SYS_CLOSE,
    SYSCALLS_MAX,
};

struct proc_data_t {
    __u64 enter_ns;
    __u64 exit_ns;
    char proc_name[PROC_NAME_SIZE];
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

struct output_data_t {
    __u64 id;
    struct proc_data_t proc_data;
    __s16 syscall;
    union syscall_data_t syscall_data;
};

#endif
