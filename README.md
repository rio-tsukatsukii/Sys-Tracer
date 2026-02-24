# eBPF Process tracer

A simple bpf program to trace system calls.

It attaches to Linux tracepoints to:
- Track processes when they call `execve`
- Collect basic statistics for `read` and `write` syscalls
- Submit data in a ringbuffer so userspace can log it when:
    - A tracked syscall occurs
    - A process exits

Per-process state and syscall statistics are stored in BPF hash maps.

Very WIP at the moment.
