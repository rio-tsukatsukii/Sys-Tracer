# eBPF Process tracer

A simple bpf program to trace system calls.

It attaches to Linux tracepoints to:
- Track new processes when they are `execve`d
- Collect basic statistics for `read` and `write` syscalls
- Submit data in a ringbuffer so userspace can log it when a tracker process exits

Per-process state and syscall statistics are stored in BPF hash maps.

---

## Requirements

- Linux kernel >= 5.8
- clang/LLVM >= 12
- libbpf
- bpftool
- kernel config options:
  - CONFIG_BPF=y
  - CONFIG_BPF_SYSCALL=y
  - CONFIG_BPF_JIT=y
  - CONFIG_DEBUG_INFO=y
  - CONFIG_DEBUG_INFO_DWARF5=y OR CONFIG_DEBUG_INFO_DWARF4=y
  - CONFIG_DEBUG_INFO_BTF=y

---

## Build and Run

```bash
make
sudo ./build/sys_tracer
```

---

## Example output
```text
[exec]      /usr/bin/pgrep wofi
[sys_read]  610757 bytes over 1879 calls
[exec]      took 14.423 ms

[exec]      /bin/sh -c pgrep wofi > /dev/null 2>&1 && killall wofi || wofi --show drun
[sys_read]  3880370 bytes over 1228 calls
[sys_write] 4660 bytes over 45 calls
[exec]      took 600.167 ms
```

---
