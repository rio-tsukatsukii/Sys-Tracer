BUILD_DIR := ./build

SRCS_DIR := ./src

TARGET_ARCH := __TARGET_ARCH_x86

CC := gcc
CFLAGS := -Wall -Wextra -g
LDFLAGS := -lbpf

BPF_CC := clang
BPF_CFLAGS := -target bpf -D$(TARGET_ARCH) $(CFLAGS) -O2

$(BUILD_DIR)/sys_tracer: $(SRCS_DIR)/sys_tracer.c $(SRCS_DIR)/sys_tracer.h $(SRCS_DIR)/sys_tracer.skel.h $(BUILD_DIR)/sys_tracer.bpf.o | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILD_DIR)/sys_tracer.bpf.o: $(SRCS_DIR)/sys_tracer.bpf.c $(SRCS_DIR)/sys_tracer.h | $(BUILD_DIR)
	$(BPF_CC) $(BPF_CFLAGS) -o $@ -c $<
	llvm-strip -g $@
	bpftool gen skeleton $@ > $(SRCS_DIR)/sys_tracer.skel.h

$(SRCS_DIR)/sys_tracer.skel.h: $(BUILD_DIR)/sys_tracer.bpf.o

$(BUILD_DIR):
	mkdir $(BUILD_DIR)
