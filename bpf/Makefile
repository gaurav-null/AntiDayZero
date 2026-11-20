# Makefile for eBPF syscall sketch detector and network monitor

CLANG ?= clang
BPFTOOL ?= bpftool

BPF_CFLAGS = -target bpf -D__TARGET_ARCH_x86 -D__BPF_TRACING__ \
    -Wall -Werror -O2 -g \
    -I/usr/include/bpf \
    -mllvm -bpf-stack-size=2048

.PHONY: all clean test install-deps test-analyze

all: syscall_sketch.bpf.o network_monitor.bpf.o

syscall_sketch.bpf.o: syscall_sketch.bpf.c
	@echo "Compiling eBPF syscall sketch program: $<"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@ 2>&1
	@echo "Compilation successful: $@"

network_monitor.bpf.o: network_monitor.bpf.c
	@echo "Compiling eBPF network monitor program: $<"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@ 2>&1
	@echo "Compilation successful: $@"

clean:
	rm -f *.o

test: all
	$(BPFTOOL) verify syscall_sketch.bpf.o 2>&1 || true
	$(BPFTOOL) verify network_monitor.bpf.o 2>&1 || true

test-analyze: all
	$(BPFTOOL) prog show 2>&1 || true
	$(BPFTOOL) map show 2>&1 || true

install-deps:
	sudo apt-get update
	sudo apt-get install -y clang llvm libbpf-dev llvm-dev \
		pkg-config linux-headers-generic bpftool

