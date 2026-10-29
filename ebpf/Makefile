CLANG := clang
CC := clang
# The apt-installed bpftool wrapper refuses to run on this kernel's custom
# version string; the real binary underneath works fine invoked directly.
# See README-toolchain.md.
BPFTOOL := /usr/lib/linux-tools-6.8.0-139/bpftool

ARCH_DEFINE := -D__TARGET_ARCH_arm64
BPF_CFLAGS := -g -O2 -target bpf $(ARCH_DEFINE) -I.
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf) -lelf -lz

all: loader

collector.bpf.o: collector.bpf.c common.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c collector.bpf.c -o collector.bpf.o

collector.skel.h: collector.bpf.o
	$(BPFTOOL) gen skeleton collector.bpf.o > collector.skel.h

loader: loader.c collector.skel.h common.h
	$(CC) -g -O2 -I. $(LIBBPF_CFLAGS) loader.c -o loader $(LIBBPF_LIBS)

clean:
	rm -f collector.bpf.o collector.skel.h loader err.log

.PHONY: all clean
