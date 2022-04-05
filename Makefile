ARCH=$(shell uname -m)

TARGET := simple
TARGET_BPF := $(TARGET).bpf.o

GO_SRC := *.go
BPF_SRC := *.bpf.c

LIBBPF_HEADERS := /usr/include/bpf
LIBBPF_OBJ := /usr/lib/$(ARCH)-linux-gnu/libbpf.a


.PHONY: all
all: vmlinux.h $(TARGET) $(TARGET_BPF)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

go_env := CC=clang CGO_CFLAGS="-I $(LIBBPF_HEADERS)" CGO_LDFLAGS="$(LIBBPF_OBJ)"
$(TARGET): $(GO_SRC)
	$(go_env) go build -o $(TARGET) 

# $@：目前的目標項目名稱
# $<：代表目前的相依性項目
$(TARGET_BPF): $(BPF_SRC)
	clang \
		-I /usr/include/$(ARCH)-linux-gnu \
		-g -O2 -c -target bpf \
		-Dbpf_target_x86 \
		-o $@ $<

clean:
	-rm *.o $(TARGET) vmlinux.h