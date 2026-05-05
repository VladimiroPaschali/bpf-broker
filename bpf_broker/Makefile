# Makefile for bpf-broker using system kernel headers
# Modified to use /lib/modules/<kernel>/build and libbpf-dev

KERNEL_VERSION ?= $(shell uname -r)
LINUX_BUILD_PATH ?= /lib/modules/$(KERNEL_VERSION)/build
LINUX_SOURCE_PATH ?= /lib/modules/$(KERNEL_VERSION)/source

# Try to find libbpf - check common locations
LIBBPF_HEADERS := $(shell pkg-config --cflags libbpf 2>/dev/null || echo "-I/usr/include")
LIBBPF_LIBS := $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf -lelf -lz")

TARGETS += bpf_broker

CLANG ?= clang
LLC ?= llc
CC := gcc

KERN_SOURCES = ${TARGETS:=_kern.c}
USER_SOURCES = ${TARGETS:=_user.c}
KERN_OBJECTS = ${KERN_SOURCES:.c=.o}
USER_OBJECTS = ${USER_SOURCES:.c=.o}

CFLAGS := -g -O2 -Wall
CFLAGS += -I.
CFLAGS += $(LIBBPF_HEADERS)

LDFLAGS ?= $(LIBBPF_LIBS)

NOSTDINC_FLAGS := -nostdinc -isystem $(shell $(CC) -print-file-name=include)
ARCH=$(shell uname -m | sed 's/x86_64/x86/' | sed 's/i386/x86/')

# Use system kernel headers
LINUXINCLUDE := -I/usr/include -I/usr/include/bpf
LINUXINCLUDE += -I$(LINUX_SOURCE_PATH)/arch/$(ARCH)/include
LINUXINCLUDE += -I$(LINUX_SOURCE_PATH)/arch/$(ARCH)/include/uapi
LINUXINCLUDE += -I$(LINUX_BUILD_PATH)/arch/$(ARCH)/include/generated
LINUXINCLUDE += -I$(LINUX_BUILD_PATH)/arch/$(ARCH)/include/generated/uapi
LINUXINCLUDE += -I$(LINUX_SOURCE_PATH)/include
LINUXINCLUDE += -I$(LINUX_SOURCE_PATH)/include/uapi
LINUXINCLUDE += -I$(LINUX_BUILD_PATH)/include/generated/uapi
LINUXINCLUDE += -I$(LINUX_SOURCE_PATH)/tools/testing/selftests/bpf

EXTRA_CFLAGS_TMP := -I$(LINUX_SOURCE_PATH)/tools/include \
                    -I$(LINUX_SOURCE_PATH)/tools/lib/bpf

EXTRA_CFLAGS=-Werror

###

all: dependencies $(TARGETS) $(KERN_OBJECTS) $(PROTO)

.PHONY: clean dependencies verify_cmds verify_target_bpf $(CLANG) $(LLC)

clean:
	@find . -type f \
		\( -name '*~' \
		-o -name '*.ll' \
		-o -name '*.bc' \
		-o -name 'core' \) \
		-exec rm -vf '{}' \;
	rm -f $(TARGETS)
	rm -f $(KERN_OBJECTS)
	rm -f $(USER_OBJECTS)
	rm -f $(PROTO)

dependencies: verify_target_bpf

verify_cmds: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if ! (which -- "$${TOOL}" > /dev/null 2>&1); then \
			echo "*** ERROR: Cannot find LLVM tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

verify_target_bpf: verify_cmds
	@if ! (${LLC} -march=bpf -mattr=help > /dev/null 2>&1); then \
		echo "*** ERROR: LLVM (${LLC}) does not support 'bpf' target" ;\
		echo "   NOTICE: LLVM version >= 3.7.1 required" ;\
		exit 2; \
	else true; fi

# Compiling of eBPF restricted-C code with LLVM
$(KERN_OBJECTS): %.o: %.c
	$(CLANG) -S $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS_TMP) \
	    -D__KERNEL__ -D__ASM_SYSREG_H -D__BPF_TRACING__ \
	    -D__TARGET_ARCH_$(ARCH) \
	    -Dtypedef=typedef -Du32=__u32 -Du64=__u64 -Du16=__u16 -Du8=__u8 \
		-Wno-error=ignored-attributes -fcf-protection=none \
	    -Wno-unused-value -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Wno-gnu-variable-sized-type-not-at-end \
	    -Wno-tautological-compare \
	    -Wno-unknown-warning-option \
	    -Wno-address-of-packed-member \
	    -Wno-incompatible-function-pointer-types \
	    -O2 -g -emit-llvm -c $< -o ${@:.o=.ll}
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

$(TARGETS): %: %_user.c $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@ $< $(LDFLAGS)

PROTO := bpf_broker_proto
PROTO_OBJECTS := bpf_broker_proto.o

$(PROTO): $(PROTO_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

all: $(PROTO)
