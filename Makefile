# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang-13
LLVM_STRIP ?= llvm-strip-13
LIBBPF_OBJ := /usr/lib64/libbpf.a
INCLUDES := -I$(OUTPUT)
CFLAGS := -g -O2 -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

ifeq ($(V),1)
Q =
msg =
else
Q = @
msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";
MAKEFLAGS += --no-print-directory
endif

GOFLAGS := CC=$(CLANG)
GOFLAGS += CGO_LDFLAGS="-lelf -lz $(LIBBPF_OBJ)"

prog: $(LIBBPF_OBJ) $(OUTPUT)/drop.bpf.o
	$(GOFLAGS) go build dropsnoop

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS) $(APP_ALIASES)

$(OUTPUT) $(OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH)	      \
		     -I./ $(INCLUDES) -c $(filter %.c,$^) -o $@ && \
	$(LLVM_STRIP) -g $@


# delete failed targets
.DELETE_ON_ERROR:
# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
