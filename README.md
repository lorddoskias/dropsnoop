# dropsnoop
eBPF based tool which prints a stacktrace when an skb gets freed.

# Build
Simply run `make`

# Requirements
* llvm/clang 13 (older could also work but you need to adjust the Makefile)
* libbpf statically compiled, it's assumed to be in /usr/lib64/libbpf.a 
* libelf and libz

