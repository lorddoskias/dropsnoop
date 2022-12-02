// +build ignore

// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define MAX_STACK	20

static u32 init_net_ns_idx = 0;
static u32 filtered_ns_idx = 1;

struct event {
	__u32 ns;
	__u32 kern_stack_size;
	__u64 kern_stack[MAX_STACK];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
    __uint(max_entries, 2);
} params SEC(".maps");


struct possible_net_t {
	struct net_namespace *net;
};

extern struct net init_net;

static __always_inline u32 get_ns(struct sk_buff *skb) {
	if (bpf_core_field_exists(skb->dev->nd_net.net)) {
		return BPF_CORE_READ(skb,dev,nd_net.net,ns.inum);
	} else {
		u32 *value = bpf_map_lookup_elem(&params, &init_net_ns_idx);
		if (value)
			return *value;
		return 0;
	}
}

SEC("tracepoint/skb/kfree_skb")
int kfree_trace(struct trace_event_raw_kfree_skb *ctx)
{
	struct event e = {};
	u32 ns = get_ns(ctx->skbaddr);

	u64 *value = bpf_map_lookup_elem(&params, &filtered_ns_idx);
	/* can  never be null */
	if (!value)
		return 0;

	if (*value != 0 && *value != ns)
		return 0;

	e.ns = ns;
	e.kern_stack_size =	bpf_get_stack(ctx, e.kern_stack, sizeof(e.kern_stack),
			0);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
