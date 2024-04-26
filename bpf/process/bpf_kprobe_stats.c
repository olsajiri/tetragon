// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

#define bpf_core_container_of(ptr, type, member) ({			\
	void *__mptr = (void *)(ptr);					\
	((type *)(__mptr - bpf_core_field_offset(type, member))); })

struct kprobe_stats_value {
        uint64_t id;
	uint64_t nmissed;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct kprobe_stats_value);
	__uint(max_entries, 1);
} kprobe_stats_map SEC(".maps");

__attribute__((section(("kprobe/perf_read")), used)) int
kprobe_stats(struct pt_regs *ctx)
{
	struct kprobe_stats_value *stats;
	struct trace_probe_event *tpe;
	struct trace_event_call *call;
	struct perf_event *event;
	struct trace_kprobe *tk;
	struct list_head *list;
	struct trace_probe *tp;
	struct file *file;
	__u64 id;

	stats = map_lookup_elem(&kprobe_stats_map, &(__u32){ 0 });
	if (!stats)
		return 0;

	file = (struct file *) PT_REGS_PARM1_CORE(ctx);
	if (!file)
		return 0;

	event = (struct perf_event *) BPF_CORE_READ(file, private_data);
	if (!event)
		return 0;

	id = BPF_CORE_READ(event, id);
	if (stats->id != id)
		return 0;

	call = (struct trace_event_call *) BPF_CORE_READ(event, tp_event);
	if (!call)
		return 0;

	tpe = bpf_core_container_of(call, struct trace_probe_event, call);
	list = (struct list_head *) __builtin_preserve_access_index(({ &tpe->probes; }));
	if (!list)
		return 0;

	list = (struct list_head *) BPF_CORE_READ(list, next);
	if (!list)
		return 0;

	tp = bpf_core_container_of(list, struct trace_probe, list);
	tk = bpf_core_container_of(tp, struct trace_kprobe, tp);
	stats->nmissed = (unsigned long) BPF_CORE_READ(tk, rp.kp.nmissed);
	return 0;
}
