// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

#define container_of(ptr, type, member) ({		\
	void *__mptr = (void *)(ptr);			\
	((type *)(__mptr - offsetof(type, member))); })

struct kprobe_stats_value {
        uint64_t id;
	uint64_t nmissed;
	uint64_t hit;
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
	struct file *file;
	struct list_head *list;
	struct trace_probe *tp;
	struct trace_kprobe *tk;
	unsigned long nmissed;
	__u64 id;

	stats = map_lookup_elem(&kprobe_stats_map, &(__u32){ 0 });
	if (!stats)
		return 0;

	file = (struct file *) PT_REGS_PARM1_CORE(ctx);
	if (!file)
		return 0;

	bpf_printk("file %lx\n", (unsigned long) file);

	event = (struct perf_event *) BPF_CORE_READ(file, private_data);
	if (!event)
		return 0;

	id = BPF_CORE_READ(event, id);

	bpf_printk("id %lu\n", (__u64) id);

	if (stats->id != id)
		return 0;

	bpf_printk("event %lx\n", (unsigned long) event);

	call = (struct trace_event_call *) BPF_CORE_READ(event, tp_event);
	if (!call)
		return 0;

	bpf_printk("call  %lx\n", (unsigned long) call);

	tpe = container_of(call, struct trace_probe_event, call);

	bpf_printk("tpe   %lx\n", (unsigned long) tpe);

        __builtin_preserve_access_index(({

	list = (struct list_head *) &tpe->probes;

	}));

	if (!list)
		return 0;

	bpf_printk("list1 %lx\n", (unsigned long) list);

	list = (struct list_head *) BPF_CORE_READ(list, next);
	if (!list)
		return 0;

	bpf_printk("list2 %lx\n", (unsigned long) list);

	tp = container_of(list, struct trace_probe, list);

	bpf_printk("tp    %lx\n", (unsigned long) tp);

	tk = container_of(tp, struct trace_kprobe, tp);

	bpf_printk("tk    %lx\n", (unsigned long) tk);

	nmissed = (unsigned long) BPF_CORE_READ(tk, rp.kp.nmissed);

	bpf_printk("nmissed %lx\n", (unsigned long) nmissed);

	stats->nmissed = nmissed;
	stats->hit = 1;
	return 0;
}
