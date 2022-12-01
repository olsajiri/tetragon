// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "lib/common.h"
#include "lib/hubble_msg.h"
#include "lib/bpf_events.h"

struct msg_loader {
	struct msg_common common;
	struct msg_execve_key current;
	__u32 pid;
	__u32 buildid_size;
	__u32 file_len;
	char buildid[20];
	char file[1024];
	void *pe;
};

char _license[] __attribute__((section("license"), used)) = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_loader);
} loader_heap SEC(".maps");

#define VM_EXEC         0x00000004
#define MSG_OP_LOADER   26

__attribute__((section(("kprobe/perf_event_mmap_output")), used)) int
loader_kprobe(struct pt_regs *ctx)
{
	struct execve_map_value *curr;
	struct task_struct *current;
	struct perf_mmap_event *mmap_event;
	struct msg_loader *msg;
	int zero = 0;
	const char *file;
	struct vm_area_struct *vma;
	unsigned long vm_flags;
	void *pe;
	int tgid;
	size_t total;
	long len;

	msg = map_lookup_elem(&loader_heap, &zero);
	if (!msg)
		return 0;

	pe = (void *) PT_REGS_PARM1_CORE(ctx);

	if (!msg->pe)
		msg->pe = pe;
	else if (msg->pe != pe)
		return 0;

	current = (struct task_struct *)get_current_task();
	tgid = BPF_CORE_READ(current, tgid);

        curr = execve_map_get_noinit(tgid);
        if (!curr)
		return 0;

	msg->current.pid = curr->key.pid;
	msg->current.ktime = curr->key.ktime;

	mmap_event = (struct perf_mmap_event *) PT_REGS_PARM2_CORE(ctx);

	vma = BPF_CORE_READ(mmap_event, vma);
	vm_flags = BPF_CORE_READ(vma, vm_flags);

	if (!(vm_flags & VM_EXEC))
		return 0;

	probe_read(&msg->buildid[0], sizeof(msg->buildid),
                           _(&mmap_event->build_id[0]));

	file = BPF_CORE_READ(mmap_event, file_name);
	len = probe_read_str(&msg->file, sizeof(msg->file), file);
	msg->file_len = (__u32) len;

	msg->pid = tgid;

	total = offsetof(struct msg_loader, pe);
	msg->common.size = total;
	msg->common.ktime = ktime_get_ns();
	msg->common.op = MSG_OP_LOADER;
	msg->common.flags = 0;

	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg, total);
	return 0;
}
