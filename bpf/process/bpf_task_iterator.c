// SPDX-License-Identifier: GPL-2.0
// Copyright Authors of Tetragon

#include "vmlinux.h"
#include "api.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "common.h"
#include "bpf_events.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

union cap_value {
	kernel_cap_t base;
	__u64 val;
};

struct task_iter {
	__u32 pid;
	__u32 nspid;
	__u64 ktime;
	__u32 ppid;
	__u32 pnspid;
	__u64 pktime;
	__u64 effective;
	__u64 inheritable;
	__u64 permitted;
	__u32 uts_inum;
	__u32 ipc_inum;
	__u32 mnt_inum;
	__u32 pid_inum;
	__u32 pid_for_children_inum;
	__u32 net_inum;
	__u32 time_inum;
	__u32 time_for_children_inum;
	__u32 cgroup_inum;
	__u32 user_inum;
	__u32 uid;
	__u32 auid;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct task_iter);
} iter_heap SEC(".maps");

static inline __attribute__((always_inline)) __u64
task_ktime(struct task_struct *task)
{
	__u64 ktime = BPF_CORE_READ(task, start_boottime);

	return ktime + ktime_get_boot_ns();
}

__attribute__((section("iter.s/task"), used)) int
dump_task(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct task_struct *parent;
	struct task_iter *iter;
	union cap_value cap;
	__u32 zero = 0;

	if (task == (void *)0) {
		return 0;
	}

	iter = map_lookup_elem(&iter_heap, &zero);
	if (!iter)
		return 0;

	iter->pid = BPF_CORE_READ(task, tgid);
	iter->ktime = task_ktime(task);
	iter->nspid = get_task_pid_vnr_task(task);

	// caps
	cap.base = BPF_CORE_READ(task, cred, cap_effective);
	iter->effective = cap.val;

	cap.base = BPF_CORE_READ(task, cred, cap_inheritable);
	iter->inheritable = cap.val;

	cap.base = BPF_CORE_READ(task, cred, cap_permitted);
	iter->permitted = cap.val;

	// ns
	iter->uts_inum = BPF_CORE_READ(task, nsproxy, uts_ns, ns.inum);
	iter->ipc_inum = BPF_CORE_READ(task, nsproxy, ipc_ns, ns.inum);
	iter->mnt_inum = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	{
		struct pid *p = BPF_CORE_READ(task, thread_pid);

		if (p) {
			int level = BPF_CORE_READ(p, level);
			struct upid *up = BPF_CORE_READ(p, numbers + level);

			iter->pid_inum = BPF_CORE_READ(up, ns, ns.inum);
		} else {
			iter->pid_inum = 0;
		}
	}

	iter->pid_for_children_inum = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
	iter->net_inum = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
	iter->cgroup_inum = BPF_CORE_READ(task, nsproxy, cgroup_ns, ns.inum);
	iter->user_inum = BPF_CORE_READ(task, mm, user_ns, ns.inum);

	if (bpf_core_field_exists(task->nsproxy->time_ns)) {
		iter->time_inum = BPF_CORE_READ(task, nsproxy, time_ns, ns.inum);
		iter->time_for_children_inum = BPF_CORE_READ(task, nsproxy, time_ns_for_children, ns.inum);
	}

	iter->uid = get_current_uid_gid();

	{
		iter->auid = 0;

		if (bpf_core_field_exists(task->loginuid)) {
			iter->auid = BPF_CORE_READ(task, loginuid.val);
		} else if (bpf_core_field_exists(task->audit)) {
			if (BPF_CORE_READ(task, audit)) {
				iter->auid = BPF_CORE_READ(task, audit, loginuid.val);
			}
                }
        }

	// parent
	parent = BPF_CORE_READ(task, parent);

	iter->ppid = BPF_CORE_READ(parent, tgid);
	iter->pktime = task_ktime(parent);
	iter->pnspid = get_task_pid_vnr_task(parent);

	seq_write(seq, iter, sizeof(*iter));

	return 0;
}
