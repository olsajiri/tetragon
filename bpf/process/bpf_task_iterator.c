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

struct task_iter_proc {
	__u32 type;
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

struct task_iter_args {
	__u32 type;
	__u32 size;
	__u8 args[16384];
};

#define TYPE_PROC 0
#define TYPE_ARGS 1

struct task_iter {
	union {
		struct task_iter_proc proc;
		struct task_iter_args args;
	};
};

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
	struct task_iter_proc *p;
	struct task_iter_args *a;
	struct task_iter *iter;
	union cap_value cap;
	__u32 zero = 0;

	if (task == (void *)0) {
		return 0;
	}

	iter = map_lookup_elem(&iter_heap, &zero);
	if (!iter)
		return 0;

	p = &iter->proc;
	p->type = 0;
	p->pid = BPF_CORE_READ(task, tgid);
	p->ktime = task_ktime(task);
	p->nspid = get_task_pid_vnr_task(task);

	// caps
	cap.base = BPF_CORE_READ(task, cred, cap_effective);
	p->effective = cap.val;

	cap.base = BPF_CORE_READ(task, cred, cap_inheritable);
	p->inheritable = cap.val;

	cap.base = BPF_CORE_READ(task, cred, cap_permitted);
	p->permitted = cap.val;

	// ns
	p->uts_inum = BPF_CORE_READ(task, nsproxy, uts_ns, ns.inum);
	p->ipc_inum = BPF_CORE_READ(task, nsproxy, ipc_ns, ns.inum);
	p->mnt_inum = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	{
		struct pid *pid = BPF_CORE_READ(task, thread_pid);

		if (pid) {
			int level = BPF_CORE_READ(pid, level);
			struct upid *up = BPF_CORE_READ(pid, numbers + level);

			p->pid_inum = BPF_CORE_READ(up, ns, ns.inum);
		} else {
			p->pid_inum = 0;
		}
	}

	p->pid_for_children_inum = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
	p->net_inum = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
	p->cgroup_inum = BPF_CORE_READ(task, nsproxy, cgroup_ns, ns.inum);
	p->user_inum = BPF_CORE_READ(task, mm, user_ns, ns.inum);

	if (bpf_core_field_exists(task->nsproxy->time_ns)) {
		p->time_inum = BPF_CORE_READ(task, nsproxy, time_ns, ns.inum);
		p->time_for_children_inum = BPF_CORE_READ(task, nsproxy, time_ns_for_children, ns.inum);
	}

	p->uid = get_current_uid_gid();

	{
		p->auid = 0;

		if (bpf_core_field_exists(task->loginuid)) {
			p->auid = BPF_CORE_READ(task, loginuid.val);
		} else if (bpf_core_field_exists(task->audit)) {
			if (BPF_CORE_READ(task, audit)) {
				p->auid = BPF_CORE_READ(task, audit, loginuid.val);
			}
                }
        }

	// parent
	parent = BPF_CORE_READ(task, parent);

	p->ppid = BPF_CORE_READ(parent, tgid);
	p->pktime = task_ktime(parent);
	p->pnspid = get_task_pid_vnr_task(parent);

	seq_write(seq, p, sizeof(*p));

	// args
	a = &iter->args;
	{
		unsigned long arg_start, arg_end;

		arg_start = BPF_CORE_READ(task, mm, arg_start);
		arg_end = BPF_CORE_READ(task, mm, arg_end);

		err = copy_from_user_task(&data->buf[0], size,
					(const void *) start_stack + total, task, 0);
	}

	return 0;
}
