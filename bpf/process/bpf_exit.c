// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "bpf_exit.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

static int list_empty(struct list_head *head)
{
	struct list_head *next;

	probe_read(&next, sizeof(next), _(&head->next));
	return next == head;
}

__attribute__((section("kprobe/do_task_dead"), used)) int
event_exit(struct pt_regs *ctx)
{
	struct task_struct *task, *group_leader;
	struct list_head *thread_group;
	__u64 tgid;

	tgid = get_current_pid_tgid() >> 32;

	task = (struct task_struct *)get_current_task();
	probe_read(&group_leader, sizeof(group_leader), _(&task->group_leader));
	probe_read(&thread_group, sizeof(thread_group),
		   _(&group_leader->thread_group));

	if (list_empty(thread_group))
		event_exit_send(ctx, tgid);
	return 0;
}
