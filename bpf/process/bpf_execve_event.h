// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __BPF_EXECVE_EVENT_H__
#define __BPF_EXECVE_EVENT_H__

#include "bpf_mbset.h"
#include "bpf_rate.h"
#include "data_event.h"
#include "config.h"
#include "kstrlen.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_data);
} data_heap SEC(".maps");

FUNC_INLINE __u32
read_args(void *ctx, struct msg_execve_event *event)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct msg_process *p = &event->process;
	unsigned long start_stack;
	unsigned long free_size, args_size;
	struct args_source source;
	__u32 size = 0;
	char *args;
	int err;

#ifdef __LARGE_BPF_PROG
	event->args_source.start = 0;
	event->args_source.len = 0;
#endif

	if (!read_task_args_source(task, &source))
		return 0;
	start_stack = source.start;
	args_size = source.len;

#ifdef __LARGE_BPF_PROG
	/* Store pointer infos and late copy in execve_finalize_event() when storing
	 * the cache args.
	 */
	event->args_source.start = start_stack;
	event->args_source.len = args_size;
#endif

	size = p->size & 0x1ff /* 2*MAXARGLENGTH - 1*/;
	args = (char *)p + size;

	if (args >= (char *)&event->process + BUFFER)
		return 0;

	/* Read arguments either to rest of the space in the event,
	 * or use data event to send it separatelly.
	 */
	free_size = (char *)&event->process + BUFFER - args;

	if (args_size < 2) {
		/* args contains at most a '\0', nothing to read */
		size = 0;
	} else if (args_size < BUFFER && args_size < free_size) {
		/* args fit in the inline buffer, read them in */
		args_size -= 1; // strip trailing '\0'
		size = args_size & 0x3ff /* BUFFER - 1 */;
		err = with_errmetrics(probe_read, args, size, (char *)start_stack);
		if (err < 0) {
			p->flags |= EVENT_ERROR_ARGS;
			size = 0;
		}
	} else {
		/* args too big for inline buffer, use data event */
		size = data_event_bytes(ctx, (struct data_event_desc *)args,
					(unsigned long)start_stack,
					args_size,
					(struct bpf_map_def *)&data_heap);
		if (size > 0)
			p->flags |= EVENT_DATA_ARGS;
	}
	p->size_args = (__u16)size;
	return size;
}

#ifdef __LARGE_BPF_PROG

FUNC_INLINE __u32 read_envs(void *ctx, struct msg_execve_event *event)
{
	struct msg_process *p = &event->process;
	struct mm_struct *mm = NULL;
	struct task_struct *task;
	__u32 size = 0, flags = 0;
	unsigned long free_size, envs_size;
	unsigned long env_start, env_end;
	char *envs;
	int err;

	if (!CONFIG(ENV_VARS_ENABLED))
		return 0;

	envs = (char *)p + p->size;
	if (envs >= (char *)&event->process + BUFFER)
		return 0;

	task = (struct task_struct *)get_current_task();
	probe_read(&mm, sizeof(mm), _(&task->mm));
	if (!mm)
		return 0;

	with_errmetrics(probe_read, &env_start, sizeof(env_start), _(&mm->env_start));
	with_errmetrics(probe_read, &env_end, sizeof(env_end), _(&mm->env_end));

	if (!env_start || !env_end)
		return 0;

	free_size = (char *)&event->process + BUFFER - envs;
	envs_size = env_end - env_start;

	if (envs_size < 2) {
		/* envs contains at most a '\0', nothing to read */
		size = 0;
	} else if (envs_size < BUFFER && envs_size < free_size) {
		envs_size -= 1; // strip trailing '\0'
		size = envs_size & 0x3ff; /* BUFFER - 1 */

		err = probe_read(envs, size, (char *)env_start);
		if (err < 0) {
			flags |= EVENT_ENVS_ERROR;
			size = 0;
		}
	} else {
		size = data_event_bytes(ctx, (struct data_event_desc *)envs,
					(unsigned long)env_start,
					envs_size,
					(struct bpf_map_def *)&data_heap);
		if (size > 0)
			flags |= EVENT_ENVS_DATA;
	}

	p->size_envs = size;
	p->flags |= flags;
	return size;
}
#else
FUNC_INLINE __u32 read_envs(void *ctx, struct msg_execve_event *event)
{
	return 0;
}
#endif

FUNC_INLINE __u32
read_path(void *ctx, struct msg_execve_event *event, void *filename)
{
	struct msg_process *p = &event->process;
	__s32 size = 0;
	__u32 flags = 0;
	char *earg;

	earg = (void *)p + offsetof(struct msg_process, args);

	size = probe_read_str(earg, MAXARGLENGTH - 1, filename);
	if (size < 0) {
		flags |= EVENT_ERROR_FILENAME;
		size = 0;
	} else if (size == MAXARGLENGTH - 1) {
		size = data_event_str(ctx, (struct data_event_desc *)earg,
				      (unsigned long)filename,
				      (struct bpf_map_def *)&data_heap);
		if (size == 0)
			flags |= EVENT_ERROR_FILENAME;
		else
			flags |= EVENT_DATA_FILENAME;
	} else if (size > 0) {
		/* remove null byte */
		size -= 1;
	}

	p->size_path = (__u16)size;
	p->flags |= flags;
	return size;
}

FUNC_INLINE __u32
read_cwd(void *ctx, struct msg_process *p)
{
	if (p->flags & EVENT_ERROR_CWD)
		return 0;
	return getcwd(p, p->size, p->pid);
}

/* Full (uncapped, no data-event) variants used by event_execve_rb(), where
 * execve_event_size() has already reserved exactly enough ring buffer space
 * for the real (measured) size of each field - these trust that reservation
 * and just read the full amount, no truncation/data-event fallback needed.
 */

FUNC_INLINE __u32
read_path_full(void *ctx, struct msg_execve_event *event, void *filename)
{
	struct msg_process *p = &event->process;
	__s32 size = 0;
	__u32 flags = 0;
	char *earg;
	__u32 max = MAX_BUF_LEN;

	earg = (void *)p + offsetof(struct msg_process, args);

	asm volatile("%[max] &= 0xfff;\n"
		     : [max] "+r"(max));
	max -= 1; /* leave room for probe_read_str's forced NUL */

	size = probe_read_str(earg, max, filename);
	if (size < 0) {
		flags |= EVENT_ERROR_FILENAME;
		size = 0;
	} else if (size > 0) {
		/* remove null byte */
		size -= 1;
	}

	p->size_path = (__u16)size;
	p->flags |= flags;
	return size;
}

FUNC_INLINE __u32
read_args_full(void *ctx, struct msg_execve_event *event)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct msg_process *p = &event->process;
	unsigned long start_stack, args_size, off;
	struct args_source source;
	__u32 size = 0;
	char *args;
	int err;

#ifdef __LARGE_BPF_PROG
	event->args_source.start = 0;
	event->args_source.len = 0;
#endif

	if (!read_task_args_source(task, &source))
		return 0;
	start_stack = source.start;
	args_size = source.len;

#ifdef __LARGE_BPF_PROG
	/* Store pointer infos and late copy in execve_finalize_event() when storing
	 * the cache args.
	 */
	event->args_source.start = start_stack;
	event->args_source.len = args_size;
#endif

	if (args_size < 2) {
		/* args contains at most a '\0', nothing to read */
		p->size_args = 0;
		return 0;
	}

	off = p->size & 0x3fff; /* widened from read_args()'s 0x1ff - must cover a full-length path */
	args = (char *)p + off;

	args_size -= 1; // strip trailing '\0'
	size = args_size & 0xfff; /* verifier bound only - trust execve_event_size()'s reservation */

	err = with_errmetrics(probe_read, args, size, (char *)start_stack);
	if (err < 0) {
		p->flags |= EVENT_ERROR_ARGS;
		size = 0;
	}

	p->size_args = (__u16)size;
	return size;
}

FUNC_INLINE __u32
read_cwd_full(void *ctx, struct msg_process *p)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct fs_struct *fs = NULL;
	char *buffer;
	int flags = 0, size;
	unsigned long off;

	probe_read(&fs, sizeof(fs), _(&task->fs));
	if (!fs) {
		p->flags |= EVENT_ERROR_CWD;
		return 0;
	}

	buffer = d_path_local(_(&fs->pwd), &size, &flags);
	if (!buffer)
		return 0;

	off = p->size & 0x3fff; /* widened from getcwd()'s 0x3ff - must cover full path+args */
	asm volatile("%[size] &= 0xfff;\n"
		     : [size] "+r"(size));
	probe_read((char *)p + off, size, buffer);

	if (size == 0)
		p->flags |= EVENT_ROOT_CWD;
	if (flags & UNRESOLVED_PATH_COMPONENTS)
		p->flags |= EVENT_ERROR_PATH_COMPONENTS;
	p->flags = p->flags & ~(EVENT_NEEDS_CWD | EVENT_ERROR_CWD);
	p->size_cwd = (__u16)size;
	return size;
}

FUNC_INLINE __u32
read_envs_full(void *ctx, struct msg_execve_event *event)
{
	struct msg_process *p = &event->process;
	struct mm_struct *mm = NULL;
	struct task_struct *task;
	__u32 size = 0, flags = 0;
	unsigned long envs_size, off;
	unsigned long env_start, env_end;
	char *envs;
	int err;

	if (!CONFIG(ENV_VARS_ENABLED))
		return 0;

	task = (struct task_struct *)get_current_task();
	probe_read(&mm, sizeof(mm), _(&task->mm));
	if (!mm)
		return 0;

	with_errmetrics(probe_read, &env_start, sizeof(env_start), _(&mm->env_start));
	with_errmetrics(probe_read, &env_end, sizeof(env_end), _(&mm->env_end));

	if (!env_start || !env_end)
		return 0;

	envs_size = env_end - env_start;
	if (envs_size < 2) {
		/* envs contains at most a '\0', nothing to read */
		p->size_envs = 0;
		return 0;
	}

	off = p->size & 0x3fff; /* widened - must cover full path+args+cwd */
	envs = (char *)p + off;

	envs_size -= 1; // strip trailing '\0'
	size = envs_size & 0xfff; /* verifier bound only - trust execve_event_size()'s reservation */

	err = probe_read(envs, size, (char *)env_start);
	if (err < 0) {
		flags |= EVENT_ENVS_ERROR;
		size = 0;
	}

	p->size_envs = size;
	p->flags |= flags;
	return size;
}

FUNC_INLINE void
read_execve_shared_info(void *ctx, struct msg_process *p, __u64 pid)
{
	struct execve_info *info;

	info = execve_joined_info_map_get(pid);
	if (!info) {
		p->secureexec = 0;
		p->i_ino = 0;
		p->i_nlink = 0;
		return;
	}

	p->secureexec = info->secureexec;
	p->i_ino = info->i_ino;
	p->i_nlink = info->i_nlink;
	execve_joined_info_map_clear(pid);
}

FUNC_LOCAL void
execve_event_init(struct bpf_raw_tracepoint_args *ctx,
		  struct msg_execve_event *event, bool full)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];
	struct execve_map_value *parent;
	struct msg_process *p;
	char *filename;
	__u64 pid;

	pid = get_current_pid_tgid();
	parent = event_find_parent();
	if (parent) {
		event->parent = parent->key;
		update_mb_task(parent, &parent->bin);
		event->parent_flags = 0;
	} else {
		event_minimal_parent(event, task);
	}

	p = &event->process;
	p->flags = EVENT_EXECVE;
	p->size_path = 0;
	p->size_args = 0;
	p->size_cwd = 0;
	p->size_envs = 0;

	/**
	 * Per thread tracking rules TID == PID :
	 *  At exec all threads other than the calling one are destroyed, so
	 *  current becomes the new thread leader since we hook late during
	 *  execve.
	 */
	p->pid = pid >> 32;
	p->tid = (__u32)pid;
	p->nspid = get_task_pid_vnr_curr();
	p->ktime = tg_get_ktime();
	p->size = offsetof(struct msg_process, args);
	p->auid = get_auid();
	read_execve_shared_info(ctx, p, pid);

	probe_read(&filename, sizeof(filename), _(&bprm->filename));

	if (full) {
		p->size += read_path_full(ctx, event, filename);
		p->size += read_args_full(ctx, event);
		p->size += read_cwd_full(ctx, p);
		p->size += read_envs_full(ctx, event);
	} else {
		p->size += read_path(ctx, event, filename);
		p->size += read_args(ctx, event);
		p->size += read_cwd(ctx, p);
		p->size += read_envs(ctx, event);
	}

	event->common.op = MSG_OP_EXECVE;
	event->common.flags = 0;
	event->common.ktime = p->ktime;
	event->common.size = offsetof(struct msg_execve_event, process) + p->size;

	get_current_subj_creds(&event->creds, task);
	/**
	 * Instead of showing the task owner, we want to display the effective
	 * uid that is used to calculate the privileges of current task when
	 * acting upon other objects. This allows to be compatible with the 'ps'
	 * tool that reports snapshot of current processes.
	 */
	p->uid = event->creds.euid;
	get_namespaces(&event->ns, task);

	// Zero the cleanup key to prevent user space confusion.
	event->cleanup_key = (struct msg_execve_key){ 0 };
}

FUNC_LOCAL bool
execve_rate_check(void *ctx, struct msg_execve_event *msg)
{
#ifndef __RHEL7_BPF_PROG
	struct task_struct *task = (struct task_struct *)get_current_task();

	msg->process.flags |= __event_get_cgroup_info(task, &msg->kube);
#endif

	return cgroup_rate(ctx, &msg->kube, msg->common.ktime);
}

FUNC_LOCAL uint64_t
execve_finalize_event(struct bpf_raw_tracepoint_args *ctx,
		      struct msg_execve_event *event)
{
	struct linux_binprm *bprm __maybe_unused = (struct linux_binprm *)ctx->args[2];
	struct execve_map_value *curr;
	struct msg_process *p;
	uint64_t size;
	__u32 pid;
#if defined(__NS_CHANGES_FILTER) || defined(__CAP_CHANGES_FILTER)
	bool init_curr = 0;
#endif

#ifdef __LARGE_BPF_PROG
	// Reading the absolute path of the process exe for matchBinaries.
	// Historically we used the filename, a potentially relative path (maybe to
	// a symlink) coming from the execve tracepoint. For kernels not supporting
	// large BPF prog, we still use the filename.
	read_exe((struct task_struct *)get_current_task(), &event->exe);
#endif

	p = &event->process;

	pid = (get_current_pid_tgid() >> 32);

	curr = execve_map_get_noinit(pid);
	if (curr) {
		event->cleanup_key = curr->key;
#if defined(__NS_CHANGES_FILTER) || defined(__CAP_CHANGES_FILTER)
		/* if this exec event preceds a clone, initialize  capabilities
		 * and namespaces as well.
		 */
		if (curr->flags == EVENT_COMMON_FLAG_CLONE)
			init_curr = 1;
#endif
		curr->key.pid = p->pid;
		curr->key.ktime = p->ktime;
		curr->nspid = p->nspid;
		curr->pkey = event->parent;
		if (curr->flags & EVENT_COMMON_FLAG_CLONE)
			event_set_clone(p);
		curr->flags &= ~EVENT_COMMON_FLAG_CLONE;
		/* Set EVENT_IN_INIT_TREE flag on the process if nspid=1.
		 */
		set_in_init_tree(curr, NULL);
		if (curr->flags & EVENT_IN_INIT_TREE)
			event->process.flags |= EVENT_IN_INIT_TREE;
#ifdef __NS_CHANGES_FILTER
		if (init_curr)
			memcpy(&curr->ns, &event->ns, sizeof(struct msg_ns));
#endif
#ifdef __CAP_CHANGES_FILTER
		if (init_curr) {
			curr->caps.permitted = event->creds.caps.permitted;
			curr->caps.effective = event->creds.caps.effective;
			curr->caps.inheritable = event->creds.caps.inheritable;
		}
#endif

		update_parents_map(event, curr);

		/* zero out previous paths in ->bin */
		binary_reset(&curr->bin);
#ifdef __LARGE_BPF_PROG
		// read from proc exe stored at execve time
		copy_exe_to_bin(&event->exe, &curr->bin);
		copy_args(&event->args_source, &curr->args);
#else
		struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];
		char *filename;

		probe_read(&filename, sizeof(filename), _(&bprm->filename));
		curr->bin.path_length = probe_read_str(curr->bin.path, BINARY_PATH_MAX_LEN, (void *)filename);
		if (curr->bin.path_length > 1) {
			// don't include the NULL byte in the length
			curr->bin.path_length--;
		}
#endif

		update_mb_bitset(&curr->bin);
	}

	event->common.flags = 0;
	size = validate_msg_execve_size(
		sizeof(struct msg_common) + sizeof(struct msg_k8s) +
		sizeof(struct msg_execve_key) + sizeof(__u64) +
		sizeof(struct msg_cred) + sizeof(struct msg_ns) +
		sizeof(struct msg_execve_key) + p->size);
	return size;
}

#ifdef __V61_BPF_PROG
#define EXECVE_RB_SIZE sizeof(struct msg_execve_event)

FUNC_LOCAL __u64
execve_event_size(struct bpf_raw_tracepoint_args *ctx)
{
	struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];
	struct task_struct *task = (struct task_struct *)get_current_task();
	__u64 size = offsetof(struct msg_process, args);
	char *filename;

	/* -- path, mirrors read_path() -- */
	probe_read(&filename, sizeof(filename), _(&bprm->filename));
	{
		int psize = kstrlen(filename);

		if (psize < 0)
			psize = 0;
		size += psize;
	}

	/* -- args, mirrors read_args() -- */
	{
		struct args_source source;
		__u32 asize = 0;

		if (read_task_args_source(task, &source)) {
			unsigned long args_size = source.len;

			if (args_size >= 2)
				asize = (__u32)(args_size - 1);
		}
		size += asize;
	}

	/* -- cwd, mirrors read_cwd()/getcwd() -- */
	{
		struct fs_struct *fs = NULL;
		int cwd_size = 0;

		probe_read(&fs, sizeof(fs), _(&task->fs));
		if (fs)
			cwd_size = d_path_local_size(_(&fs->pwd));
		size += cwd_size;
	}

	/* -- envs, mirrors read_envs() -- */
	if (CONFIG(ENV_VARS_ENABLED)) {
		struct mm_struct *mm = NULL;
		__u32 esize = 0;

		probe_read(&mm, sizeof(mm), _(&task->mm));
		if (mm) {
			unsigned long env_start = 0, env_end = 0;

			probe_read(&env_start, sizeof(env_start), _(&mm->env_start));
			probe_read(&env_end, sizeof(env_end), _(&mm->env_end));
			if (env_start && env_end) {
				unsigned long envs_size = env_end - env_start;

				if (envs_size >= 2)
					esize = (__u32)(envs_size - 1);
			}
		}
		size += esize;
	}

	return offsetof(struct msg_execve_event, process) + size;
}

FUNC_INLINE void
execve_event_zero_tail(struct msg_execve_event *event)
{
	struct msg_process *p = &event->process;
	__u64 size = offsetof(struct msg_execve_event, process) + p->size;

	event->common.size = size;
	// todo: zero the tail
}

FUNC_LOCAL int
event_execve_rb(struct bpf_raw_tracepoint_args *ctx)
{
	struct msg_execve_event *event;
	struct bpf_dynptr ptr;
	__u64 size;

	size = execve_event_size(ctx);

	event = event_ringbuf_reserve_dynptr(MSG_OP_EXECVE, size, &ptr);
	if (!event)
		return 0;

	execve_event_init(ctx, event, true);

	if (!execve_rate_check(ctx, event)) {
		ringbuf_discard_dynptr(&ptr, 0);
		return 0;
	}

	execve_finalize_event(ctx, event);
	execve_event_zero_tail(event);

	ringbuf_submit_dynptr(&ptr, 0);
	return 0;
}
#endif /* __V61_BPF_PROG */

#endif /* __BPF_EXECVE_EVENT_H__ */
