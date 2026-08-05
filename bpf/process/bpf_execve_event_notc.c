// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "bpf_process_event.h"
#include "bpf_execve_event.h"
#include "bpf_helpers.h"
#include "bpf_rate.h"
#include "errmetrics.h"
#include "bpf_mbset.h"
#include "bpf_ktime.h"
#include "environ_conf.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

#ifdef __V511_BPF_PROG
#ifndef __V61_BPF_PROG
FUNC_INLINE void
execve_event_zero_tail(struct msg_execve_event *event)
{
	volatile __u8 *bytes = (volatile __u8 *)event;
	volatile __u64 *words;
	__u32 end, i, off, size = event->common.size;

	if (size > sizeof(*event))
		size = sizeof(*event);
	end = (size + sizeof(*words) - 1) & ~(sizeof(*words) - 1);
	if (end > sizeof(*event))
		end = sizeof(*event);

#pragma unroll
	for (i = 0; i < sizeof(*words); i++) {
		off = size + i;
		if (off < end)
			bytes[off] = 0;
	}

#pragma clang loop unroll(disable)
	for (i = sizeof(*event); i > end; i -= sizeof(*words)) {
		words = (volatile __u64 *)(bytes + i - sizeof(*words));
		*words = 0;
	}
}

FUNC_INLINE void
execve_event_copy(struct msg_execve_event *dst, struct msg_execve_event *src)
{
	volatile __u64 *dst_data = (volatile __u64 *)dst;
	volatile __u64 *src_data = (volatile __u64 *)src;
	__u32 i;

#pragma clang loop unroll(disable)
	for (i = 0; i < sizeof(*dst) / sizeof(*dst_data); i++)
		dst_data[i] = src_data[i];
}
#endif /* !__V61_BPF_PROG */

#ifdef __V61_BPF_PROG
#define EXECVE_FIXED_SIZE \
	(offsetof(struct msg_execve_event, process) + offsetof(struct msg_process, args))
#define EXECVE_ARGS_DESC_OFF MAXARGLENGTH
#define EXECVE_ENVS_DESC_OFF (MAXARGLENGTH + sizeof(struct data_event_desc))
#define EXECVE_COPY_CHUNK 64

struct execve_payload_plan {
	unsigned long args_start;
	unsigned long args_bytes;
	unsigned long envs_start;
	unsigned long envs_bytes;
	unsigned long filename;
	char *cwd;
	__u32 flags;
	__u32 size_path;
	__u32 size_args;
	__u32 size_cwd;
	__u32 size_envs;
	__u8 spill_path;
	__u8 spill_args;
	__u8 spill_envs;
};

struct execve_dynptr_copy_ctx {
	struct bpf_dynptr *ptr;
	const char *source;
	__u32 offset;
	__u32 chunks;
	int error;
};

FUNC_INLINE void
execve_plan_args_source(struct execve_payload_plan *plan,
			struct execve_heap *heap)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	unsigned long start_stack, end_stack;
	struct mm_struct *mm;
	long off;

	probe_read(&mm, sizeof(mm), _(&task->mm));
	if (!mm)
		return;
	probe_read(&start_stack, sizeof(start_stack), _(&mm->arg_start));
	probe_read(&end_stack, sizeof(end_stack), _(&mm->arg_end));
	if (!start_stack || !end_stack)
		return;

	off = probe_read_str(heap->maxpath, sizeof(heap->maxpath),
			     (char *)start_stack);
	if (off < 0)
		return;
	start_stack += off;
	if (end_stack < start_stack)
		return;

	plan->args_start = start_stack;
	plan->args_bytes = end_stack - start_stack;
}

FUNC_INLINE void execve_plan_path(struct execve_payload_plan *plan,
				  struct execve_heap *heap, void *filename)
{
	__s32 size;

	size = probe_read_str(heap->maxpath, MAXARGLENGTH - 1, filename);
	if (size < 0) {
		plan->flags |= EVENT_ERROR_FILENAME;
		return;
	}
	if (size == MAXARGLENGTH - 1) {
		plan->filename = (unsigned long)filename;
		plan->spill_path = 1;
		size = sizeof(struct data_event_desc);
	} else if (size > 0) {
		size--;
	}
	plan->size_path = size;
}

FUNC_INLINE void execve_plan_args(struct execve_payload_plan *plan)
{
	unsigned long free_size, size = plan->args_bytes;
	__u32 used = offsetof(struct msg_process, args) + plan->size_path;

	if (!plan->args_start || used >= BUFFER)
		return;
	free_size = BUFFER - used;
	if (size < BUFFER && size < free_size) {
		if (size)
			size--;
		size &= BUFFER - 1;
	} else {
		plan->spill_args = 1;
		size = sizeof(struct data_event_desc);
	}
	plan->size_args = size;
}

FUNC_INLINE void
execve_plan_cwd(struct execve_payload_plan *plan, __u32 pid)
{
	struct task_struct *task = get_task_from_pid(pid);
	struct fs_struct *fs;
	int flags = 0, size;

	probe_read(&fs, sizeof(fs), _(&task->fs));
	if (!fs) {
		plan->flags |= EVENT_ERROR_CWD;
		return;
	}

	plan->cwd = d_path_local(_(&fs->pwd), &size, &flags);
	if (!plan->cwd)
		return;
	if (!size)
		plan->flags |= EVENT_ROOT_CWD;
	if (flags & UNRESOLVED_PATH_COMPONENTS)
		plan->flags |= EVENT_ERROR_PATH_COMPONENTS;
	plan->size_cwd = size;
}

FUNC_INLINE void execve_plan_envs(struct execve_payload_plan *plan)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	unsigned long env_start, env_end, free_size, size;
	struct mm_struct *mm;
	__u32 used;

	if (!ENV_VARS_ENABLED)
		return;
	used = offsetof(struct msg_process, args) + plan->size_path +
	       plan->size_args + plan->size_cwd;
	if (used >= BUFFER)
		return;

	probe_read(&mm, sizeof(mm), _(&task->mm));
	if (!mm)
		return;
	probe_read(&env_start, sizeof(env_start), _(&mm->env_start));
	probe_read(&env_end, sizeof(env_end), _(&mm->env_end));
	if (!env_start || !env_end || env_end < env_start)
		return;

	free_size = BUFFER - used;
	size = env_end - env_start;
	plan->envs_start = env_start;
	plan->envs_bytes = size;
	if (size < BUFFER && size < free_size) {
		if (size)
			size--;
		size &= BUFFER - 1;
	} else {
		plan->spill_envs = 1;
		size = sizeof(struct data_event_desc);
	}
	plan->size_envs = size;
}

struct execve_plan_ctx {
	struct linux_binprm *bprm;
	struct execve_payload_plan *plan;
	struct execve_heap *heap;
};

static long execve_plan_v61(__u32 index, void *data)
{
	struct execve_plan_ctx *ctx = data;
	struct linux_binprm *bprm = ctx->bprm;
	char *filename;

	execve_plan_args_source(ctx->plan, ctx->heap);
	probe_read(&filename, sizeof(filename), _(&bprm->filename));
	execve_plan_path(ctx->plan, ctx->heap, filename);
	execve_plan_args(ctx->plan);
	execve_plan_cwd(ctx->plan, get_current_pid_tgid() >> 32);
	execve_plan_envs(ctx->plan);
	return 1;
}

struct execve_spills_ctx {
	struct bpf_raw_tracepoint_args *ctx;
	struct execve_payload_plan *plan;
	struct execve_heap *heap;
};

static long execve_spills_v61(__u32 index, void *data)
{
	struct execve_spills_ctx *ctx = data;
	unsigned long start, bytes;
	long size;

	if (index == 0) {
		if (!ctx->plan->spill_envs)
			return 0;
		start = ctx->plan->envs_start;
		bytes = ctx->plan->envs_bytes;
	} else {
		if (!ctx->plan->spill_args)
			return 0;
		start = ctx->plan->args_start;
		bytes = ctx->plan->args_bytes;
	}

	size = data_event_bytes(
		ctx->ctx,
		(struct data_event_desc *)(ctx->heap->maxpath + EXECVE_ARGS_DESC_OFF),
		start, bytes, (struct bpf_map_def *)&data_heap);
	if (index == 0) {
		if (size > 0) {
			memcpy(ctx->heap->maxpath + EXECVE_ENVS_DESC_OFF,
			       ctx->heap->maxpath + EXECVE_ARGS_DESC_OFF,
			       sizeof(struct data_event_desc));
			ctx->plan->flags |= EVENT_ENVS_DATA;
		} else {
			ctx->plan->size_envs = 0;
		}
	} else if (size > 0) {
		ctx->plan->flags |= EVENT_DATA_ARGS;
	} else {
		ctx->plan->size_args = 0;
	}
	return 0;
}

static long execve_dynptr_copy_chunk(__u32 index, void *data)
{
	struct execve_dynptr_copy_ctx *copy = data;
	__u32 pos;
	void *dst;
	int err;

	if (index >= copy->chunks)
		return 1;
	index &= (CWD_MAX - 1) / EXECVE_COPY_CHUNK;
	pos = index * EXECVE_COPY_CHUNK;
	dst = dynptr_data(copy->ptr, copy->offset + pos,
			  EXECVE_COPY_CHUNK);
	if (!dst) {
		copy->error = -E2BIG;
		return 1;
	}
	err = probe_read(dst, EXECVE_COPY_CHUNK, copy->source + pos);
	if (err < 0) {
		copy->error = err;
		return 1;
	}
	return 0;
}

FUNC_LOCAL int
execve_dynptr_copy(struct bpf_dynptr *ptr, __u32 *offset, const void *source,
		   __u32 length)
{
	struct execve_dynptr_copy_ctx copy = {
		.ptr = ptr,
		.source = source,
		.offset = *offset,
		.chunks = length / EXECVE_COPY_CHUNK,
	};
	__u32 copied, tail;
	void *dst;
	int err;

	if (length > CWD_MAX - 1)
		return -E2BIG;
	loop((CWD_MAX - 1) / EXECVE_COPY_CHUNK, execve_dynptr_copy_chunk,
	     &copy, 0);
	if (copy.error)
		return copy.error;
	copied = length & ~(EXECVE_COPY_CHUNK - 1);
	tail = length & (EXECVE_COPY_CHUNK - 1);
	if (!tail) {
		*offset = copy.offset + copied;
		return 0;
	}
	dst = dynptr_data(ptr, copy.offset + copied, EXECVE_COPY_CHUNK);
	if (!dst)
		return -E2BIG;
	err = probe_read(dst, tail, copy.source + copied);
	if (err < 0)
		return err;
	*offset = copy.offset + copied + tail;
	return 0;
}

FUNC_LOCAL int
execve_dynptr_zero(struct bpf_dynptr *ptr, __u32 offset, __u32 length)
{
	__u32 i;
	struct {
		__u8 value[EXECVE_COPY_CHUNK];
	} *chunk;
	__u8 *byte;

	if (length > sizeof(struct msg_execve_event) + EXECVE_COPY_CHUNK - 1)
		return -E2BIG;

#pragma clang loop unroll(disable)
	for (i = 0; i < (sizeof(struct msg_execve_event) +
			EXECVE_COPY_CHUNK - 1) / EXECVE_COPY_CHUNK; i++) {
		if (length < EXECVE_COPY_CHUNK)
			break;
		chunk = dynptr_data(ptr, offset, EXECVE_COPY_CHUNK);
		if (!chunk)
			return -E2BIG;
		memset(chunk->value, 0, sizeof(chunk->value));
		offset += EXECVE_COPY_CHUNK;
		length -= EXECVE_COPY_CHUNK;
	}

#pragma clang loop unroll(disable)
	for (i = 0; i < EXECVE_COPY_CHUNK - 1; i++) {
		if (!length)
			break;
		byte = dynptr_data(ptr, offset, 1);
		if (!byte)
			return -E2BIG;
		*byte = 0;
		offset++;
		length--;
	}
	return 0;
}

struct execve_metadata_ctx {
	struct bpf_raw_tracepoint_args *ctx;
	struct msg_execve_event *event;
	const void *args_source;
	__u32 flags;
	__u32 size_path;
	__u32 size_args;
	__u32 size_cwd;
	__u32 size_envs;
	__u8 keep;
};

static long execve_metadata_v61(__u32 index, void *data)
{
	struct execve_metadata_ctx *meta = data;
	struct msg_process *p;

	execve_event_init_fixed(meta->ctx, meta->event);
	p = &meta->event->process;
	p->flags |= meta->flags;
	p->size_path = meta->size_path;
	p->size_args = meta->size_args;
	p->size_cwd = meta->size_cwd;
	p->size_envs = meta->size_envs;
	p->size += meta->size_path + meta->size_args + meta->size_cwd +
		   meta->size_envs;
	meta->event->common.size = offsetof(struct msg_execve_event, process) +
				   p->size;

	if (!execve_rate_check(meta->ctx, meta->event))
		return 1;
	execve_finalize_event_from(meta->ctx, meta->event, meta->args_source);
	meta->keep = 1;
	return 1;
}

static __attribute__((noinline)) int
execve_dynptr_event(struct bpf_raw_tracepoint_args *ctx)
{
	struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];
	struct execve_payload_plan *plan;
	struct execve_payload_plan payload;
	struct msg_execve_event *event;
	struct execve_heap *heap;
	struct execve_metadata_ctx meta = {};
	struct execve_plan_ctx planner = {};
	struct execve_spills_ctx spills = {};
	struct msg_process *p;
	struct bpf_dynptr ring = {};
	const void *args_source = NULL;
	__u32 planned_size, reserve_size, last_size, offset, zero = 0;
	int err;

	heap = map_lookup_elem(&execve_heap, &zero);
	if (!heap)
		return 0;
	plan = (struct execve_payload_plan *)map_lookup_elem(&execve_val, &zero);
	if (!plan)
		return 0;
	memset(plan, 0, sizeof(*plan));
	planner.bprm = bprm;
	planner.plan = plan;
	planner.heap = heap;
	loop(1, execve_plan_v61, &planner, 0);
	if (plan->spill_path) {
		err = data_event_str(ctx,
			(struct data_event_desc *)heap->maxpath,
			plan->filename, (struct bpf_map_def *)&data_heap);
		if (err > 0)
			plan->flags |= EVENT_DATA_FILENAME;
		else {
			plan->flags |= EVENT_ERROR_FILENAME;
			plan->size_path = 0;
		}
	}
	spills.ctx = ctx;
	spills.plan = plan;
	spills.heap = heap;
	loop(2, execve_spills_v61, &spills, 0);
	probe_read(&payload, sizeof(payload), plan);
	plan = &payload;
	planned_size = EXECVE_FIXED_SIZE + plan->size_path + plan->size_args +
		       plan->size_cwd + plan->size_envs;
	if (planned_size > sizeof(*event))
		planned_size = sizeof(*event);
	if (plan->size_envs)
		last_size = plan->size_envs;
	else if (plan->size_cwd)
		last_size = plan->size_cwd;
	else if (plan->size_args)
		last_size = plan->size_args;
	else
		last_size = plan->size_path;
	reserve_size = planned_size +
		       ((-last_size) & (EXECVE_COPY_CHUNK - 1));
	err = ringbuf_reserve_dynptr(&tg_rb_events, reserve_size, 0, &ring);
	if (err) {
		event_output_update_error_metric(MSG_OP_EXECVE, -EAGAIN);
		ringbuf_discard_dynptr(&ring, 0);
		return 0;
	}

	event = dynptr_data(&ring, 0, EXECVE_FIXED_SIZE);
	if (!event) {
		ringbuf_discard_dynptr(&ring, 0);
		return 0;
	}
	if (plan->flags & EVENT_DATA_ARGS)
		args_source = heap->maxpath + EXECVE_ARGS_DESC_OFF;
	else
		args_source = (const void *)plan->args_start;
	meta.ctx = ctx;
	meta.event = event;
	meta.args_source = args_source;
	meta.flags = plan->flags;
	meta.size_path = plan->size_path;
	meta.size_args = plan->size_args;
	meta.size_cwd = plan->size_cwd;
	meta.size_envs = plan->size_envs;
	loop(1, execve_metadata_v61, &meta, 0);
	if (!meta.keep) {
		ringbuf_discard_dynptr(&ring, 0);
		return 0;
	}
	p = &event->process;

	offset = EXECVE_FIXED_SIZE;
	if (execve_dynptr_copy(&ring, &offset, heap->maxpath,
				plan->size_path) < 0) {
		p->flags &= ~EVENT_DATA_FILENAME;
		p->flags |= EVENT_ERROR_FILENAME;
		plan->size_path = 0;
	}
	if (execve_dynptr_copy(&ring, &offset, args_source,
				plan->size_args) < 0) {
		p->flags &= ~EVENT_DATA_ARGS;
		p->flags |= EVENT_ERROR_ARGS;
		plan->size_args = 0;
		args_source = NULL;
	}
	if (execve_dynptr_copy(&ring, &offset, plan->cwd,
				plan->size_cwd) < 0) {
		p->flags |= EVENT_ERROR_CWD;
		plan->size_cwd = 0;
	}
	if (plan->flags & EVENT_ENVS_DATA)
		plan->envs_start = (unsigned long)(heap->maxpath + EXECVE_ENVS_DESC_OFF);
	if (execve_dynptr_copy(&ring, &offset, (const void *)plan->envs_start,
				plan->size_envs) < 0) {
		p->flags &= ~EVENT_ENVS_DATA;
		p->flags |= EVENT_ENVS_ERROR;
		plan->size_envs = 0;
	}
	p->size_path = plan->size_path;
	p->size_args = plan->size_args;
	p->size_cwd = plan->size_cwd;
	p->size_envs = plan->size_envs;
	p->size = offsetof(struct msg_process, args) + plan->size_path +
		  plan->size_args + plan->size_cwd + plan->size_envs;
	event->common.size = offsetof(struct msg_execve_event, process) + p->size;

	if (offset < reserve_size)
		execve_dynptr_zero(&ring, offset, reserve_size - offset);
	ringbuf_submit_dynptr(&ring, 0);
	return 0;
}
#endif /* __V61_BPF_PROG */

static __attribute__((noinline)) int
execve_ringbuf_event(struct bpf_raw_tracepoint_args *ctx)
{
#ifdef __V61_BPF_PROG
	return execve_dynptr_event(ctx);
#else
	struct msg_execve_event *event;
	struct msg_execve_event *output;

	event = ringbuf_reserve(&tg_rb_events, sizeof(*event), 0);
	if (!event) {
		event_output_update_error_metric(MSG_OP_EXECVE, -EAGAIN);
		return 0;
	}

	execve_event_init(ctx, event);

	if (!execve_rate_check(ctx, event)) {
		ringbuf_discard(event, 0);
		return 0;
	}

	execve_finalize_event(ctx, event);
	/* The complete reservation is visible to user space on submission. */
	execve_event_zero_tail(event);

	/*
	 * Data events are reserved after the exec event and must be consumed
	 * first. Move the exec event behind them in the ring buffer while keeping
	 * the common path zero-copy.
	 */
	if (event->process.flags &
	    (EVENT_DATA_FILENAME | EVENT_DATA_ARGS | EVENT_ENVS_DATA)) {
		output = ringbuf_reserve(&tg_rb_events, sizeof(*output), 0);
		if (!output) {
			event_output_update_error_metric(MSG_OP_EXECVE, -EAGAIN);
			ringbuf_discard(event, 0);
			return 0;
		}
		execve_event_copy(output, event);
		ringbuf_discard(event, 0);
		event = output;
	}

	ringbuf_submit(event, 0);
	return 0;
#endif
}
#endif

__attribute__((section("raw_tracepoint/sys_execve"), used)) int
event_execve(struct bpf_raw_tracepoint_args *ctx)
{
	struct msg_execve_event *event;
	__u32 zero = 0;

#ifdef __V511_BPF_PROG
	struct tetragon_conf *conf;

	conf = map_lookup_elem(&tg_conf_map, &zero);
	if (!conf || !conf->use_perf_ring_buf)
		return execve_ringbuf_event(ctx);
#endif

	event = map_lookup_elem(&execve_msg_heap_map, &zero);
	if (!event)
		return 0;

	execve_event_init(ctx, event);

	if (execve_rate_check(ctx, event))
		return execve_send_event(ctx, event);
	return 0;
}
