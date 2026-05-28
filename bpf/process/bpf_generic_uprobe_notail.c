// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#ifndef __V61_BPF_PROG
#error "generic uprobe no-tail object is only supported for the v6.1 variant"
#endif

#ifdef __GENERIC_RETUPROBE_NOTAIL
#define GENERIC_URETPROBE
#else
#define GENERIC_UPROBE
#endif

#include "compiler.h"
#include "bpf_tracing.h"
#include "bpf_event.h"
#include "bpf_task.h"
#include "retprobe_map.h"
#include "types/operations.h"
#include "types/basic.h"
#ifndef __GENERIC_RETUPROBE_NOTAIL
#include "uprobe_offload.h"
#include "user_preload.h"
#endif

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

#include "generic_maps.h"
#include "generic_calls.h"
#include "generic_calls_notail.h"

#ifdef __MULTI_KPROBE
#define UPROBE_MAIN	"uprobe.multi/generic_uprobe"
#define URETPROBE_MAIN	"uprobe.multi/generic_retuprobe"
#define OFFLOAD		"uprobe.multi.s/generic_uprobe"
#else
#define UPROBE_MAIN	"uprobe/generic_uprobe"
#define URETPROBE_MAIN	"uprobe/generic_retuprobe"
#define OFFLOAD		"uprobe.s/generic_uprobe"
#endif

struct generic_uprobe_filter_arg_no_tail_ctx {
	void *ctx;
	bool is_entry;
	int arg;
	u8 op;
	int selidx;
};

#ifndef __GENERIC_RETUPROBE_NOTAIL
FUNC_LOCAL int generic_uprobe_process_event_no_tail_cb(__u32 idx, void *ctx)
{
	struct msg_generic_kprobe *e;
	int zero = 0;
	long errv;

	if (arg_idx(idx) == -1)
		return -1;
	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return -1;
	if (e->common.size >= MAX_TOTAL)
		return -1;

	errv = generic_read_arg(ctx, idx, e->common.size, (struct bpf_map_def *)0,
				__READ_ARG_ALL);
	if (errv > 0)
		e->common.size += errv;
	return errv > 0 ? 0 : 01;
}

FUNC_LOCAL int generic_uprobe_process_event_no_tail(void *ctx)
{
	int idx;

	if (arg_idx(0) == -1)
		return 1;

	bpf_for(idx, 0, MAX_POSSIBLE_ARGS) {
		if (generic_uprobe_process_event_no_tail_cb(idx, ctx))
			break;
	}

	return 0;
}
#endif

FUNC_LOCAL long generic_uprobe_actions_post_no_tail(void *ctx)
{
	struct selector_arg_filters *arg;
	struct selector_action *actions;
	struct msg_generic_kprobe *e;
	int actoff, pass, zero = 0;
	bool postit;
	__u8 *f;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	pass = e->pass;
	if (pass <= 1)
		return 0;

	f = map_lookup_elem(&filter_map, &e->idx);
	if (!f)
		return 0;

	asm volatile("%[pass] &= 0x7ff;\n"
		     : [pass] "+r"(pass)
		     :);
	arg = (struct selector_arg_filters *)&f[pass];

	actoff = pass + arg->arglen;
	asm volatile("%[actoff] &= 0x7ff;\n"
		     : [actoff] "+r"(actoff)
		     :);
	actions = (struct selector_action *)&f[actoff];

	postit = do_actions(ctx, actions);
	return postit;
}

FUNC_LOCAL int generic_uprobe_filter_arg_no_tail_cb(__u32 idx __maybe_unused, void *data)
{
	struct generic_uprobe_filter_arg_no_tail_ctx *cb = data;
	struct msg_generic_kprobe *e;
	int pass, zero = 0;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 1;

	pass = filter_args(cb->ctx, (struct bpf_map_def *)0, e,
			   cb->selidx & MAX_SELECTORS_MASK, cb->is_entry, cb->arg);
	if (pass) {
		if (pass > 1) {
			e->pass = pass;
			if (!generic_uprobe_actions_post_no_tail(cb->ctx))
				return 1;
		}
		generic_output(cb->ctx, cb->op);
		return 1;
	}

	cb->selidx = next_selidx(e, cb->selidx);
	if (cb->selidx > MAX_SELECTORS) {
		filter_args_reject(e->func_id);
		return 1;
	}
	e->tailcall_index_selector = cb->selidx;
	return 0;
}

FUNC_LOCAL int generic_uprobe_filter_arg_no_tail(void *ctx, bool is_entry, int arg, u8 op)
{
	struct generic_uprobe_filter_arg_no_tail_ctx cb;
	struct msg_generic_kprobe *e;
	int zero = 0;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	cb.ctx = ctx;
	cb.is_entry = is_entry;
	cb.arg = arg;
	cb.op = op;
	cb.selidx = e->tailcall_index_selector;

	loop(MAX_SELECTORS + 1, generic_uprobe_filter_arg_no_tail_cb, &cb, 0);
	return 0;
}

#ifndef __GENERIC_RETUPROBE_NOTAIL
FUNC_LOCAL int generic_uprobe_event_no_tail(void *ctx)
{
	int ret;

	if (generic_start_process_filter(ctx))
		return 0;

	ret = generic_process_filter_notail();
	if (ret != PFILTER_ACCEPT)
		return 0;

	if (generic_process_event_and_setup(ctx))
		return 0;

	if (generic_uprobe_process_event_no_tail(ctx))
		return 0;

	return generic_uprobe_filter_arg_no_tail(ctx, true, __FILTER_ARG_ALL,
						 MSG_OP_GENERIC_UPROBE);
}

__attribute__((section((UPROBE_MAIN)), used)) int
generic_uprobe_event(struct pt_regs *ctx)
{
	return generic_uprobe_event_no_tail(ctx);
}

__attribute__((section(OFFLOAD), used)) int
generic_sleepable_preload(struct pt_regs *ctx)
{
	return user_preload(ctx);
}

__attribute__((section(OFFLOAD), used)) int
generic_sleepable_preload_cleanup(struct pt_regs *ctx)
{
	return user_preload_cleanup(ctx);
}

__attribute__((section(OFFLOAD), used)) int
generic_sleepable_offload(struct pt_regs *ctx)
{
	return uprobe_offload(ctx);
}
#else
FUNC_LOCAL int generic_retuprobe_setup_no_tail(void *ctx, unsigned long ret)
{
	struct execve_map_value *enter;
	struct msg_generic_kprobe *e;
	struct retprobe_info info;
	struct event_config *config;
	bool walker = false;
	int zero = 0;
	__u32 ppid;
	long size = 0;
	long ty_arg, do_copy;
	__u64 pid_tgid;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	e->idx = get_index(ctx);

	config = map_lookup_elem(&config_map, &e->idx);
	if (!config)
		return 0;

	e->func_id = config->func_id;
	e->retprobe_id = retprobe_map_get_key(ctx);
	pid_tgid = get_current_pid_tgid();
	e->tid = (__u32)pid_tgid;

	if (!retprobe_map_get(e->func_id, e->retprobe_id, &info))
		return 0;

	*(unsigned long *)e->args = info.ktime_enter;
	size += sizeof(info.ktime_enter);

	ty_arg = config->argreturn;
	do_copy = config->argreturncopy;
	if (ty_arg) {
		e->arg_status[0] = 0;
		size += read_arg(ctx, 0, ty_arg, size, ret, 0, __READ_ARG_ALL);
	}

	asm volatile("%[size] &= 0x1fff;\n"
		     : [size] "+r"(size));

	switch (do_copy) {
	case char_buf:
		size = write_arg_status(e, size, 0);
		size += __copy_char_buf(ctx, size, info.ptr, ret, false, e);
		break;
	case char_iovec:
		size = write_arg_status(e, size, 0);
		size += __copy_char_iovec(size, info.ptr, info.cnt, ret, e);
		break;
	default:
		break;
	}

	enter = event_find_curr(&ppid, &walker);
	e->common.op = MSG_OP_GENERIC_UPROBE;
	e->common.flags = MSG_COMMON_FLAG_RETURN;
	e->common.pad[0] = 0;
	e->common.pad[1] = 0;
	e->common.size = size;
	e->common.ktime = tg_get_ktime();

	if (enter) {
		e->current.pid = enter->key.pid;
		e->current.ktime = enter->key.ktime;
	}
	e->current.pad[0] = 0;
	e->current.pad[1] = 0;
	e->current.pad[2] = 0;
	e->current.pad[3] = 0;

	e->func_id = config->func_id;
	e->common.size = size;

	return 1;
}

FUNC_LOCAL int generic_retuprobe_no_tail(void *ctx, unsigned long ret)
{
	if (!generic_retuprobe_setup_no_tail(ctx, ret))
		return 0;

	return generic_uprobe_filter_arg_no_tail(ctx, false, __FILTER_ARG_ALL,
						 MSG_OP_GENERIC_UPROBE);
}

__attribute__((section((URETPROBE_MAIN)), used)) int
BPF_KRETPROBE(generic_retuprobe_event, unsigned long ret)
{
	return generic_retuprobe_no_tail(ctx, ret);
}
#endif
