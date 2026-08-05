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

static __attribute__((noinline)) int
execve_ringbuf_event(struct bpf_raw_tracepoint_args *ctx)
{
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
