// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __HEAP_H__
#define __HEAP_H__

#include "ratelimit_maps.h"
#include "string_maps.h"

struct heap_ro_value {
	union {
		char string_maps_heap[STRING_MAPS_HEAP_SIZE];
		char ratelimit_heap[sizeof(struct ratelimit_key) + 128];
		struct msg_generic_kprobe process_call_heap;
	};
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct heap_ro_value);
} heap_ro_zero SEC(".maps");

/*
 * Lookup-or-seed helpers for the per-invocation scratch heaps that are hash
 * maps (keyed by pid_tgid) under GENERIC_UPROBE/GENERIC_URETPROBE/
 * GENERIC_USDT and plain per-cpu arrays otherwise; see the "#if defined(...)"
 * guards next to each map's declaration for why. A hash entry doesn't exist
 * until first touched by this thread, so on a miss we seed a fresh zeroed
 * entry from heap_ro_zero (map_update_elem needs a value to copy from, and
 * these are too large to build on the BPF stack) before looking it up again.
 * heap_dtor() in generic_maps.h deletes these entries once the invocation is
 * done, so the next one always starts from a fresh seed.
 */
#if defined(GENERIC_UPROBE) || defined(GENERIC_URETPROBE) || defined(GENERIC_USDT)
FUNC_INLINE void *string_maps_heap_get(void)
{
	__u64 key = get_current_pid_tgid();
	void *val = map_lookup_elem(&string_maps_heap, &key);
	struct heap_ro_value *ro;
	__u32 zidx = 0;

	if (val)
		return val;
	ro = map_lookup_elem(&heap_ro_zero, &zidx);
	if (!ro)
		return 0;
	if (map_update_elem(&string_maps_heap, &key, &ro->string_maps_heap, BPF_ANY))
		return 0;
	return map_lookup_elem(&string_maps_heap, &key);
}
#else
FUNC_INLINE void *string_maps_heap_get(void)
{
	__u32 zero = 0;

	return map_lookup_elem(&string_maps_heap, &zero);
}
#endif /* GENERIC_UPROBE || GENERIC_URETPROBE || GENERIC_USDT */

struct heap_value {
	union {
		char fdinstall[4104]; /* 4096B paths + 4B length + 4B flags */
	};
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct heap_value);
} heap SEC(".maps");

#endif // __HEAP_H__
