// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"
#include "compiler.h"
#include "bpf_event.h"
#include "bpf_task.h"

#define GENERIC_UPROBE
#define SOPATH_MAX 128
#define SONAME_MAX 32
#ifndef NULL
#define NULL ((void *)0)
#endif

struct uprobe_regs {
	char sopath[SOPATH_MAX];
	__u32 sopath_len;
	char soname[SONAME_MAX];
	__u64 sym_addr;
	__u64 mmap_addr;
	__u64 dlopen_addr;
};

#include "uprobe_dyn.h"

const volatile __u64 java_mmap_offset;
const volatile __u64 java_setenv_offset;

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

SEC("uprobe.s/java_start")
int java_start(struct pt_regs *ctx)
{
	return uprobe_dyn_entry_state_machine(ctx, java_mmap_offset, java_setenv_offset);
}
