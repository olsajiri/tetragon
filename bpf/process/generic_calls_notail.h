// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __GENERIC_CALLS_NOTAIL_H__
#define __GENERIC_CALLS_NOTAIL_H__

#include "generic_calls.h"

FUNC_LOCAL int generic_process_filter_notail(void)
{
	int ret, i;

	bpf_for(i, 0, MAX_SELECTORS + 1) {
		ret = generic_process_filter();
		if (ret != PFILTER_CONTINUE)
			break;
	}
	return ret;
}

#endif /* __GENERIC_CALLS_NOTAIL_H__ */
