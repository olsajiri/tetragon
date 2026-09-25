// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __KSTRLEN_H__
#define __KSTRLEN_H__

#include "bpf_helpers.h"
#include "config.h"

#define KSTRLEN_CHUNK	  32
#define KSTRLEN_MAX_ITER  128 /* KSTRLEN_CHUNK * KSTRLEN_MAX_ITER =~ 4096 byte cap */

FUNC_INLINE int kstrlen_probe_read(const char *s)
{
	char buf[KSTRLEN_CHUNK];
	int total = 0;
	int ret;
	int idx;

	if (CONFIG(ITER_NUM)) {
		bpf_for(idx, 0, KSTRLEN_MAX_ITER)
		{
			ret = probe_read_str(buf, KSTRLEN_CHUNK, s + total);
			if (ret < 0)
				return ret;
			if (ret < KSTRLEN_CHUNK)
				return total + ret - 1;
			total += KSTRLEN_CHUNK - 1;
		}
	} else {
		for (idx = 0; idx < KSTRLEN_MAX_ITER; idx++) {
			ret = probe_read_str(buf, KSTRLEN_CHUNK, s + total);
			if (ret < 0)
				return ret;
			if (ret < KSTRLEN_CHUNK)
				return total + ret - 1;
			total += KSTRLEN_CHUNK - 1;
		}
	}
	return total;
}

FUNC_INLINE int kstrlen(const char *s)
{
	if (bpf_ksym_exists(bpf_strlen))
		return bpf_strlen(s);

	return kstrlen_probe_read(s);
}

#endif /* __KSTRLEN_H__ */
