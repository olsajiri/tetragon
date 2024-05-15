// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __INLINE_H__
#define __INLINE_H__

#ifdef __V61_BPF_PROG
#define FUNC_ATTR __attribute__((noinline)) __attribute__((__unused__))
#else
#define FUNC_ATTR static inline __attribute__((always_inline))
#endif

#endif /* __INLINE_H__ */
