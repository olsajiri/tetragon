// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Tetragon */

/*
 * Native JVMTI agent that Tetragon loads into running HotSpot JVMs.
 *
 * The agent connects to Tetragon's control socket, receives hooks (classes
 * and methods to monitor) and rewrites matching classes so each monitored
 * method calls TetragonHook.enter(key) at its entry. The native enter()
 * reports the call to Tetragon through the shared ring buffer.
 *
 * The control channel and the ring formats are described in proto.h.
 *
 * Agent lifetime, time goes down:
 *
 *   Event           Tetragon <-> agent       Agent function and its actions
 *   -----           ------------------       ------------------------------
 *
 *   agent load      --------------------->   Agent_OnAttach
 *                                              connect to the control socket
 *                   <--- HELLO -----------     send JVM version
 *                   ---- RING + memfd --->     map the ring
 *                                              define TetragonHook class
 *                                              enable class load hook
 *                                              start control thread
 *
 *   policy add      ---- HOOK_ADD ------->   handle_command
 *                                              store the hook
 *                   <--- ACK -------------
 *
 *   policy commit   ---- POLICY_COMMIT -->   handle_command
 *                                              activate policy hooks
 *                                              rewrite matching classes
 *                   <=== METHOD_DEF ======     describe each hooked method
 *                   <--- ACK -------------
 *
 *   method call                              hook_enter
 *                   <=== METHOD_ENTRY ====     report hooked method call
 *
 *   class load                               class_file_load_hook
 *                                              rewrite the class if it matches
 *                   <=== METHOD_DEF ======     describe each hooked method
 *
 *   policy remove   ---- POLICY_REMOVE -->   handle_command
 *                                              deactivate policy hooks
 *                                              restore matching classes
 *                                              free policy hooks
 *                   <--- ACK -------------
 *
 *   Tetragon exit   ---- socket closed -->   cleanup_control_session
 *                                              restore all classes
 *                                              free all hooks
 *                                              unmap the ring
 *
 *   Tetragon start                           session_open
 *                                              connect to the control socket
 *                   <--- HELLO -----------     send JVM version
 *                   ---- RING + memfd --->     map the ring
 *
 *   --->  message on the control socket
 *   ===>  record in the ring
 *
 * transform_class puts TetragonHook.enter(key) call at the entry of each
 * hooked method, hook_enter is the native implementation of that call.
 * The class is always rewritten from its original bytes, so without
 * hooks it gets back to its original form.
 */

#define _GNU_SOURCE
#include <jni.h>
#include <jvmti.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "proto.h"
#include "tetragonhook.h"

#ifndef __maybe_unused
#define __maybe_unused __attribute__((__unused__))
#endif

#define MAX_HOOKS	1024
#define MAX_METHODS	65536
#define MAX_CLASS_NAME	4096

/*
 * Hook received from Tetragon (TG_MSG_HOOK_ADD), selects a class or all
 * classes under a package prefix and optionally their methods. The hook
 * takes effect once its policy is committed.
 */
struct hook {
	uint32_t policy_id;
	uint32_t hook_id;
	uint8_t kind;
	char *class_name;
	uint16_t nr_methods;

	struct {
		char *name;
		char *descriptor;
	} *methods;

	int committed;
	struct hook *next;
};

/*
 * Instrumented method of one hook. The key identifies the method in ring
 * records, it is unique and never reused.
 */
struct method_match {
	uint64_t key;
	uint32_t policy_id;
	uint32_t hook_id;
	char *class_name;
	char *name;
	char *descriptor;
	int defined;
	struct method_match *next;
};

/*
 * The JVM we are loaded in and our JVMTI environment, the handle for all
 * JVMTI calls. Both are set by Agent_OnAttach when it sets up the agent
 * and are not released.
 */
static JavaVM *g_vm;
static jvmtiEnv *g_jvmti;

/*
 * Control session state, set up by session_open and released by
 * cleanup_control_session.
 */

/* Control socket connected to Tetragon, -1 without a session. */
static int g_sock = -1;

/* The ring memfd received from Tetragon, -1 without a session. */
static int g_ring_fd = -1;

/* Mapping of the ring memfd and its length, MAP_FAILED without a session. */
static void *g_ring_map = MAP_FAILED;
static size_t g_ring_len;

/*
 * The ring header at the start of the mapping, the data area follows it.
 * It is NULL without a session and ring_write drops all records then.
 */
static struct tg_ring_hdr *g_ring;

/* Protects hooks, methods and the control session (socket and ring) state. */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* Serializes ring producers, taken inside g_lock. */
static pthread_mutex_t g_ring_lock = PTHREAD_MUTEX_INITIALIZER;

/* Hooks received from Tetragon in this session, both committed and not. */
static struct hook *g_hooks;

/*
 * Methods instrumented in this session, new ones are added to the head.
 * hook_enter looks up the method by its key in here.
 */
static struct method_match *g_methods;

/*
 * Key for the next method match. It is not reset with new session, so
 * the key stays unique for the whole JVM life.
 */
static uint64_t g_next_key = 1;

/* Reconnect delay in seconds, doubled after each failed attempt. */
#define RECONNECT_DELAY_MIN	1
#define RECONNECT_DELAY_MAX	5

/*
 * Tetragon's control socket path the control thread reconnects to. It is
 * updated by each Agent_OnAttach, protected by g_lock.
 */
static char g_path[sizeof(((struct sockaddr_un *)0)->sun_path)];

/*
 * Set once the agent is set up and its control thread runs, following
 * Agent_OnAttach calls only update g_path. Protected by g_lock.
 */
static int g_initialized;

/*
 * Agent_OnAttach sets g_wake and signals g_wake_cond to ask the control
 * thread to reconnect now instead of waiting for the reconnect delay.
 * Both are used with g_lock, the condition is initialized in Agent_OnAttach
 * to use the monotonic clock.
 */
static int g_wake;
static pthread_cond_t g_wake_cond;

/* Control messages and ring records are little-endian. */
static uint16_t rd16(const unsigned char *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t rd32(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

/* Decode u64 in the shared little-endian protocol. */
static uint64_t rd64(const unsigned char *p)
{
	uint64_t v = 0;
	int i;

	for (i = 0; i < 8; i++)
		v |= (uint64_t)p[i] << (i * 8);
	return v;
}

static void wr16(unsigned char *p, uint16_t v)
{
	p[0] = (unsigned char)v;
	p[1] = (unsigned char)(v >> 8);
}

static void wr32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)v;
	p[1] = (unsigned char)(v >> 8);
	p[2] = (unsigned char)(v >> 16);
	p[3] = (unsigned char)(v >> 24);
}

static void wr64(unsigned char *p, uint64_t v)
{
	int i;

	for (i = 0; i < 8; i++)
		p[i] = (unsigned char)(v >> (i * 8));
}

/* Send one control message, struct tg_msg_hdr followed by the payload. */
static int send_packet(uint16_t type, uint32_t seq, const void *payload,
		       size_t len)
{
	unsigned char *buf;
	ssize_t n;

	buf = calloc(1, sizeof(struct tg_msg_hdr) + len);
	if (!buf)
		return -1;
	wr16(buf, type);
	wr16(buf + 2, 0);
	wr32(buf + 4, seq);
	if (len)
		memcpy(buf + 8, payload, len);
	n = send(g_sock, buf, 8 + len, MSG_NOSIGNAL);
	free(buf);
	return n == (ssize_t)(8 + len) ? 0 : -1;
}

/*
 * Receive one control message. The file descriptor passed along with
 * SCM_RIGHTS is stored in passed_fd, -1 if there is none.
 */
static int receive_packet(unsigned char *buf, size_t cap, size_t *len,
			  int *passed_fd)
{
	unsigned char control[CMSG_SPACE(sizeof(int))];
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = cap,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct cmsghdr *c;
	ssize_t n;

	n = recvmsg(g_sock, &msg, 0);
	/* The message must have at least the header and must not be truncated. */
	if (n < 8 || (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)))
		return -1;

	*len = (size_t)n;
	*passed_fd = -1;
	for (c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
		if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
		    c->cmsg_len >= CMSG_LEN(sizeof(int))) {
			memcpy(passed_fd, CMSG_DATA(c), sizeof(int));
			break;
		}
	}

	return 0;
}

/* Wake up the consumer if it sleeps on the notify futex. */
static void ring_notify(void)
{
	/* Skip the syscall when the consumer does not wait. */
	if (!atomic_load_explicit((_Atomic uint32_t *)&g_ring->consumer_waiting,
				  memory_order_relaxed))
		return;
	atomic_fetch_add_explicit((_Atomic uint32_t *)&g_ring->notify, 1,
				  memory_order_release);
	syscall(SYS_futex, &g_ring->notify, FUTEX_WAKE, 1, NULL, NULL, 0);
}

/*
 * Write one record to the ring. The record is visible to the consumer once
 * its length is stored in the record header, producer_pos is moved after
 * that. When the ring is full the record is dropped and accounted in the
 * ring header.
 */
static int ring_write(uint32_t type, const void *payload, uint32_t payload_len)
{
	uint64_t data_size, prod, cons, off, tail, need;
	struct tg_rec_hdr *hdr, *pad;
	unsigned char *area;
	uint32_t length;

	if (!g_ring)
		return -1;
	data_size = g_ring->data_size;

	/* Record length with the header, aligned to TG_REC_ALIGN. */
	length = (uint32_t)((sizeof(struct tg_rec_hdr) + payload_len +
			     TG_REC_ALIGN - 1) &
			    ~(TG_REC_ALIGN - 1));
	if (length > data_size)
		return -1;

	pthread_mutex_lock(&g_ring_lock);
	prod = atomic_load_explicit((_Atomic uint64_t *)&g_ring->producer_pos,
				    memory_order_relaxed);
	cons = atomic_load_explicit((_Atomic uint64_t *)&g_ring->consumer_pos,
				    memory_order_acquire);

	off = prod & (data_size - 1);
	tail = data_size - off;
	need = length + (tail < length ? tail : 0);

	/* No room for the record (and the padding in front of it). */
	if (prod - cons + need > data_size) {
		if (type == TG_REC_METHOD_ENTRY)
			atomic_fetch_add(&g_ring->dropped, 1);
		else if (type == TG_REC_METHOD_DEF)
			atomic_fetch_add(&g_ring->dropped_defs, 1);
		pthread_mutex_unlock(&g_ring_lock);
		return -1;
	}

	area = (unsigned char *)g_ring_map + TG_RING_HDR_SIZE;
	/*
	 * The record does not fit before the end of the data area, fill the
	 * rest with padding record and start from the beginning.
	 */
	if (tail < length) {
		pad = (struct tg_rec_hdr *)(area + off);
		pad->len = 0;
		pad->type = TG_REC_PAD;
		memset((unsigned char *)pad + sizeof(*pad), 0,
		       tail - sizeof(*pad));
		atomic_store_explicit((_Atomic uint32_t *)&pad->len,
				      (uint32_t)tail, memory_order_release);
		prod += tail;
		off = 0;
	}

	hdr = (struct tg_rec_hdr *)(area + off);
	/* Zero length marks the record as not committed. */
	hdr->len = 0;
	hdr->type = type;
	if (payload_len)
		memcpy((unsigned char *)hdr + sizeof(*hdr), payload,
		       payload_len);

	/* Zero the alignment padding behind the payload. */
	memset((unsigned char *)hdr + sizeof(*hdr) + payload_len, 0,
	       length - sizeof(*hdr) - payload_len);

	/* Commit the record and publish new producer position. */
	atomic_store_explicit((_Atomic uint32_t *)&hdr->len, length,
			      memory_order_release);
	atomic_store_explicit((_Atomic uint64_t *)&g_ring->producer_pos,
			      prod + length, memory_order_release);
	pthread_mutex_unlock(&g_ring_lock);

	ring_notify();
	return 0;
}

/*
 * Emit TG_REC_METHOD_DEF record that describes the method key:
 * u64 key, u32 policy_id, u32 hook_id, u16 class_len, u16 name_len,
 * u16 desc_len, u16 pad, followed by class, name and descriptor.
 */
static int emit_def(struct method_match *m)
{
	size_t cl = strlen(m->class_name);
	size_t nl = strlen(m->name);
	size_t dl = strlen(m->descriptor);
	unsigned char *p;
	int rc;

	if (cl > 65535 || nl > 65535 || dl > 65535)
		return -1;
	p = calloc(1, 24 + cl + nl + dl);
	if (!p)
		return -1;

	wr64(p, m->key);
	wr32(p + 8, m->policy_id);
	wr32(p + 12, m->hook_id);
	wr16(p + 16, (uint16_t)cl);
	wr16(p + 18, (uint16_t)nl);
	wr16(p + 20, (uint16_t)dl);
	memcpy(p + 24, m->class_name, cl);
	memcpy(p + 24 + cl, m->name, nl);
	memcpy(p + 24 + cl + nl, m->descriptor, dl);

	rc = ring_write(TG_REC_METHOD_DEF, p, (uint32_t)(24 + cl + nl + dl));
	free(p);
	return rc;
}

static int eq(const char *a, const char *b)
{
	return a && b && strcmp(a, b) == 0;
}

/*
 * Hook without methods matches all methods of the class, method without
 * descriptor matches all its overloads.
 */
static int method_allowed(struct hook *h, const char *name, const char *desc)
{
	uint16_t i;

	if (h->nr_methods == 0)
		return 1;
	for (i = 0; i < h->nr_methods; i++) {
		if (eq(h->methods[i].name, name) &&
		    (!h->methods[i].descriptor[0] ||
		     eq(h->methods[i].descriptor, desc)))
			return 1;
	}

	return 0;
}

/* Class names are in JVM internal form (a/b/C), prefix hook matches a/b/. */
static int class_allowed(struct hook *h, const char *name)
{
	size_t n;

	if (h->kind == TG_HOOK_CLASS)
		return eq(h->class_name, name);
	n = strlen(h->class_name);
	return strncmp(h->class_name, name, n) == 0;
}

static struct method_match *find_method(const char *class_name,
					const char *name, const char *desc,
					uint32_t policy_id, uint32_t hook_id)
{
	struct method_match *m;

	for (m = g_methods; m; m = m->next) {
		if (m->policy_id == policy_id && m->hook_id == hook_id &&
		    eq(m->class_name, class_name) && eq(m->name, name) &&
		    eq(m->descriptor, desc))
			return m;
	}

	return NULL;
}

/*
 * Get the match for the method and hook, new one is added with fresh key
 * if it does not exist yet.
 */
static struct method_match *add_method(const char *class_name,
				       const char *name, const char *desc,
				       uint32_t policy_id, uint32_t hook_id)
{
	struct method_match *m;

	m = find_method(class_name, name, desc, policy_id, hook_id);
	if (m)
		return m;

	m = calloc(1, sizeof(*m));
	if (!m)
		return NULL;

	m->key = g_next_key++;
	m->policy_id = policy_id;
	m->hook_id = hook_id;
	m->class_name = strdup(class_name);
	m->name = strdup(name);
	m->descriptor = strdup(desc);
	if (!m->class_name || !m->name || !m->descriptor) {
		free(m->class_name);
		free(m->name);
		free(m->descriptor);
		free(m);
		return NULL;
	}

	m->next = g_methods;
	g_methods = m;
	return m;
}

/*
 * Read u16 length prefixed string at offset off, returns allocated zero
 * terminated copy and moves off behind the string.
 */
static char *get_string(const unsigned char *p, size_t len, size_t *off)
{
	uint16_t n;
	char *s;

	if (*off + 2 > len)
		return NULL;

	n = rd16(p + *off);
	*off += 2;
	if (n > len - *off)
		return NULL;

	s = calloc(1, (size_t)n + 1);
	if (!s)
		return NULL;
	memcpy(s, p + *off, n);
	*off += n;
	return s;
}

static void free_hook(struct hook *h)
{
	uint16_t i;

	if (!h)
		return;
	free(h->class_name);
	for (i = 0; i < h->nr_methods; i++) {
		free(h->methods[i].name);
		free(h->methods[i].descriptor);
	}

	free(h->methods);
	free(h);
}

/*
 * Parse TG_MSG_HOOK_ADD payload: u32 policy_id, u32 hook_id, u8 kind,
 * u8 pad, u16 nr_methods, class name and name plus descriptor string for
 * each method.
 */
static struct hook *parse_hook(const unsigned char *p, size_t len)
{
	size_t off = 12;
	struct hook *h;
	uint16_t i;

	if (len < 14)
		return NULL;

	h = calloc(1, sizeof(*h));
	if (!h)
		return NULL;

	h->policy_id = rd32(p);
	h->hook_id = rd32(p + 4);
	h->kind = p[8];
	h->nr_methods = rd16(p + 10);
	if (h->kind != TG_HOOK_CLASS && h->kind != TG_HOOK_PREFIX)
		goto fail;

	h->class_name = get_string(p, len, &off);
	if (!h->class_name)
		goto fail;

	if (h->nr_methods) {
		h->methods = calloc(h->nr_methods, sizeof(*h->methods));
		if (!h->methods)
			goto fail;
	}

	for (i = 0; i < h->nr_methods; i++) {
		h->methods[i].name = get_string(p, len, &off);
		h->methods[i].descriptor = get_string(p, len, &off);
		if (!h->methods[i].name || !h->methods[i].descriptor)
			goto fail;
	}

	/* No trailing data is allowed. */
	if (off != len)
		goto fail;
	return h;

fail:
	free_hook(h);
	return NULL;
}

/*
 * Class file rewriter.
 *
 * The class file is big-endian, see the JVM specification chapter 4 for
 * its format.
 */

/* Growable output buffer. */
struct buffer {
	unsigned char *p;
	size_t n;
	size_t cap;
};

/* Constant pool entry, bytes and len are set only for CONSTANT_Utf8. */
struct cp_entry {
	uint8_t tag;
	const unsigned char *bytes;
	uint16_t len;
};

/*
 * One TetragonHook.enter call to inject, long_index is the constant pool
 * index of the method key.
 */
struct call_plan {
	struct method_match *match;
	uint16_t long_index;
	struct call_plan *next;
};

/* Calls to inject into one method of the class. */
struct method_plan {
	uint16_t name_index;
	uint16_t desc_index;
	struct call_plan *calls;
	size_t count;
};

static uint16_t be16(const unsigned char *p)
{
	return ((uint16_t)p[0] << 8) | p[1];
}

static uint32_t be32(const unsigned char *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | p[3];
}

static void put_be16(unsigned char *p, uint16_t v)
{
	p[0] = (unsigned char)(v >> 8);
	p[1] = (unsigned char)v;
}

static void put_be32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)(v >> 24);
	p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);
	p[3] = (unsigned char)v;
}

/* Append n bytes to the buffer, returns -1 when it can not grow. */
static int append(struct buffer *b, const void *p, size_t n)
{
	unsigned char *q;
	size_t cap;

	if (n > SIZE_MAX - b->n)
		return -1;
	if (b->n + n > b->cap) {
		/* Double the capacity until the data fits. */
		cap = b->cap ? b->cap : 256;
		while (cap < b->n + n) {
			if (cap > SIZE_MAX / 2)
				return -1;
			cap *= 2;
		}

		q = realloc(b->p, cap);
		if (!q)
			return -1;
		b->p = q;
		b->cap = cap;
	}

	memcpy(b->p + b->n, p, n);
	b->n += n;
	return 0;
}

static int append_u2(struct buffer *b, uint16_t v)
{
	unsigned char p[2];

	put_be16(p, v);
	return append(b, p, 2);
}

static int append_u4(struct buffer *b, uint32_t v)
{
	unsigned char p[4];

	put_be32(p, v);
	return append(b, p, 4);
}

/* Check that n bytes at offset off fit into total bytes. */
static int bounds(size_t off, size_t n, size_t total)
{
	return off <= total && n <= total - off;
}

/* Returns allocated copy of CONSTANT_Utf8 entry, NULL for other entries. */
static char *cp_string(struct cp_entry *cp, uint16_t idx)
{
	char *s;

	if (!cp[idx].tag || cp[idx].tag != 1)
		return NULL;
	s = calloc(1, (size_t)cp[idx].len + 1);
	if (!s)
		return NULL;
	memcpy(s, cp[idx].bytes, cp[idx].len);
	return s;
}

/*
 * Skip field_info: u2 access_flags, u2 name_index, u2 descriptor_index,
 * u2 attributes_count and the attributes.
 */
static int skip_member(const unsigned char *d, size_t len, size_t *off)
{
	uint16_t attrs, i;
	uint32_t n;

	if (!bounds(*off, 8, len))
		return -1;
	attrs = be16(d + *off + 6);
	*off += 8;
	for (i = 0; i < attrs; i++) {
		if (!bounds(*off, 6, len))
			return -1;
		n = be32(d + *off + 2);
		*off += 6;
		if (!bounds(*off, n, len))
			return -1;
		*off += n;
	}

	return 0;
}

/*
 * Walk the instructions and check they all stay within the code, returns
 * 1 if they do. The code is not changed, only moved by the prefix, so all
 * we need to know is the instruction length.
 */
static int safe_bytecode(const unsigned char *code, uint32_t len)
{
	uint32_t pc = 0, n, pad, base;
	int32_t low, high, pairs;
	uint64_t entries, size;
	uint8_t op;

	while (pc < len) {
		op = code[pc];
		n = 1;

		/*
		 * tableswitch (0xaa) and lookupswitch (0xab) are padded so their
		 * operands start at 4 bytes boundary from the code start.
		 */
		if (op == 0xaa || op == 0xab) {
			pad = (4 - ((pc + 1) & 3)) & 3;
			base = pc + 1 + pad;
			if (!bounds(base, op == 0xaa ? 12 : 8, len))
				return 0;
			if (op == 0xaa) {
				/* u4 default, u4 low, u4 high and high - low + 1 jump offsets */
				low = (int32_t)be32(code + base + 4);
				high = (int32_t)be32(code + base + 8);
				if (high < low)
					return 0;
				entries = (uint64_t)((int64_t)high - low + 1);
				size = 1 + pad + 12 + entries * 4;
				if (size > UINT32_MAX)
					return 0;
				n = (uint32_t)size;
			} else {
				/* u4 default, u4 npairs and npairs pairs of u4 match and offset */
				pairs = (int32_t)be32(code + base + 4);
				if (pairs < 0)
					return 0;
				size = 1 + pad + 8 + (uint64_t)pairs * 8;
				if (size > UINT32_MAX)
					return 0;
				n = (uint32_t)size;
			}
		}

		/*
		 * Instructions with operands, the rest is single byte:
		 *   2 bytes: bipush, ldc, iload..aload, istore..astore, ret,
		 *            newarray
		 *   3 bytes: sipush, ldc_w, ldc2_w, ifeq..jsr, iinc,
		 *            getstatic..invokestatic, new..instanceof (0xbb..0xc1),
		 *            ifnull, ifnonnull
		 *   5 bytes: invokeinterface, invokedynamic, goto_w, jsr_w
		 *   4 bytes: multianewarray
		 *   wide (0xc4): 6 bytes for iinc, 4 bytes otherwise
		 */
		if (op == 0x10 || op == 0x12 || op == 0x15 || op == 0x16 ||
		    op == 0x17 || op == 0x18 || op == 0x19 || op == 0x36 ||
		    op == 0x37 || op == 0x38 || op == 0x39 || op == 0x3a ||
		    op == 0xa9 || op == 0xbc) {
			n = 2;
		} else if (op == 0x11 || op == 0x13 || op == 0x14 ||
			   (op >= 0x99 && op <= 0xa8) || op == 0x84 ||
			   (op >= 0xb2 && op <= 0xb8) ||
			   (op >= 0xbb && op <= 0xc1) || op == 0xc6 ||
			   op == 0xc7) {
			n = 3;
		} else if (op == 0xb9 || op == 0xba) {
			n = 5;
		} else if (op == 0xc5) {
			n = 4;
		} else if (op == 0xc8 || op == 0xc9) {
			n = 5;
		} else if (op == 0xc4) {
			if (pc + 1 >= len)
				return 0;
			n = code[pc + 1] == 0x84 ? 6 : 4;
		}

		if (!bounds(pc, n, len))
			return 0;
		pc += n;
	}

	return 1;
}

/*
 * Copy verification_type_info. Object (7) carries constant pool index,
 * Uninitialized (8) carries offset of the new instruction, which moves by
 * the prefix.
 */
static int copy_verification_type(const unsigned char *src, size_t len,
				  size_t *off, uint32_t prefix,
				  struct buffer *out)
{
	uint16_t pc;
	uint8_t tag;

	if (!bounds(*off, 1, len))
		return -1;

	tag = src[(*off)++];
	append(out, &tag, 1);

	if (tag == 7) {
		if (!bounds(*off, 2, len))
			return -1;
		append(out, src + *off, 2);
		*off += 2;
	} else if (tag == 8) {
		if (!bounds(*off, 2, len))
			return -1;
		pc = be16(src + *off);
		if (pc + prefix > 65535)
			return -1;
		append_u2(out, (uint16_t)(pc + prefix));
		*off += 2;
	} else if (tag > 8) {
		return -1;
	}

	return 0;
}

static int copy_element_value(const unsigned char *src, size_t len, size_t *off,
			      struct buffer *out);

/*
 * Copy annotation: u2 type_index, u2 num_element_value_pairs and the
 * pairs of u2 element_name_index and element_value.
 */
static int copy_annotation(const unsigned char *src, size_t len, size_t *off,
			   struct buffer *out)
{
	uint16_t pairs, i;

	if (!bounds(*off, 4, len))
		return -1;
	append(out, src + *off, 4);
	pairs = be16(src + *off + 2);
	*off += 4;
	for (i = 0; i < pairs; i++) {
		if (!bounds(*off, 2, len))
			return -1;
		append(out, src + *off, 2);
		*off += 2;
		if (copy_element_value(src, len, off, out))
			return -1;
	}

	return 0;
}

static int copy_element_value(const unsigned char *src, size_t len, size_t *off,
			      struct buffer *out)
{
	uint16_t n, i;
	uint8_t tag;

	if (!bounds(*off, 1, len))
		return -1;
	tag = src[*off];
	append(out, src + *off, 1);
	(*off)++;

	/* const_value_index for primitive types and String */
	if (strchr("BCDFIJSZs", tag)) {
		if (!bounds(*off, 2, len))
			return -1;
		append(out, src + *off, 2);
		*off += 2;
		return 0;
	}

	/* enum: type_name_index and const_name_index */
	if (tag == 'e') {
		if (!bounds(*off, 4, len))
			return -1;
		append(out, src + *off, 4);
		*off += 4;
		return 0;
	}

	/* class: class_info_index */
	if (tag == 'c') {
		if (!bounds(*off, 2, len))
			return -1;
		append(out, src + *off, 2);
		*off += 2;
		return 0;
	}

	/* nested annotation */
	if (tag == '@')
		return copy_annotation(src, len, off, out);

	/* array: num_values and the values */
	if (tag == '[') {
		if (!bounds(*off, 2, len))
			return -1;
		n = be16(src + *off);
		append(out, src + *off, 2);
		*off += 2;
		for (i = 0; i < n; i++) {
			if (copy_element_value(src, len, off, out))
				return -1;
		}

		return 0;
	}

	return -1;
}

/*
 * Rewrite Runtime(In)VisibleTypeAnnotations of the Code attribute, shift
 * bytecode offsets in the annotation targets by the prefix:
 *   0x40-0x41 localvar_target, table of start_pc, length, index
 *   0x42      catch_target, exception table index (no offset)
 *   0x43-0x46 offset_target
 *   0x47-0x4b type_argument_target, offset and type argument index
 */
static int transform_type_annotations(const unsigned char *src, uint32_t len,
				      uint32_t prefix, struct buffer *out)
{
	uint16_t count, n, pc, i, j;
	uint8_t target, path_len;
	size_t path_bytes;
	size_t off = 2;

	if (len < 2)
		return -1;

	count = be16(src);
	append_u2(out, count);
	for (i = 0; i < count; i++) {
		if (!bounds(off, 1, len))
			return -1;

		target = src[off++];
		append(out, &target, 1);

		if (target == 0x40 || target == 0x41) {
			if (!bounds(off, 2, len))
				return -1;
			n = be16(src + off);
			append_u2(out, n);
			off += 2;
			for (j = 0; j < n; j++) {
				if (!bounds(off, 6, len))
					return -1;
				pc = be16(src + off);
				if (pc + prefix > 65535)
					return -1;
				append_u2(out, (uint16_t)(pc + prefix));
				append(out, src + off + 2, 4);
				off += 6;
			}
		} else if (target == 0x42) {
			if (!bounds(off, 2, len))
				return -1;
			append(out, src + off, 2);
			off += 2;
		} else if (target >= 0x43 && target <= 0x46) {
			if (!bounds(off, 2, len))
				return -1;
			pc = be16(src + off);
			if (pc + prefix > 65535)
				return -1;
			append_u2(out, (uint16_t)(pc + prefix));
			off += 2;
		} else if (target >= 0x47 && target <= 0x4b) {
			if (!bounds(off, 3, len))
				return -1;
			pc = be16(src + off);
			if (pc + prefix > 65535)
				return -1;
			append_u2(out, (uint16_t)(pc + prefix));
			append(out, src + off + 2, 1);
			off += 3;
		} else {
			return -1;
		}

		if (!bounds(off, 1, len))
			return -1;

		/*
		 * type_path, u1 path_length and path_length pairs of u1 kind
		 * and u1 argument index, followed by the annotation itself.
		 */
		path_len = src[off];
		path_bytes = 1 + (size_t)path_len * 2;
		if (!bounds(off, path_bytes, len))
			return -1;
		append(out, src + off, path_bytes);
		off += path_bytes;
		if (copy_annotation(src, len, &off, out))
			return -1;
	}

	return off == len ? 0 : -1;
}

/*
 * Rewrite StackMapTable. Each frame stores offset delta from the previous
 * frame, so only the first frame moves by the prefix. The frame is changed
 * to its extended form when the new delta does not fit into the frame type.
 */
static int transform_stackmap(const unsigned char *src, uint32_t len,
			      uint32_t prefix, struct buffer *out)
{
	uint16_t count, delta, locals, stack, i, j;
	uint32_t shift, d;
	size_t off = 2;
	uint8_t ft, b, k;
	int compact;

	if (len < 2)
		return -1;

	count = be16(src);
	append_u2(out, count);
	for (i = 0; i < count; i++) {
		if (!bounds(off, 1, len))
			return -1;

		ft = src[off++];

		/* Only the first frame has absolute offset. */
		shift = i == 0 ? prefix : 0;

		/* same_frame, changed to same_frame_extended (251) if needed */
		if (ft <= 63) {
			d = (uint32_t)ft + shift;
			if (d > 65535)
				return -1;
			if (d <= 63) {
				b = (uint8_t)d;
				append(out, &b, 1);
			} else {
				b = 251;
				append(out, &b, 1);
				append_u2(out, (uint16_t)d);
			}
			continue;
		}

		/*
		 * same_locals_1_stack_item_frame and its extended form (247),
		 * followed by one verification type
		 */
		if (ft <= 127 || ft == 247) {
			compact = ft <= 127;
			if (compact) {
				delta = (uint16_t)(ft - 64);
			} else {
				if (!bounds(off, 2, len))
					return -1;
				delta = be16(src + off);
				off += 2;
			}

			d = (uint32_t)delta + shift;
			if (d > 65535)
				return -1;

			/* Keep the compact form only if the new delta fits in. */
			if (compact && d <= 63) {
				b = (uint8_t)(64 + d);
				append(out, &b, 1);
			} else {
				b = 247;
				append(out, &b, 1);
				append_u2(out, (uint16_t)d);
			}

			if (copy_verification_type(src, len, &off, prefix, out))
				return -1;
			continue;
		}

		/* chop_frame and same_frame_extended */
		if (ft >= 248 && ft <= 251) {
			if (!bounds(off, 2, len))
				return -1;
			delta = be16(src + off);
			off += 2;
			d = (uint32_t)delta + shift;
			if (d > 65535)
				return -1;
			append(out, &ft, 1);
			append_u2(out, (uint16_t)d);
			continue;
		}

		/* append_frame, followed by ft - 251 verification types */
		if (ft >= 252 && ft <= 254) {
			if (!bounds(off, 2, len))
				return -1;
			delta = be16(src + off);
			off += 2;
			d = (uint32_t)delta + shift;
			if (d > 65535)
				return -1;
			append(out, &ft, 1);
			append_u2(out, (uint16_t)d);
			for (k = 0; k < (uint8_t)(ft - 251); k++) {
				if (copy_verification_type(src, len, &off,
							   prefix, out))
					return -1;
			}
			continue;
		}

		/* full_frame, followed by locals and stack verification types */
		if (ft == 255) {
			if (!bounds(off, 2, len))
				return -1;
			delta = be16(src + off);
			off += 2;
			d = (uint32_t)delta + shift;
			if (d > 65535)
				return -1;
			append(out, &ft, 1);
			append_u2(out, (uint16_t)d);
			if (!bounds(off, 2, len))
				return -1;
			locals = be16(src + off);
			off += 2;
			append_u2(out, locals);
			for (j = 0; j < locals; j++) {
				if (copy_verification_type(src, len, &off,
							   prefix, out))
					return -1;
			}

			if (!bounds(off, 2, len))
				return -1;
			stack = be16(src + off);
			off += 2;
			append_u2(out, stack);
			for (j = 0; j < stack; j++) {
				if (copy_verification_type(src, len, &off,
							   prefix, out))
					return -1;
			}
			continue;
		}

		return -1;
	}

	return off == len ? 0 : -1;
}

/*
 * Rewrite Code attribute, put prefix in front of the bytecode and shift
 * all absolute bytecode offsets by prefix_len. Branch offsets are relative,
 * so the original bytecode is copied unchanged.
 *
 *   u2 max_stack, u2 max_locals, u4 code_length, code,
 *   u2 exception_table_length, exception table,
 *   u2 attributes_count, attributes
 *
 * Returns 1 on success, 0 if the attribute can not be safely rewritten.
 */
static int transform_code(const unsigned char *src, uint32_t src_len,
			  const unsigned char *prefix, uint32_t prefix_len,
			  struct cp_entry *cp, struct buffer *out)
{
	const unsigned char *code, *exception_table;
	uint16_t max_stack, max_locals, exceptions, attrs, i;
	struct buffer nested = {0};
	uint32_t code_len;
	size_t off = 8;

	if (src_len < 12)
		return 0;

	max_stack = be16(src);
	max_locals = be16(src + 2);
	code_len = be32(src + 4);

	/* The code with the prefix must fit into the 64K method code limit. */
	if (!bounds(off, code_len + 2, src_len) ||
	    code_len + prefix_len > 65535)
		return 0;

	code = src + off;
	if (!safe_bytecode(code, code_len))
		return 0;
	off += code_len;

	exceptions = be16(src + off);
	off += 2;
	if (!bounds(off, (size_t)exceptions * 8 + 2, src_len))
		return 0;

	exception_table = src + off;
	off += (size_t)exceptions * 8;

	/*
	 * Nested attributes with bytecode offsets are rewritten into nested
	 * buffer, unknown attribute fails the transformation.
	 */
	attrs = be16(src + off);
	off += 2;
	for (i = 0; i < attrs; i++) {
		uint16_t name_idx, count, x;
		char *name;
		uint32_t n;

		if (!bounds(off, 6, src_len))
			goto fail;
		name_idx = be16(src + off);
		n = be32(src + off + 2);
		off += 6;
		if (!bounds(off, n, src_len))
			goto fail;
		name = cp_string(cp, name_idx);
		if (!name)
			goto fail;
		if (!strcmp(name, "LineNumberTable")) {
			struct buffer a = {0};

			if (n < 2) {
				free(name);
				goto fail;
			}

			count = be16(src + off);
			/* entries of u2 start_pc, u2 line_number */
			if (n != 2 + (uint32_t)count * 4) {
				free(name);
				goto fail;
			}

			append_u2(&a, count);
			for (x = 0; x < count; x++) {
				uint16_t pc = be16(src + off + 2 + x * 4);

				if (pc + prefix_len > 65535) {
					free(a.p);
					free(name);
					goto fail;
				}

				append_u2(&a, (uint16_t)(pc + prefix_len));
				append(&a, src + off + 4 + x * 4, 2);
			}

			append_u2(&nested, name_idx);
			append_u4(&nested, (uint32_t)a.n);
			append(&nested, a.p, a.n);
			free(a.p);
		} else if (!strcmp(name, "LocalVariableTable") ||
			   !strcmp(name, "LocalVariableTypeTable")) {
			struct buffer a = {0};

			if (n < 2) {
				free(name);
				goto fail;
			}

			count = be16(src + off);
			/*
			 * entries of u2 start_pc, u2 length, u2 name_index,
			 * u2 descriptor_index (or signature_index), u2 index
			 */
			if (n != 2 + (uint32_t)count * 10) {
				free(name);
				goto fail;
			}

			append_u2(&a, count);
			for (x = 0; x < count; x++) {
				uint16_t pc = be16(src + off + 2 + x * 10);

				if (pc + prefix_len > 65535) {
					free(a.p);
					free(name);
					goto fail;
				}

				append_u2(&a, (uint16_t)(pc + prefix_len));
				append(&a, src + off + 4 + x * 10, 8);
			}

			append_u2(&nested, name_idx);
			append_u4(&nested, (uint32_t)a.n);
			append(&nested, a.p, a.n);
			free(a.p);
		} else if (!strcmp(name, "StackMapTable")) {
			struct buffer a = {0};

			if (transform_stackmap(src + off, n, prefix_len, &a)) {
				free(a.p);
				free(name);
				goto fail;
			}

			append_u2(&nested, name_idx);
			append_u4(&nested, (uint32_t)a.n);
			append(&nested, a.p, a.n);
			free(a.p);
		} else if (!strcmp(name, "RuntimeVisibleTypeAnnotations") ||
			   !strcmp(name, "RuntimeInvisibleTypeAnnotations")) {
			struct buffer a = {0};

			if (transform_type_annotations(src + off, n, prefix_len,
						       &a)) {
				free(a.p);
				free(name);
				goto fail;
			}

			append_u2(&nested, name_idx);
			append_u4(&nested, (uint32_t)a.n);
			append(&nested, a.p, a.n);
			free(a.p);
		} else if (!strcmp(name, "CharacterRangeTable")) {
			struct buffer a = {0};

			if (n < 2) {
				free(name);
				goto fail;
			}

			count = be16(src + off);
			/*
			 * entries of u2 start_pc, u2 end_pc, u4 character_range_start,
			 * u4 character_range_end, u2 flags
			 */
			if (n != 2 + (uint32_t)count * 14) {
				free(name);
				goto fail;
			}

			append_u2(&a, count);
			for (x = 0; x < count; x++) {
				const unsigned char *e = src + off + 2 + x * 14;
				uint16_t start = be16(e), end = be16(e + 2);

				if (start + prefix_len > 65535 ||
				    end + prefix_len > 65535) {
					free(a.p);
					free(name);
					goto fail;
				}

				append_u2(&a, (uint16_t)(start + prefix_len));
				append_u2(&a, (uint16_t)(end + prefix_len));
				append(&a, e + 4, 10);
			}

			append_u2(&nested, name_idx);
			append_u4(&nested, (uint32_t)a.n);
			append(&nested, a.p, a.n);
			free(a.p);
		} else {
			free(name);
			goto fail;
		}

		free(name);
		off += n;
	}

	/* The attribute must be fully consumed. */
	if (off != src_len)
		goto fail;

	/* The long key of the injected call takes two stack slots. */
	append_u2(out, max_stack < 2 ? 2 : max_stack);
	append_u2(out, max_locals);
	append_u4(out, code_len + prefix_len);
	append(out, prefix, prefix_len);
	append(out, code, code_len);
	append_u2(out, exceptions);

	/* u2 start_pc, u2 end_pc, u2 handler_pc, u2 catch_type */
	for (i = 0; i < exceptions; i++) {
		const unsigned char *e = exception_table + i * 8;
		uint16_t start = be16(e), end = be16(e + 2);
		uint16_t handler = be16(e + 4);

		if (start + prefix_len > 65535 || end + prefix_len > 65535 ||
		    handler + prefix_len > 65535)
			goto fail;
		append_u2(out, (uint16_t)(start + prefix_len));
		append_u2(out, (uint16_t)(end + prefix_len));
		append_u2(out, (uint16_t)(handler + prefix_len));
		append(out, e + 6, 2);
	}

	append_u2(out, attrs);
	append(out, nested.p, nested.n);
	free(nested.p);
	return 1;

fail:
	free(nested.p);
	return 0;
}

/*
 * Rewrite the class so all its methods matching committed hooks call
 * TetragonHook.enter(key) at entry:
 *   - parse the constant pool and find the methods to instrument
 *   - add constant pool entries for TetragonHook.enter and the method keys
 *   - put the call in front of the bytecode of each matching method
 *   - emit definition of each new method key
 *
 * Returns 1 with the new class in out, 0 if the class stays unchanged.
 *
 * The transformer deliberately declines Code attributes whose verifier or
 * bytecode offsets it cannot safely rewrite; the original class is preserved.
 *
 * Called with g_lock held.
 */
static int transform_class(const char *class_name, const unsigned char *data,
			   size_t len, unsigned char **out, size_t *out_len)
{
	uint16_t class_utf, class_idx, enter_utf, desc_utf, nt_idx, method_idx;
	uint16_t cp_count, interfaces, fields, method_count, i, a;
	size_t cp_end, method_count_off, methods_end;
	struct method_match *old_head, *m;
	uint32_t new_cp_count, next_cp;
	struct buffer cp_extra = {0};
	struct buffer result = {0};
	struct method_plan *plans;
	struct call_plan *c, *next;
	struct cp_entry *cp;
	size_t calls = 0;
	size_t off = 10;
	struct hook *h;

	/* u4 magic, u2 minor_version, u2 major_version, u2 constant_pool_count */
	if (len < 10 || be32(data) != 0xcafebabe)
		return 0;
	cp_count = be16(data + 8);

	/* Full size table, so any u2 index from the class file is safe to use. */
	cp = calloc(65536, sizeof(*cp));
	if (!cp)
		return -1;

	/*
	 * Constant pool, entries are indexed from 1. We only need to skip
	 * them and remember the Utf8 (1) ones:
	 *   3 Integer, 4 Float, 5 Long, 6 Double, 7 Class, 8 String,
	 *   9 Fieldref, 10 Methodref, 11 InterfaceMethodref, 12 NameAndType,
	 *   15 MethodHandle, 16 MethodType, 17 Dynamic, 18 InvokeDynamic,
	 *   19 Module, 20 Package
	 */
	for (i = 1; i < cp_count; i++) {
		size_t n = 0;
		uint8_t tag;

		if (!bounds(off, 1, len))
			goto bad;

		tag = data[off++];
		cp[i].tag = tag;

		switch (tag) {
		case 1:
			if (!bounds(off, 2, len))
				goto bad;
			cp[i].len = be16(data + off);
			off += 2;
			if (!bounds(off, cp[i].len, len))
				goto bad;
			cp[i].bytes = data + off;
			off += cp[i].len;
			continue;
		case 3:
		case 4:
			n = 4;
			break;
		case 5:
		case 6:
			n = 8;
			break;
		case 7:
		case 8:
		case 16:
		case 19:
		case 20:
			n = 2;
			break;
		case 9:
		case 10:
		case 11:
		case 12:
		case 17:
		case 18:
			n = 4;
			break;
		case 15:
			n = 3;
			break;
		default:
			goto bad;
		}

		if (!bounds(off, n, len))
			goto bad;
		off += n;

		/* Long and Double take two constant pool entries. */
		if (tag == 5 || tag == 6)
			i++;
	}

	/* Skip access_flags, this_class, super_class, interfaces and fields. */
	cp_end = off;
	if (!bounds(off, 8, len))
		goto bad;
	off += 6;

	interfaces = be16(data + off);
	off += 2;
	if (!bounds(off, (size_t)interfaces * 2 + 2, len))
		goto bad;
	off += (size_t)interfaces * 2;

	fields = be16(data + off);
	off += 2;
	for (i = 0; i < fields; i++) {
		if (skip_member(data, len, &off))
			goto bad;
	}

	if (!bounds(off, 2, len))
		goto bad;
	method_count_off = off;
	method_count = be16(data + off);
	off += 2;
	plans = calloc(method_count, sizeof(*plans));
	if (!plans)
		goto bad;

	/*
	 * Find methods to instrument. New method matches are added to the head
	 * of g_methods, so they can be dropped if the transformation fails.
	 */
	old_head = g_methods;
	for (i = 0; i < method_count; i++) {
		uint16_t access, name_idx, desc_idx, attrs;
		char *mn, *md;
		uint32_t n;

		if (!bounds(off, 8, len))
			goto plan_bad;

		access = be16(data + off);
		name_idx = be16(data + off + 2);
		desc_idx = be16(data + off + 4);
		attrs = be16(data + off + 6);
		plans[i].name_index = name_idx;
		plans[i].desc_index = desc_idx;

		mn = cp_string(cp, name_idx);
		md = cp_string(cp, desc_idx);
		if (!mn || !md) {
			free(mn);
			free(md);
			goto plan_bad;
		}

		/* Skip class initializer, native (0x0100) and abstract (0x0400) methods. */
		if (strcmp(mn, "<clinit>") && !(access & (0x0100 | 0x0400))) {
			for (h = g_hooks; h; h = h->next) {
				if (!h->committed ||
				    !class_allowed(h, class_name) ||
				    !method_allowed(h, mn, md))
					continue;
				m = add_method(class_name, mn, md, h->policy_id,
					       h->hook_id);
				if (!m) {
					free(mn);
					free(md);
					goto plan_bad;
				}

				c = calloc(1, sizeof(*c));
				if (!c) {
					free(mn);
					free(md);
					goto plan_bad;
				}

				c->match = m;
				c->next = plans[i].calls;
				plans[i].calls = c;
				plans[i].count++;
			}
		}

		free(mn);
		free(md);
		off += 8;
		for (a = 0; a < attrs; a++) {
			if (!bounds(off, 6, len))
				goto plan_bad;
			n = be32(data + off + 2);
			off += 6;
			if (!bounds(off, n, len))
				goto plan_bad;
			off += n;
		}
	}

	methods_end = off;
	if (!bounds(off, 2, len))
		goto plan_bad;
	for (i = 0; i < method_count; i++)
		calls += plans[i].count;

	/* Nothing to instrument in this class. */
	if (calls == 0) {
		free(plans);
		free(cp);
		return 0;
	}

	/*
	 * New constant pool entries are added behind the existing ones, six
	 * for the TetragonHook.enter method and Long (two entries) with the
	 * method key for each call.
	 */
	new_cp_count = (uint32_t)cp_count + 6 + (uint32_t)calls * 2;
	if (new_cp_count > 65535)
		goto plan_bad;

	/*
	 * Utf8 "io/tetragon/TetragonHook", Class, Utf8 "enter", Utf8 "(J)V",
	 * NameAndType (12) and Methodref (10).
	 */
	class_utf = cp_count;
	class_idx = cp_count + 1;
	enter_utf = cp_count + 2;
	desc_utf = cp_count + 3;
	nt_idx = cp_count + 4;
	method_idx = cp_count + 5;
	next_cp = (uint32_t)cp_count + 6;

	append(&cp_extra, "\1", 1);
	append_u2(&cp_extra, 24);
	append(&cp_extra, "io/tetragon/TetragonHook", 24);
	append(&cp_extra, "\7", 1);
	append_u2(&cp_extra, class_utf);
	append(&cp_extra, "\1", 1);
	append_u2(&cp_extra, 5);
	append(&cp_extra, "enter", 5);
	append(&cp_extra, "\1", 1);
	append_u2(&cp_extra, 4);
	append(&cp_extra, "(J)V", 4);
	append(&cp_extra, "\14", 1);
	append_u2(&cp_extra, enter_utf);
	append_u2(&cp_extra, desc_utf);
	append(&cp_extra, "\12", 1);
	append_u2(&cp_extra, class_idx);
	append_u2(&cp_extra, nt_idx);
	for (i = 0; i < method_count; i++) {
		for (c = plans[i].calls; c; c = c->next) {
			unsigned char entry[9] = { 5 };
			uint64_t v = c->match->key;
			int b;

			/* CONSTANT_Long (5) with the method key in big-endian. */
			c->long_index = (uint16_t)next_cp;
			for (b = 0; b < 8; b++)
				entry[8 - b] = (unsigned char)(v >> (8 * b));
			append(&cp_extra, entry, sizeof(entry));
			next_cp += 2;
		}
	}

	/*
	 * Output: header with new constant pool count, constant pool with the
	 * new entries, everything up to methods unchanged and the methods.
	 */
	append(&result, data, 10);
	put_be16(result.p + 8, (uint16_t)new_cp_count);
	append(&result, data + 10, cp_end - 10);
	append(&result, cp_extra.p, cp_extra.n);
	free(cp_extra.p);
	append(&result, data + cp_end, method_count_off + 2 - cp_end);
	off = method_count_off + 2;
	for (i = 0; i < method_count; i++) {
		struct buffer prefix = {0};
		size_t method_start = off;
		uint16_t attrs;

		if (!bounds(off, 8, len))
			goto output_bad;
		attrs = be16(data + off + 6);
		off += 8;
		append(&result, data + method_start, 8);
		for (c = plans[i].calls; c; c = c->next) {
			/* ldc2_w <key>; invokestatic TetragonHook.enter */
			unsigned char seq[6] = { 0x14, 0, 0, 0xb8, 0, 0 };

			put_be16(seq + 1, c->long_index);
			put_be16(seq + 4, method_idx);
			append(&prefix, seq, sizeof(seq));
		}

		/*
		 * Pad the prefix with nops, so the switch instructions in the
		 * original bytecode keep their alignment.
		 */
		while (prefix.n % 4) {
			unsigned char nop = 0;

			append(&prefix, &nop, 1);
		}

		for (a = 0; a < attrs; a++) {
			struct buffer code = {0};
			char *attr_name;
			uint16_t ni;
			uint32_t n;
			size_t hdr;
			int ok;

			if (!bounds(off, 6, len))
				goto output_bad;
			ni = be16(data + off);
			n = be32(data + off + 2);
			hdr = off;
			off += 6;
			if (!bounds(off, n, len))
				goto output_bad;
			attr_name = cp_string(cp, ni);
			if (!attr_name)
				goto output_bad;

			/*
			 * Only the Code attribute of instrumented method is
			 * rewritten, everything else is copied.
			 */
			if (prefix.n && !strcmp(attr_name, "Code")) {
				ok = transform_code(data + off, n, prefix.p,
						    (uint32_t)prefix.n, cp,
						    &code);
				if (!ok || code.n > UINT32_MAX) {
					free(attr_name);
					free(code.p);
					goto output_bad;
				}

				append(&result, data + hdr, 2);
				append_u4(&result, (uint32_t)code.n);
				append(&result, code.p, code.n);
				free(code.p);
			} else {
				append(&result, data + hdr, 6 + n);
			}

			free(attr_name);
			off += n;
		}

		free(prefix.p);
	}

	/* Both passes over the methods must end at the same place. */
	if (off != methods_end || !bounds(off, 2, len))
		goto output_bad;

	/* Class attributes are copied unchanged. */
	append(&result, data + off, len - off);
	for (i = 0; i < method_count; i++) {
		for (c = plans[i].calls; c; c = c->next) {
			/*
			 * Tell Tetragon about new method keys. If the record
			 * gets dropped, hook_enter emits it again.
			 */
			if (!c->match->defined)
				c->match->defined = emit_def(c->match) == 0;
		}
	}

	for (i = 0; i < method_count; i++) {
		for (c = plans[i].calls; c; c = next) {
			next = c->next;
			free(c);
		}
	}

	free(plans);
	free(cp);
	*out = result.p;
	*out_len = result.n;
	return 1;

output_bad:
	free(result.p);

plan_bad:
	/* Drop method matches added for this class. */
	while (g_methods != old_head) {
		m = g_methods;
		g_methods = m->next;
		free(m->class_name);
		free(m->name);
		free(m->descriptor);
		free(m);
	}

	for (i = 0; i < method_count; i++) {
		for (c = plans[i].calls; c; c = next) {
			next = c->next;
			free(c);
		}
	}

	free(plans);

bad:
	free(cp);
	return 0;
}

/*
 * Native implementation of TetragonHook.enter(long key), called at the
 * entry of each instrumented method. Emits TG_REC_METHOD_ENTRY record:
 * u64 key, u64 ktime, u32 tid, u32 pad.
 */
static void JNICALL hook_enter(JNIEnv *jni __maybe_unused,
			       jclass klass __maybe_unused, jlong key)
{
	struct method_match *m;
	struct timespec ts;
	uint64_t ktime;
	uint32_t tid;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	/* CLOCK_MONOTONIC is the clock of bpf_ktime_get_ns used for BPF events. */
	ktime = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
	tid = (uint32_t)syscall(SYS_gettid);

	pthread_mutex_lock(&g_lock);
	for (m = g_methods; m; m = m->next) {
		if (m->key != (uint64_t)key)
			continue;

		/* Emit the definition again if it was dropped before. */
		if (!m->defined)
			m->defined = emit_def(m) == 0;
		if (m->defined) {
			unsigned char p[24] = {0};

			wr64(p, m->key);
			wr64(p + 8, ktime);
			wr32(p + 16, tid);
			ring_write(TG_REC_METHOD_ENTRY, p, sizeof(p));
		}
		break;
	}
	pthread_mutex_unlock(&g_lock);
}

/* JDK classes and our hook class are never instrumented. */
static int excluded_class(const char *name)
{
	return !name || strncmp(name, "java/", 5) == 0 ||
	       strncmp(name, "jdk/", 4) == 0 || strncmp(name, "sun/", 4) == 0 ||
	       strncmp(name, "io/tetragon/", 12) == 0;
}

/*
 * Called by the JVM for each class being loaded or retransformed with the
 * class file bytes. The class stays unchanged unless new_bytes is set.
 */
static void JNICALL class_file_load_hook(jvmtiEnv *jvmti,
					 JNIEnv *jni __maybe_unused,
					 jclass redefining __maybe_unused,
					 jobject loader __maybe_unused,
					 const char *name,
					 jobject domain __maybe_unused,
					 jint len, const unsigned char *bytes,
					 jint *new_len,
					 unsigned char **new_bytes)
{
	unsigned char *transformed = NULL;
	size_t transformed_len = 0;
	int rc;

	if (len <= 0 || excluded_class(name))
		return;

	pthread_mutex_lock(&g_lock);
	rc = transform_class(name, bytes, (size_t)len, &transformed,
			     &transformed_len);

	/* The JVM expects (and frees) the new class in JVMTI allocated memory. */
	if (rc == 1 && transformed_len <= INT32_MAX &&
	    (*jvmti)->Allocate(jvmti, (jlong)transformed_len, new_bytes) ==
		    JVMTI_ERROR_NONE) {
		memcpy(*new_bytes, transformed, transformed_len);
		*new_len = (jint)transformed_len;
	}
	pthread_mutex_unlock(&g_lock);
	free(transformed);
}

/*
 * Retransform already loaded classes that match hooks of the policy (and
 * all committed hooks with include_committed), so the JVM calls
 * class_file_load_hook for them and they get rewritten based on the
 * current hooks.
 *
 * Called without g_lock, class_file_load_hook takes it.
 */
static void retransform_policy_classes(uint32_t policy_id,
				       int include_committed)
{
	jclass *classes = NULL;
	jint count = 0, i;

	if ((*g_jvmti)->GetLoadedClasses(g_jvmti, &count, &classes) !=
	    JVMTI_ERROR_NONE)
		return;
	for (i = 0; i < count; i++) {
		char *sig = NULL, *generic = NULL, *name;
		jboolean modifiable = JNI_FALSE;
		jvmtiError e = JVMTI_ERROR_NONE;
		int selected = 0;
		struct hook *h;
		size_t n;

		(*g_jvmti)->GetClassSignature(g_jvmti, classes[i], &sig,
					      &generic);

		/* Class signature is "La/b/C;", get the a/b/C name. */
		if (sig && sig[0] == 'L') {
			n = strlen(sig);
			name = calloc(1, n - 1);
			if (name) {
				memcpy(name, sig + 1, n - 2);
				pthread_mutex_lock(&g_lock);
				for (h = g_hooks; h; h = h->next) {
					if ((h->policy_id == policy_id ||
					     (include_committed &&
					      h->committed)) &&
					    class_allowed(h, name)) {
						selected = 1;
						break;
					}
				}
				pthread_mutex_unlock(&g_lock);
				free(name);
			}
		}

		/* Skip classes the JVM is not able to modify. */
		if (selected)
			e = (*g_jvmti)->IsModifiableClass(g_jvmti, classes[i],
							  &modifiable);
		if (sig)
			(*g_jvmti)->Deallocate(g_jvmti, (unsigned char *)sig);
		if (generic)
			(*g_jvmti)->Deallocate(g_jvmti,
					       (unsigned char *)generic);
		if (!selected || e != JVMTI_ERROR_NONE || !modifiable)
			continue;

		/* One class at a time, so a failure does not affect other classes. */
		e = (*g_jvmti)->RetransformClasses(g_jvmti, 1, &classes[i]);
		if (e != JVMTI_ERROR_NONE)
			fprintf(stderr,
				"tetragon-jvmti: class retransformation failed (%d)\n",
				e);
	}

	(*g_jvmti)->Deallocate(g_jvmti, (unsigned char *)classes);
}

/*
 * Close the control session: remove the instrumentation from all classes,
 * free hooks and methods and release the ring and the control socket.
 */
static void cleanup_control_session(void)
{
	size_t count = 0, capacity = 0, ring_len, next, i;
	int ring_fd, fd, seen;
	struct method_match *m;
	uint32_t *ids = NULL, *p;
	struct hook *h;
	void *ring_map;

	pthread_mutex_lock(&g_lock);
	/* Uncommit all hooks and collect ids of their policies. */
	for (h = g_hooks; h; h = h->next) {
		h->committed = 0;
		seen = 0;
		for (i = 0; i < count; i++) {
			if (ids[i] == h->policy_id) {
				seen = 1;
				break;
			}
		}

		if (seen)
			continue;
		if (count == capacity) {
			next = capacity ? capacity * 2 : 8;
			p = realloc(ids, next * sizeof(*p));
			if (!p)
				break;
			ids = p;
			capacity = next;
		}

		ids[count++] = h->policy_id;
	}
	pthread_mutex_unlock(&g_lock);

	/* No hook is committed now, so the classes are rewritten without the calls. */
	for (i = 0; i < count; i++)
		retransform_policy_classes(ids[i], 0);
	free(ids);

	pthread_mutex_lock(&g_lock);
	while (g_hooks) {
		h = g_hooks;
		g_hooks = h->next;
		free_hook(h);
	}

	while (g_methods) {
		m = g_methods;
		g_methods = m->next;
		free(m->class_name);
		free(m->name);
		free(m->descriptor);
		free(m);
	}

	/* Detach the session state under the lock and release it outside. */
	g_ring = NULL;
	ring_map = g_ring_map;
	ring_len = g_ring_len;
	ring_fd = g_ring_fd;
	g_ring_map = MAP_FAILED;
	g_ring_len = 0;
	g_ring_fd = -1;
	fd = g_sock;
	g_sock = -1;
	pthread_mutex_unlock(&g_lock);

	if (fd >= 0)
		close(fd);
	if (ring_map != MAP_FAILED)
		munmap(ring_map, ring_len);
	if (ring_fd >= 0)
		close(ring_fd);
}

/*
 * Define the TetragonHook class (if not defined already) in the bootstrap
 * class loader, so it is visible to all classes, and bind its native
 * enter method to hook_enter.
 */
static int define_hook_class(JNIEnv *jni)
{
	JNINativeMethod method = {
		.name = "enter",
		.signature = "(J)V",
		.fnPtr = (void *)hook_enter,
	};
	jclass klass;

	/*
	 * The class is already there if previous attach got this far and
	 * failed later. Failed lookup leaves NoClassDefFoundError pending,
	 * it must be cleared before any other JNI call.
	 */
	klass = (*jni)->FindClass(jni, "io/tetragon/TetragonHook");
	if (!klass) {
		(*jni)->ExceptionClear(jni);

		/*
		 * NULL loader is the bootstrap class loader. The class bytes
		 * are compiled jvmti/TetragonHook.java, see tetragonhook.h.
		 */
		klass = (*jni)->DefineClass(jni, "io/tetragon/TetragonHook",
					    NULL,
					    (const jbyte *)tetragon_hook_class,
					    (jsize)sizeof(tetragon_hook_class));
	}

	if (!klass)
		return -1;

	/*
	 * Bind the native method explicitly, the JVM would not find it by
	 * the Java_io_tetragon_TetragonHook_enter symbol lookup, because the
	 * agent library is not loaded through System.loadLibrary.
	 */
	return (*jni)->RegisterNatives(jni, klass, &method, 1) == JNI_OK ? 0 : -1;
}

/*
 * Send TG_MSG_ACK for the command with seq: u32 seq, i32 status,
 * u32 classes, u16 error length and the error string.
 */
static int ack(uint32_t seq, int32_t status, uint32_t classes,
	       const char *error)
{
	size_t n = error ? strlen(error) : 0;
	unsigned char p[12 + 256] = {0};

	if (n > 250)
		n = 250;
	wr32(p, seq);
	wr32(p + 4, (uint32_t)status);
	wr32(p + 8, classes);
	wr16(p + 12, (uint16_t)n);
	if (n)
		memcpy(p + 14, error, n);
	return send_packet(TG_MSG_ACK, seq, p, 14 + n);
}

/*
 * Handle one command from Tetragon and acknowledge it:
 *   TG_MSG_HOOK_ADD      - store the hook, not active yet
 *   TG_MSG_POLICY_COMMIT - activate hooks of the policy and instrument
 *                          matching classes
 *   TG_MSG_POLICY_REMOVE - remove hooks of the policy together with the
 *                          instrumentation
 */
static int handle_command(unsigned char *buf, size_t len)
{
	const unsigned char *p = buf + 8;
	uint32_t seq = rd32(buf + 4);
	uint16_t type = rd16(buf);
	size_t n = len - 8;
	struct hook *h, *it;
	int status = 0;
	uint32_t id;

	if (type == TG_MSG_HOOK_ADD) {
		h = parse_hook(p, n);
		if (!h) {
			status = -1;
		} else {
			int duplicate = 0;

			pthread_mutex_lock(&g_lock);
			for (it = g_hooks; it; it = it->next) {
				if (it->policy_id == h->policy_id &&
				    it->hook_id == h->hook_id) {
					duplicate = 1;
					break;
				}
			}

			/* The list takes over the hook, duplicate hook is dropped. */
			if (!duplicate) {
				h->next = g_hooks;
				g_hooks = h;
				h = NULL;
			}
			pthread_mutex_unlock(&g_lock);
			free_hook(h);
		}
	} else if (type == TG_MSG_POLICY_COMMIT && n == 4) {
		id = rd32(p);
		pthread_mutex_lock(&g_lock);
		for (h = g_hooks; h; h = h->next) {
			if (h->policy_id == id)
				h->committed = 1;
		}
		pthread_mutex_unlock(&g_lock);

		retransform_policy_classes(id, 0);
	} else if (type == TG_MSG_POLICY_REMOVE && n == 4) {
		struct method_match *removed = NULL, **mp, *old;
		struct hook **hp;

		id = rd32(p);
		pthread_mutex_lock(&g_lock);
		for (h = g_hooks; h; h = h->next) {
			if (h->policy_id == id)
				h->committed = 0;
		}
		pthread_mutex_unlock(&g_lock);

		/*
		 * The hooks are still in the list, but not committed, so the
		 * classes are rewritten without them.
		 */
		retransform_policy_classes(id, 1);

		pthread_mutex_lock(&g_lock);
		/* Free hooks and method matches of the policy. */
		hp = &g_hooks;
		while (*hp) {
			if ((*hp)->policy_id == id) {
				h = *hp;
				*hp = h->next;
				free_hook(h);
			} else {
				hp = &(*hp)->next;
			}
		}

		mp = &g_methods;
		while (*mp) {
			if ((*mp)->policy_id == id) {
				old = *mp;
				*mp = old->next;
				old->next = removed;
				removed = old;
			} else {
				mp = &(*mp)->next;
			}
		}

		while (removed) {
			old = removed;
			removed = removed->next;
			free(old->class_name);
			free(old->name);
			free(old->descriptor);
			free(old);
		}
		pthread_mutex_unlock(&g_lock);
	} else {
		status = -1;
	}

	return ack(seq, status, 0,
		   status ? "invalid or unsupported command" : "");
}

/* Connect to the Tetragon control socket, returns the socket or -1. */
static int connect_control(const char *path)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd;

	if (!path ||
	    strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path))
		return -1;
	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * Open the control session with Tetragon: connect to its socket, say HELLO
 * and map the ring it hands back. Nothing is left behind on failure.
 * The failure is reported only for verbose, the reconnect attempts fail
 * silently while Tetragon is away.
 */
static int session_open(const char *path, int verbose)
{
	unsigned char packet[8 + 4 + 2 + 255] = {0};
	unsigned char buf[TG_MSG_MAX_SIZE];
	size_t version_len, ring_len, n = 0;
	struct tg_ring_hdr *ring;
	char *vm_version = NULL;
	int control_fd;
	int passed = -1;
	void *ring_map;

	control_fd = connect_control(path);
	if (control_fd < 0) {
		if (verbose)
			fprintf(stderr,
				"tetragon-jvmti: connect failed for %s: %s\n",
				path, strerror(errno));
		return -1;
	}

	pthread_mutex_lock(&g_lock);
	g_sock = control_fd;
	pthread_mutex_unlock(&g_lock);

	(*g_jvmti)->GetSystemProperty(g_jvmti, "java.vm.version", &vm_version);
	version_len = vm_version ? strlen(vm_version) : 0;
	if (version_len > 255)
		version_len = 255;

	/* HELLO: header, u32 protocol version, u16 length and the JVM version. */
	wr16(packet, TG_MSG_HELLO);
	wr32(packet + 4, 0);
	wr32(packet + 8, TG_PROTO_VERSION);
	wr16(packet + 12, (uint16_t)version_len);
	if (version_len)
		memcpy(packet + 14, vm_version, version_len);
	if (vm_version)
		(*g_jvmti)->Deallocate(g_jvmti, (unsigned char *)vm_version);

	if (send(g_sock, packet, 14 + version_len, MSG_NOSIGNAL) !=
	    (ssize_t)(14 + version_len)) {
		if (verbose)
			fprintf(stderr, "tetragon-jvmti: HELLO send failed\n");
		goto fail;
	}

	if (receive_packet(buf, sizeof(buf), &n, &passed) != 0 ||
	    rd16(buf) != TG_MSG_RING || n < 16 || passed < 0) {
		if (verbose)
			fprintf(stderr,
				"tetragon-jvmti: ring handoff failed n=%zu type=%u fd=%d errno=%s\n",
				n, n >= 2 ? rd16(buf) : 0, passed,
				strerror(errno));
		if (passed >= 0)
			close(passed);
		goto fail;
	}

	/* RING: header, u64 ring length, the ring memfd comes with SCM_RIGHTS. */
	ring_len = (size_t)rd64(buf + 8);
	if (ring_len < TG_RING_HDR_SIZE + 1024) {
		if (verbose)
			fprintf(stderr,
				"tetragon-jvmti: invalid ring length %zu\n",
				ring_len);
		close(passed);
		goto fail;
	}

	ring_map = mmap(NULL, ring_len, PROT_READ | PROT_WRITE, MAP_SHARED,
			passed, 0);
	if (ring_map == MAP_FAILED) {
		if (verbose)
			fprintf(stderr, "tetragon-jvmti: mmap ring failed %s\n",
				strerror(errno));
		close(passed);
		goto fail;
	}

	ring = (struct tg_ring_hdr *)ring_map;
	/* Check the ring header prepared by Tetragon. */
	if (ring->magic != TG_RING_MAGIC || ring->version != TG_RING_VERSION ||
	    ring->data_size != ring_len - TG_RING_HDR_SIZE) {
		if (verbose)
			fprintf(stderr,
				"tetragon-jvmti: invalid ring header magic=%x version=%u size=%lu len=%zu\n",
				ring->magic, ring->version,
				(unsigned long)ring->data_size, ring_len);
		munmap(ring_map, ring_len);
		close(passed);
		goto fail;
	}

	pthread_mutex_lock(&g_lock);
	/* Publish the ring, hook_enter can write records from now on. */
	g_ring_fd = passed;
	g_ring_map = ring_map;
	g_ring_len = ring_len;
	g_ring = ring;
	pthread_mutex_unlock(&g_lock);
	return 0;

fail:
	cleanup_control_session();
	return -1;
}

/*
 * Wait before the next reconnect attempt, Agent_OnAttach cuts the wait
 * short when Tetragon attaches again.
 */
static void reconnect_wait(unsigned int delay)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_sec += delay;

	pthread_mutex_lock(&g_lock);
	/* The timeout (or an error) ends the wait as well. */
	while (!g_wake) {
		if (pthread_cond_timedwait(&g_wake_cond, &g_lock, &ts) != 0)
			break;
	}

	g_wake = 0;
	pthread_mutex_unlock(&g_lock);
}

/*
 * The control thread serves the session opened by Agent_OnAttach. When the
 * session ends (Tetragon exited or restarted), it removes the hooks and keeps
 * trying to connect back, so Tetragon does not need to attach again.
 */
static void *control_thread(void *unused __maybe_unused)
{
	static unsigned char buf[TG_MSG_MAX_SIZE];
	JavaVMAttachArgs args = {
		.version = JNI_VERSION_1_6,
		.name = "tetragon-jvmti-control",
		.group = NULL,
	};
	unsigned int delay = RECONNECT_DELAY_MIN;
	int connected = 1;
	JNIEnv *jni = NULL;

	/*
	 * The thread needs to be attached to the JVM to use JVMTI, daemon
	 * thread does not block the JVM exit.
	 */
	if ((*g_vm)->AttachCurrentThreadAsDaemon(g_vm, (void **)&jni, &args) !=
	    JNI_OK) {
		cleanup_control_session();
		pthread_mutex_lock(&g_lock);
		g_initialized = 0;
		pthread_mutex_unlock(&g_lock);
		return NULL;
	}

	for (;;) {
		if (!connected) {
			char path[sizeof(g_path)];

			pthread_mutex_lock(&g_lock);
			memcpy(path, g_path, sizeof(path));
			pthread_mutex_unlock(&g_lock);

			connected = session_open(path, 0) == 0;
		}

		if (connected) {
			for (;;) {
				size_t n = 0;
				int fd = -1;

				/* Serve commands until the session breaks. */
				if (receive_packet(buf, sizeof(buf), &n, &fd))
					break;

				/* Commands do not carry file descriptors. */
				if (fd >= 0)
					close(fd);
				if (handle_command(buf, n))
					break;
			}

			cleanup_control_session();
			connected = 0;
			delay = RECONNECT_DELAY_MIN;
		}

		/* Back off up to RECONNECT_DELAY_MAX between the attempts. */
		reconnect_wait(delay);
		delay *= 2;
		if (delay > RECONNECT_DELAY_MAX)
			delay = RECONNECT_DELAY_MAX;
	}

	return NULL;
}

/*
 * Called by the JVM when Tetragon loads the agent, options carry the path
 * of the control socket. The first attach sets up the agent, opens the
 * control session and starts the control thread. Following attaches only
 * pass new socket path to the control thread.
 *
 * The first attach goes through following steps:
 *   - get the JVMTI environment
 *   - open the control session (HELLO and ring handoff)
 *   - add JVMTI capabilities needed to rewrite classes
 *   - define the TetragonHook class
 *   - register and enable the ClassFileLoadHook event
 *   - start the control thread
 *
 * The function runs in the JVM's attach listener thread, which is a Java
 * thread, so both JVMTI and JNI are available. The return value is passed
 * back to Tetragon as the result of the load command. The library stays
 * loaded even when we fail, so the next attach comes here again with
 * g_initialized not set and starts from scratch.
 */
JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM *vm, char *options,
				      void *reserved __maybe_unused)
{
	jvmtiEventCallbacks callbacks = {0};
	jvmtiCapabilities caps = {0};
	pthread_condattr_t attr;
	JNIEnv *jni = NULL;
	pthread_t thread;
	jvmtiError jerr;
	int perr;

	if (!options || !options[0]) {
		fprintf(stderr, "tetragon-jvmti: no socket option\n");
		return JNI_ERR;
	}
	if (strlen(options) >= sizeof(g_path)) {
		fprintf(stderr, "tetragon-jvmti: socket path too long\n");
		return JNI_ERR;
	}

	pthread_mutex_lock(&g_lock);
	if (g_initialized) {
		/*
		 * The agent is already in this JVM, take the socket path
		 * and let the control thread connect right away.
		 */
		strcpy(g_path, options);
		g_wake = 1;
		pthread_cond_signal(&g_wake_cond);
		pthread_mutex_unlock(&g_lock);
		return JNI_OK;
	}
	pthread_mutex_unlock(&g_lock);

	/* The control thread needs the JavaVM to attach itself to the JVM. */
	g_vm = vm;

	/*
	 * Get the JVMTI environment, the handle for all JVMTI calls. Each
	 * GetEnv call with JVMTI version creates new environment with its
	 * own capabilities, callbacks and enabled events, so nothing we set
	 * up below affects other agents in the JVM.
	 *
	 * The version is the lowest JVMTI version we ask the JVM to support,
	 * RetransformClasses is there since 1.1.
	 */
	if ((*vm)->GetEnv(vm, (void **)&g_jvmti, JVMTI_VERSION_1_2) != JNI_OK ||
	    !g_jvmti) {
		fprintf(stderr, "tetragon-jvmti: GetEnv failed\n");
		return JNI_ERR;
	}

	/*
	 * Fail the attach early if Tetragon is not reachable. This is done
	 * before the JVM gets changed in any way, but after we have g_jvmti,
	 * session_open uses it to read the JVM version for HELLO.
	 */
	if (session_open(options, 1) != 0)
		return JNI_ERR;

	/*
	 * Capabilities are off by default and must be added before the
	 * functions and events they guard are used:
	 *
	 *   can_retransform_classes
	 *     Allows RetransformClasses, which we use to instrument classes
	 *     that are already loaded. It also makes ClassFileLoadHook of
	 *     this environment to be called for retransformed classes, not
	 *     just for the newly loaded ones.
	 *
	 *   can_generate_all_class_hook_events
	 *     ClassFileLoadHook is generated for every class the JVM loads.
	 *
	 * We are attached to the running JVM (live phase), where only some
	 * capabilities can be added, HotSpot allows both of these.
	 */
	caps.can_generate_all_class_hook_events = 1;
	caps.can_retransform_classes = 1;
	jerr = (*g_jvmti)->AddCapabilities(g_jvmti, &caps);
	if (jerr != JVMTI_ERROR_NONE) {
		fprintf(stderr, "tetragon-jvmti: AddCapabilities failed %d\n",
			jerr);
		goto fail;
	}

	/*
	 * TetragonHook must exist before any class gets instrumented, so
	 * define it before the ClassFileLoadHook is enabled. This time GetEnv
	 * is called with JNI version and returns the JNIEnv of the current
	 * thread, which is needed for JNI calls in define_hook_class.
	 */
	if ((*vm)->GetEnv(vm, (void **)&jni, JNI_VERSION_1_6) != JNI_OK ||
	    define_hook_class(jni) != 0) {
		fprintf(stderr,
			"tetragon-jvmti: failed to define TetragonHook bootstrap class\n");
		goto fail;
	}

	/*
	 * Register the event callbacks. The call sets the whole callback
	 * table of the environment, events with NULL callback are not
	 * delivered. The size tells the JVM which version of the table we
	 * were compiled with.
	 */
	callbacks.ClassFileLoadHook = class_file_load_hook;
	jerr = (*g_jvmti)->SetEventCallbacks(g_jvmti, &callbacks,
					     sizeof(callbacks));
	if (jerr != JVMTI_ERROR_NONE) {
		fprintf(stderr, "tetragon-jvmti: SetEventCallbacks failed %d\n",
			jerr);
		goto fail;
	}

	/*
	 * Registered callback is not called until its event is enabled, NULL
	 * thread enables it for all threads. From now on class_file_load_hook
	 * can run in any thread that loads a class, even before we return.
	 * No hook is committed yet, so it leaves all classes unchanged.
	 */
	jerr = (*g_jvmti)->SetEventNotificationMode(g_jvmti, JVMTI_ENABLE,
						    JVMTI_EVENT_CLASS_FILE_LOAD_HOOK,
						    NULL);
	if (jerr != JVMTI_ERROR_NONE) {
		fprintf(stderr,
			"tetragon-jvmti: enable class load hook failed %d\n",
			jerr);
		goto fail;
	}

	/* reconnect_wait uses monotonic clock for the timeout. */
	pthread_condattr_init(&attr);
	pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	pthread_cond_init(&g_wake_cond, &attr);
	pthread_condattr_destroy(&attr);

	pthread_mutex_lock(&g_lock);
	strcpy(g_path, options);
	g_wake = 0;
	g_initialized = 1;
	pthread_mutex_unlock(&g_lock);

	perr = pthread_create(&thread, NULL, control_thread, NULL);
	if (perr != 0) {
		fprintf(stderr,
			"tetragon-jvmti: control thread create failed %d\n",
			perr);
		pthread_mutex_lock(&g_lock);
		g_initialized = 0;
		pthread_mutex_unlock(&g_lock);
		goto fail;
	}

	pthread_detach(thread);
	return JNI_OK;

fail:
	/*
	 * Close the session opened above. The JVMTI setup is not reverted,
	 * the capabilities, the TetragonHook class and possibly enabled
	 * ClassFileLoadHook stay, but they do nothing without hooks.
	 */
	cleanup_control_session();
	return JNI_ERR;
}
