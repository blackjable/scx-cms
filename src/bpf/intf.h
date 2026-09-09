/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __INTF_H
#define __INTF_H

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;
typedef int pid_t;
#endif

enum consts {
	SHARED_DSQ = 0,

	/* Not exposed by vmlinux.h; every scheduler here defines its own. */
	CLOCK_BOOTTIME = 7,

	/* struct task_struct.comm is TASK_COMM_LEN (16) bytes, including the
	 * trailing NUL; kept as our own constant so identity.bpf.c doesn't
	 * depend on vmlinux.h just for this. */
	CMS_COMM_LEN = 16,
};

/*
 * Candidate task-identity keys for the (not-yet-built) wakeup-frequency
 * tracker. Which one to use is an open, evidence-based decision -- see
 * delivery plan Section 2 and paper Section 4.1.1's targeted-collision
 * finding -- so it's selectable at scheduler start rather than hardcoded.
 */
enum cms_identity_key {
	CMS_IDENTITY_PID	= 0,	/* fastest churn, hardest to spoof */
	CMS_IDENTITY_TGID	= 1,	/* survives thread churn within a process */
	CMS_IDENTITY_COMM	= 2,	/* coarsest; self-settable by the task */
};

/*
 * Mechanism ids and names are NOT declared here. They are derived from
 * CMS_MECHANISM_LIST in bpf/mechanisms/index.h, which is the single place
 * a mechanism is registered -- see that file before adding one.
 */

/*
 * Which counting method backs the wakeup tracker. This is the study's
 * independent variable -- the whole question is whether the approximate
 * one can replace the exact one -- so unlike mechanisms it is a fixed
 * pair rather than an extensible set, and is registered by hand.
 */
enum cms_tracker_kind {
	CMS_TRACKER_EXACT	= 0,
	CMS_TRACKER_SKETCH	= 1,
};

enum sketch_consts {
	/*
	 * Bounds for the loops the verifier must see terminate. The table
	 * itself is sized at load time to exactly 2 * width * depth cells,
	 * not to these maxima -- the sketch's entire claim is a small fixed
	 * footprint, so an over-allocated table would make the measured
	 * memory disagree with the reported memory.
	 */
	CMS_SKETCH_MAX_WIDTH	= 4096,
	CMS_SKETCH_MAX_DEPTH	= 8,

	/*
	 * Phase 1's reference configuration (paper Section 4.1): a stable
	 * ~31.9% overestimate against a 65.7x memory saving. Defaulting here
	 * keeps kernel-side results directly comparable to that figure.
	 */
	CMS_DFL_SKETCH_WIDTH	= 256,
	CMS_DFL_SKETCH_DEPTH	= 4,
};

enum tracker_consts {
	/*
	 * Upper bound on distinct identities tracked at once. The map is an
	 * LRU hash, so exceeding this evicts the least-recently-used entry
	 * rather than failing the insert -- which also cleans up identities
	 * that churned away and will never be seen again.
	 */
	CMS_MAX_TRACKED		= 16384,

	CMS_DFL_WINDOW_NS	= 1000000000ULL,	/* 1s rotation */
	CMS_DFL_PENALTY_NS	= 1000ULL,		/* per tracked wakeup */
	CMS_DFL_BOOST_NS	= 1000ULL,		/* per wakeup under threshold */
	CMS_DFL_BOOST_THRESH	= 8ULL,
	CMS_DFL_ADJUST_MAX_NS	= 20000000ULL,		/* cap: one default slice */
};

/*
 * Per-identity counts for the rotating dual-buffer window (paper Section
 * 2.3.1). `cur` accumulates this window, `prev` holds the last one, and a
 * query sums both. Rather than actively clearing a buffer at each rotation
 * -- which would mean iterating and deleting every map entry from BPF --
 * each entry records the epoch it was last touched and is rolled forward
 * lazily on next access. Same semantics, no full-map iteration.
 */
struct cms_count {
	u64 epoch;
	u64 cur;
	u64 prev;
};

#endif /* __INTF_H */
