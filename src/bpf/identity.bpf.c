/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Swappable per-task identity abstraction.
 *
 * The eventual wakeup-frequency tracker (Count-Min Sketch vs. exact
 * counter, see the phase 2 handoff docs) needs a single notion of "which
 * task is this" to key its counters by. Which candidate is right --
 * PID, TGID, or `comm` -- is deliberately not decided here: PID churns
 * fastest and is arguably the wrong granularity, TGID survives thread
 * churn within a process, and `comm` is coarsest but self-settable by
 * the task itself, which matters once a deliberate hash-collision attack
 * against the tracker is a demonstrated risk rather than a theoretical
 * one. Every caller goes through task_identity() so that decision can be
 * made later, from real evidence (BPF ergonomics + a per-candidate
 * replication of the collision attack), without touching tracking logic.
 *
 * cms_identity_key is a const volatile set by userspace before load
 * (see main.rs), not a compile-time #define, so switching candidates
 * doesn't require a rebuild.
 */

const volatile u32 cms_identity_key = CMS_IDENTITY_PID;

/*
 * FNV-1a. Chosen (not blake2b) per the Phase 1 finding that both hashes
 * showed identical vulnerability to the targeted-collision attack -- so
 * there's no security reason to pay a cryptographic hash's cost on a BPF
 * hot path. Only used for the `comm` identity candidate; PID/TGID need
 * no hashing.
 */
#define FNV_OFFSET_BASIS	0xcbf29ce484222325ULL
#define FNV_PRIME		0x100000001b3ULL

static __always_inline u64 fnv1a_hash_comm(const char comm[CMS_COMM_LEN])
{
	u64 hash = FNV_OFFSET_BASIS;
	int i;

#pragma unroll
	for (i = 0; i < CMS_COMM_LEN; i++) {
		hash ^= (u8)comm[i];
		hash *= FNV_PRIME;
	}

	return hash;
}

static __always_inline u64 task_identity(struct task_struct *p)
{
	switch (cms_identity_key) {
	case CMS_IDENTITY_TGID:
		return (u64)p->tgid;
	case CMS_IDENTITY_COMM:
		return fnv1a_hash_comm(p->comm);
	case CMS_IDENTITY_PID:
	default:
		return (u64)p->pid;
	}
}
