/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Per-task probe: publish what both counters currently say about one
 * chosen pid.
 *
 * The aggregate compare statistics answer "how far apart are the counters
 * across everything", which is the wrong question for an attack. An attack
 * inflates one victim's estimate while leaving the rest of the system
 * alone, so measuring it needs a readout for that victim specifically.
 *
 * Deliberately computed here rather than in the attacking harness. The
 * harness could read the sketch table and seeds and do the hashing itself,
 * but then two implementations of the same hash would have to agree, and
 * the one doing the measuring would be the one that could silently drift.
 * Phase 1 was bitten by exactly that (paper Section 4.1.3, where a
 * collision search hardcoded the wrong hash and produced a false "this
 * hash is immune" result). The kernel's own query is authoritative, so the
 * measurement uses it.
 *
 * Both counters must be live for this to mean anything, so run with
 * --compare. The target pid is written by userspace at run time, since a
 * victim's pid is not knowable before the scheduler starts.
 */

struct cms_probe {
	u32 pid;	/* written by userspace; 0 disables the probe */
	u32 pad;
	u64 identity;	/* what the tracker actually keys on for that pid */
	u64 exact;	/* truth */
	u64 sketch;	/* estimate; the gap between them is the attack */
	u64 samples;
	/* Diagnostic-only, added while chasing a spurious never-undercount
	 * violation under hackbench: latches the first time sketch < exact
	 * is observed for THIS pid, so the raw internal state at that exact
	 * moment can be inspected instead of reasoning about the race
	 * abstractly. Not needed once that bug is understood and fixed. */
	u64 viol_seen;
	u64 viol_epoch;
	u64 viol_seq;
	u64 viol_exact_cur;
	u64 viol_exact_prev;
	u64 viol_exact_epoch;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct cms_probe);
} cms_probe SEC(".maps");

static __always_inline void cms_probe_update(struct task_struct *p, u64 id)
{
	struct cms_probe *pr;
	u32 key = 0;
	u64 exact, sketch;

	pr = bpf_map_lookup_elem(&cms_probe, &key);
	if (!pr || !pr->pid || (u32)p->pid != pr->pid)
		return;

	/* Same exact/sketch race as cms_compare_sample() in tracker.bpf.c --
	 * see the comment on cms_query_both() there. This is a per-victim
	 * probe read on every wakeup, so it hits the same window. */
	if (!cms_query_both(id, &exact, &sketch))
		return;

	pr->identity = id;
	pr->exact = exact;
	pr->sketch = sketch;
	pr->samples++;

	if (sketch < exact && !pr->viol_seen) {
		struct cms_count *c = bpf_map_lookup_elem(&cms_counts, &id);

		pr->viol_seen = 1;
		pr->viol_epoch = cms_epoch;
		pr->viol_seq = cms_sketch_seq;
		if (c) {
			pr->viol_exact_cur = c->cur;
			pr->viol_exact_prev = c->prev;
			pr->viol_exact_epoch = c->epoch;
		}
	}
}
