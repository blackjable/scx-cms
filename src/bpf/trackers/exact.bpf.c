/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Exact per-identity wakeup counter with rotating dual-buffer windowing.
 *
 * This is the isolation baseline: exact counts, so the sketch can be
 * compared against it with everything else held constant. It ports the
 * windowing scheme validated in Phase 1 (paper Section 2.3.1) -- counts
 * live in two buffers, a query sums both, and at each window boundary the
 * older buffer is discarded. Without that a counter answers "how often
 * has this task ever woken since boot" rather than "is this task a heavy
 * waker right now", and only the latter is a useful scheduling signal.
 *
 * Its memory grows with the number of distinct identities seen, which is
 * exactly the cost the sketch is meant to avoid.
 *
 * Two deliberate departures from the Python prototype, both forced by
 * what BPF can do cheaply:
 *
 *   - Buffers are not two maps that get swapped and cleared. Clearing a
 *     hash map from a BPF program means iterating and deleting every
 *     entry; nothing else in this repo does that. Instead each entry
 *     carries the epoch it was last touched and is rolled forward on next
 *     access. Observable semantics are identical.
 *
 *   - The map is an LRU hash. The Python model needed no eviction because
 *     it rebuilt buffers wholesale; here, identities that churn away are
 *     never touched again and would otherwise hold slots forever.
 */

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, CMS_MAX_TRACKED);
	__type(key, u64);
	__type(value, struct cms_count);
} cms_counts SEC(".maps");

/*
 * Bring an entry up to date with the current epoch, applying however many
 * rotations it slept through. One window missed means this window's counts
 * became last window's; two or more means both buffers are stale.
 */
static __always_inline void cms_roll(struct cms_count *c, u64 epoch)
{
	if (c->epoch == epoch)
		return;

	if (epoch - c->epoch == 1) {
		c->prev = c->cur;
		c->cur = 0;
	} else {
		c->prev = 0;
		c->cur = 0;
	}

	c->epoch = epoch;
}

static __always_inline void cms_exact_increment(u64 id)
{
	struct cms_count *c, init;
	u64 epoch = cms_epoch;

	c = bpf_map_lookup_elem(&cms_counts, &id);
	if (c) {
		cms_roll(c, epoch);
		c->cur++;
		return;
	}

	__builtin_memset(&init, 0, sizeof(init));
	init.epoch = epoch;
	init.cur = 1;
	bpf_map_update_elem(&cms_counts, &id, &init, BPF_ANY);
}

/*
 * Tracked wakeups for this identity across the current and previous window.
 *
 * WARNING for anything reading cms_counts from outside this file (userspace
 * analysis, `bpftool map dump`, the exact-vs-sketch comparison): stored
 * values are only rolled forward when the entry is next touched, so an entry
 * whose task went quiet keeps its old epoch and old counts indefinitely. A
 * raw read of `cur`/`prev` without applying cms_roll()'s logic against the
 * live cms_epoch will report counts for a window that closed long ago. The
 * true answer for a stale entry is usually zero, not what is stored.
 */
static __always_inline u64 cms_exact_query(u64 id)
{
	struct cms_count *c;

	c = bpf_map_lookup_elem(&cms_counts, &id);
	if (!c)
		return 0;

	cms_roll(c, cms_epoch);

	return c->cur + c->prev;
}
