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
 * The same tracker backed by a plain hash, which does not evict: once
 * full, inserts fail and new identities are simply untracked.
 *
 * This exists as a control. The finding that exact counting degrades at
 * small entry counts was explained by LRU behaviour, and that explanation
 * was never tested. BPF's LRU keeps per-CPU free lists targeting
 * LOCAL_FREE_TARGET (128) entries each, so a map sized in the tens or
 * low hundreds on a multi-core system is smaller than the machinery
 * managing it, and its behaviour may be dominated by the implementation
 * rather than by LRU semantics. Same capacity, different eviction policy:
 * if the degradation persists it is capacity, if it vanishes it was the
 * LRU.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CMS_MAX_TRACKED);
	__type(key, u64);
	__type(value, struct cms_count);
} cms_counts_plain SEC(".maps");

const volatile bool cms_plain_map;

static __always_inline void *cms_counts_lookup(u64 *id)
{
	if (cms_plain_map)
		return bpf_map_lookup_elem(&cms_counts_plain, id);
	return bpf_map_lookup_elem(&cms_counts, id);
}

static __always_inline long cms_counts_insert(u64 *id, struct cms_count *v)
{
	if (cms_plain_map)
		return bpf_map_update_elem(&cms_counts_plain, id, v, BPF_NOEXIST);
	return bpf_map_update_elem(&cms_counts, id, v, BPF_NOEXIST);
}

/*
 * Bring an entry up to date with the current epoch, applying however many
 * rotations it slept through. One window missed means this window's counts
 * became last window's; two or more means both buffers are stale.
 */
/*
 * Distinct identities inserted, monotonic since load. Sampled by
 * userspace over a known interval it gives the rate at which new
 * identities appear, which is a property of the WORKLOAD rather than of
 * the tracker -- so run it with a map large enough not to evict, and the
 * rate is the live identity population per window.
 *
 * It exists because the churning-regime accuracy figures were validated
 * against an assumed identity population that turned out to be wrong by
 * 4x. Assuming this number instead of measuring it invalidated a round of
 * conclusions; it is cheap to count and there is no reason to infer it.
 */
u64 cms_exact_inserts;

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
	long err;

	c = cms_counts_lookup(&id);
	if (c) {
		cms_roll(c, epoch);
		__sync_fetch_and_add(&c->cur, 1);
		return;
	}

	/*
	 * BPF_NOEXIST, not BPF_ANY: this is a genuine lost-update race with
	 * BPF_ANY, found via direct diagnostic capture, not reasoning --
	 * two CPUs racing cms_exact_increment() for the same not-yet-seen
	 * identity (common under --identity-key comm, where many threads
	 * share one identity and wake concurrently) can both see the lookup
	 * above miss, and BPF_ANY unconditionally overwrites, so whichever
	 * bpf_map_update_elem() runs second silently discards the first
	 * one's cur=1 instead of the entry ending up at cur=2. Caught
	 * because it made the sketch's separately-fixed atomic increment
	 * look like it was STILL undercounting after that fix landed --
	 * the exact side had a different, still-live lost-update bug of its
	 * own on this path.
	 */
	__builtin_memset(&init, 0, sizeof(init));
	init.epoch = epoch;
	init.cur = 1;
	err = cms_counts_insert(&id, &init);
	if (!err) {
		__sync_fetch_and_add(&cms_exact_inserts, 1);
		return;
	}
	if (err) {
		/* Lost the race: someone else just created it. Their insert
		 * already counts as one increment; add ours to it instead of
		 * silently dropping it. */
		c = cms_counts_lookup(&id);
		if (c) {
			cms_roll(c, epoch);
			__sync_fetch_and_add(&c->cur, 1);
		}
	}
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

	c = cms_counts_lookup(&id);
	if (!c)
		return 0;

	cms_roll(c, cms_epoch);

	return c->cur + c->prev;
}
