/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Wakeup tracking: the shared window clock, and the choice of counting
 * method.
 *
 * The backends live in trackers/ and register themselves in
 * trackers/index.h; --tracker picks between them at launch. They are the
 * study's independent variable: exact counting is correct but grows with
 * the number of distinct tasks, the sketch is fixed in size but
 * approximate, and the question is whether that approximation ever changes
 * a scheduling decision.
 *
 * Every backend shares one window clock, driven by the timer below, so a
 * comparison between them cannot be confounded by differing window
 * boundaries.
 *
 * This was a hand-written if/else over a fixed pair, with a comment saying
 * a third counting method was not anticipated. It is a registered list now,
 * sharing build.rs's validation with mechanisms/, because two branches
 * cannot distinguish a dispatch that works from one that routes everything
 * to the same place -- see trackers/test_null.bpf.c.
 */

const volatile u32 cms_tracker = CMS_TRACKER_EXACT;
const volatile u64 cms_window_ns = CMS_DFL_WINDOW_NS;

/* Rotation counter, and the epoch tag the exact tracker writes into entries. */
u64 cms_epoch;
u64 cms_window_rotations;

#include "trackers/index.h"

/*
 * Dispatch, generated from CMS_TRACKER_LIST so that adding a tracker means
 * editing one list rather than finding every switch site. `which` is always
 * a load-time constant (`cms_tracker` or `cms_compare_with`), so the
 * verifier folds these chains to the selected body and eliminates the rest
 * -- the same property the original if/else relied on.
 */
static __always_inline void cms_increment_as(u32 which, u64 id)
{
#define X(id_, name_, pfx_, uc_)					\
	if (which == id_) {						\
		pfx_##_increment(id);					\
		return;							\
	}
	CMS_TRACKER_LIST(X)
#undef X
}

static __always_inline u64 cms_query_as(u32 which, u64 id)
{
#define X(id_, name_, pfx_, uc_)					\
	if (which == id_)						\
		return pfx_##_query(id);
	CMS_TRACKER_LIST(X)
#undef X
	return 0;
}

static __always_inline void cms_rotate_as(u32 which)
{
#define X(id_, name_, pfx_, uc_)					\
	if (which == id_) {						\
		pfx_##_rotate();					\
		return;							\
	}
	CMS_TRACKER_LIST(X)
#undef X
}

static __always_inline s32 cms_init_as(u32 which)
{
#define X(id_, name_, pfx_, uc_)					\
	if (which == id_)						\
		return pfx_##_init();
	CMS_TRACKER_LIST(X)
#undef X
	return 0;
}

/*
 * Does the tracker at `which` promise never to report less than the true
 * count? Declared per row in trackers/index.h. Compare mode's violation
 * counter is only meaningful for a tracker that claims this; for one that
 * can legitimately undercount, a non-zero count is expected behaviour and
 * counting it as a fault would bury the real signal.
 */
static __always_inline bool cms_never_undercounts(u32 which)
{
#define X(id_, name_, pfx_, uc_)					\
	if (which == id_)						\
		return uc_;
	CMS_TRACKER_LIST(X)
#undef X
	return false;
}

/*
 * Compare mode: feed BOTH counters every wakeup and record how far apart
 * they land, while only the selected one drives scheduling.
 *
 * This exists because measuring the sketch's error across two separate runs
 * would compare it against a different workload than the one it counted --
 * different tasks, different churn, different timing -- and the resulting
 * error figure would be contaminated by that difference with no way to
 * separate the two. Phase 1 avoided this by feeding both structures an
 * identical event stream; this is the kernel-side equivalent.
 *
 * It costs an extra increment and two queries per wakeup, which is
 * acceptable precisely because this mode measures accuracy rather than
 * latency. Do not leave it on while benchmarking scheduling quality.
 */
const volatile bool cms_compare;

/*
 * Which tracker compare mode measures AGAINST exact counting. Defaults to
 * the sketch, which is what every harness in this project asks for and what
 * this mode did unconditionally before it was selectable -- so existing
 * invocations are unchanged.
 *
 * It is separate from --tracker on purpose: the harnesses run compare mode
 * with `--tracker exact --mechanism none`, measuring accuracy while exact
 * counting drives scheduling, so that the thing being measured is not also
 * perturbing the workload it is measured on.
 */
const volatile u32 cms_compare_with = CMS_TRACKER_SKETCH;

u64 cms_cmp_samples;
u64 cms_cmp_exact_sum;
/* Named for the sketch because that is what it measured for the whole
 * study; it now holds whichever tracker --compare-with selects. */
u64 cms_cmp_sketch_sum;
u64 cms_cmp_max_over;

/*
 * Count-Min's one formal guarantee is that it never undercounts. Checking it
 * against a real event stream is a genuine validation of the port, not a
 * formality -- if this is ever non-zero, the sketch is wrong and any accuracy
 * figure taken from it is meaningless. Phase 1 checked the same invariant in
 * Python (paper Section 4.1.2) and found zero violations.
 *
 * KNOWN REMAINING GAP (tracked, not fixed -- see tests/regression.py,
 * test_concurrent_stress and test_known_roll_race, both intentionally
 * xfail): this CAN still be non-zero under concurrent same-identity
 * access. Three lost-update bugs were found and fixed here (see exact.bpf.c
 * and sketch.bpf.c) -- non-atomic c->cur++ and (*cell)++, and a BPF_ANY
 * overwrite race on first touch. What's left is broader than either of
 * those: cms_track()'s sequence of incrementing exact, incrementing
 * sketch, then this function reading both is not atomic AS A UNIT, even
 * though each individual step now is. A reader on one CPU can still
 * observe one structure mid-update relative to the other when a
 * different CPU is concurrently handling another wakeup of the same
 * identity -- confirmed to scale directly with concurrency (0/9/110
 * violations at 2/8/32 workers sharing one identity, on a window long
 * enough that no rotation ever fired, ruling out cms_roll() specifically
 * for this case). cms_roll()'s own three-field update has the same class
 * of exposure, additionally triggered by real rotation.
 *
 * Both are the same underlying problem and would need the same fix: some
 * form of per-identity mutual exclusion, most naturally a bpf_spin_lock.
 * Deliberately left unfixed -- this codebase has no existing
 * bpf_spin_lock usage to build from, and the risk of an unbounded
 * debugging chase with no working reference was judged too high for the
 * pass that found this. Practical impact is bounded: it requires genuine
 * concurrent access to the same identity to trigger, which most
 * measurements in this project's attack harnesses do not sustain at high
 * enough intensity to matter (each attacker there is typically its own
 * process with its own identity, not many threads hammering one shared
 * identity the way `--identity-key comm` on a real multi-threaded
 * workload can).
 */
u64 cms_cmp_underestimates;

/*
 * Distribution of the exact count seen per query, not just its mean.
 *
 * The churning workload reports a mean tracked count of ~220 where the
 * workload model predicts ~64, a gap the measured identity population did
 * not close. A mean cannot distinguish "most queries see 220" from "most
 * see almost nothing and a few see thousands", and those imply different
 * things about what the tracker is actually holding. Buckets answer that
 * directly instead of supporting another inference.
 */
u64 cms_cmp_hist[6];

/* Diagnostic-only: latches the first violation's raw state globally,
 * since the per-pid probe only sees one task's wakeups and the
 * violations are happening across many tasks under compare mode. */
u64 diag_viol_seen;
u64 diag_viol_id;
u64 diag_viol_exact;
u64 diag_viol_sketch;
u64 diag_viol_epoch;
u64 diag_viol_seq;
u64 diag_viol_exact_cur;
u64 diag_viol_exact_prev;
u64 diag_viol_exact_epoch;

/*
 * cms_exact_query() and cms_sketch_query() each read state rotated by the
 * same timer callback, but not atomically with respect to a caller that
 * straddles both calls -- a real, if narrow, race. This seqlock
 * (cms_sketch_seq in sketch.bpf.c) closes it: odd while a rotation is in
 * progress, checked for change and parity across both reads, retried
 * (bounded) rather than recording an inconsistent pair.
 *
 * NOTE ON HOW THIS WAS FOUND, kept because the investigation took a wrong
 * turn worth recording: this was the first hypothesis for a
 * never-undercount violation found under `hackbench` (633k in a few
 * seconds). It was wrong as the explanation for THAT bug -- rebuilding
 * with only this fix left violations at essentially the same rate (607k),
 * and direct diagnostic instrumentation (latching the first violation's
 * raw state) later showed the actual culprit hit at cms_epoch=0,
 * cms_sketch_seq=0 -- before any rotation had ever occurred, ruling
 * rotation out entirely for that case. The real cause was a lost-update
 * race on the plain (non-atomic) `c->cur++` and `(*cell)++` increments
 * under concurrent multi-CPU writes to the same map cell (fixed
 * separately, see exact.bpf.c and sketch.bpf.c). This seqlock is still
 * correct and worth keeping for the narrower race it actually addresses,
 * but it was not the fix for the violations that were actually observed.
 */
static __always_inline bool cms_query_both(u64 id, u64 *exact, u64 *sketch)
{
	int i;

#pragma unroll
	for (i = 0; i < 4; i++) {
		u64 seq_before = cms_sketch_seq;

		*exact = cms_exact_query(id);
		*sketch = cms_query_as(cms_compare_with, id);

		if (seq_before == cms_sketch_seq && (seq_before & 1) == 0)
			return true;
	}

	return false;
}

static __always_inline void cms_compare_sample(u64 id)
{
	u64 exact, sketch, over;

	if (!cms_query_both(id, &exact, &sketch))
		return;

	__sync_fetch_and_add(&cms_cmp_samples, 1);

	{
		u32 b = exact == 0 ? 0 :
			exact < 10 ? 1 :
			exact < 100 ? 2 :
			exact < 1000 ? 3 :
			exact < 10000 ? 4 : 5;

		__sync_fetch_and_add(&cms_cmp_hist[b], 1);
	}
	__sync_fetch_and_add(&cms_cmp_exact_sum, exact);
	__sync_fetch_and_add(&cms_cmp_sketch_sum, sketch);

	if (sketch < exact && cms_never_undercounts(cms_compare_with)) {
		__sync_fetch_and_add(&cms_cmp_underestimates, 1);

		if (!diag_viol_seen) {
			struct cms_count *c = bpf_map_lookup_elem(&cms_counts, &id);

			diag_viol_seen = 1;
			diag_viol_id = id;
			diag_viol_exact = exact;
			diag_viol_sketch = sketch;
			diag_viol_epoch = cms_epoch;
			diag_viol_seq = cms_sketch_seq;
			if (c) {
				diag_viol_exact_cur = c->cur;
				diag_viol_exact_prev = c->prev;
				diag_viol_exact_epoch = c->epoch;
			}
		}
		return;
	}

	over = sketch - exact;
	if (over > cms_cmp_max_over)
		cms_cmp_max_over = over;
}

static __always_inline void cms_track(u64 id)
{
	if (cms_compare) {
		cms_exact_increment(id);
		if (cms_compare_with != CMS_TRACKER_EXACT)
			cms_increment_as(cms_compare_with, id);
		cms_compare_sample(id);
		return;
	}

	cms_increment_as(cms_tracker, id);
}

static __always_inline u64 cms_query(u64 id)
{
	return cms_query_as(cms_tracker, id);
}

struct cms_window_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct cms_window_timer);
} cms_window_timer SEC(".maps");

/*
 * Close the current window. For the exact tracker this is just an epoch
 * bump, since entries roll themselves forward lazily; for the sketch it is
 * a real zeroing pass over the buffer being discarded.
 */
static int cms_window_timer_cb(void *map, int *key, struct bpf_timer *timer)
{
	int err;

	__sync_fetch_and_add(&cms_epoch, 1);
	__sync_fetch_and_add(&cms_window_rotations, 1);

	cms_rotate_as(cms_tracker);
	if (cms_compare && cms_compare_with != cms_tracker)
		cms_rotate_as(cms_compare_with);

	err = bpf_timer_start(timer, cms_window_ns, 0);
	if (err)
		scx_bpf_error("failed to re-arm window rotation timer");

	return 0;
}

static s32 cms_tracker_init(void)
{
	struct bpf_timer *timer;
	u32 key = 0;
	int err;

	err = cms_init_as(cms_tracker);
	if (err)
		return err;
	if (cms_compare && cms_compare_with != cms_tracker) {
		err = cms_init_as(cms_compare_with);
		if (err)
			return err;
	}

	timer = bpf_map_lookup_elem(&cms_window_timer, &key);
	if (!timer) {
		scx_bpf_error("failed to look up window rotation timer");
		return -ESRCH;
	}

	bpf_timer_init(timer, &cms_window_timer, CLOCK_BOOTTIME);
	bpf_timer_set_callback(timer, cms_window_timer_cb);

	err = bpf_timer_start(timer, cms_window_ns, 0);
	if (err) {
		scx_bpf_error("failed to arm window rotation timer");
		return err;
	}

	return 0;
}
