/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Wakeup tracking: the shared window clock, and the choice of counting
 * method.
 *
 * Two backends live in trackers/, and --tracker picks between them at
 * launch. They are the study's independent variable: exact counting is
 * correct but grows with the number of distinct tasks, the sketch is fixed
 * in size but approximate, and the question is whether that approximation
 * ever changes a scheduling decision.
 *
 * Unlike mechanisms/, this is a hand-registered pair rather than an
 * extensible set. Adding a third counting method is not anticipated -- the
 * comparison is the experiment -- so the registration machinery that folder
 * carries would not pay for itself here.
 *
 * Both backends share one window clock, driven by the timer below, so a
 * comparison between them cannot be confounded by differing window
 * boundaries.
 */

const volatile u32 cms_tracker = CMS_TRACKER_EXACT;
const volatile u64 cms_window_ns = CMS_DFL_WINDOW_NS;

/* Rotation counter, and the epoch tag the exact tracker writes into entries. */
u64 cms_epoch;
u64 cms_window_rotations;

#include "trackers/exact.bpf.c"
#include "trackers/sketch.bpf.c"

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

u64 cms_cmp_samples;
u64 cms_cmp_exact_sum;
u64 cms_cmp_sketch_sum;
u64 cms_cmp_max_over;

/*
 * Count-Min's one formal guarantee is that it never undercounts. Checking it
 * against a real event stream is a genuine validation of the port, not a
 * formality -- if this is ever non-zero, the sketch is wrong and any accuracy
 * figure taken from it is meaningless. Phase 1 checked the same invariant in
 * Python (paper Section 4.1.2) and found zero violations.
 */
u64 cms_cmp_underestimates;

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
		*sketch = cms_sketch_query(id);

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
	__sync_fetch_and_add(&cms_cmp_exact_sum, exact);
	__sync_fetch_and_add(&cms_cmp_sketch_sum, sketch);

	if (sketch < exact) {
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
		cms_sketch_increment(id);
		cms_compare_sample(id);
		return;
	}

	if (cms_tracker == CMS_TRACKER_SKETCH)
		cms_sketch_increment(id);
	else
		cms_exact_increment(id);
}

static __always_inline u64 cms_query(u64 id)
{
	if (cms_tracker == CMS_TRACKER_SKETCH)
		return cms_sketch_query(id);

	return cms_exact_query(id);
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

	if (cms_tracker == CMS_TRACKER_SKETCH || cms_compare)
		cms_sketch_rotate();

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

	if (cms_tracker == CMS_TRACKER_SKETCH || cms_compare)
		cms_sketch_init();

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
