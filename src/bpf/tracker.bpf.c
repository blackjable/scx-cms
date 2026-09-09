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

static __always_inline void cms_compare_sample(u64 id)
{
	u64 exact = cms_exact_query(id);
	u64 sketch = cms_sketch_query(id);
	u64 over;

	__sync_fetch_and_add(&cms_cmp_samples, 1);
	__sync_fetch_and_add(&cms_cmp_exact_sum, exact);
	__sync_fetch_and_add(&cms_cmp_sketch_sum, sketch);

	if (sketch < exact) {
		__sync_fetch_and_add(&cms_cmp_underestimates, 1);
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
