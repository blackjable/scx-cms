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

static __always_inline void cms_track(u64 id)
{
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

	if (cms_tracker == CMS_TRACKER_SKETCH)
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

	if (cms_tracker == CMS_TRACKER_SKETCH)
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
