/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The trackers compiled into this build.
 *
 * A tracker is a way of storing "how often has this identity woken
 * recently". The study's independent variable is which one is selected;
 * everything downstream -- the mechanism, the identity key, the window --
 * is held constant across them.
 *
 * ADDING ONE:
 *   1. Write yours.bpf.c in this folder, defining four functions named
 *      after the prefix in its row:
 *
 *        s32  <prefix>_init(void)            -- may just return 0
 *        void <prefix>_increment(u64 id)
 *        u64  <prefix>_query(u64 id)
 *        void <prefix>_rotate(void)          -- may be empty
 *
 *   2. Add its #include below.
 *   3. Add a row to CMS_TRACKER_LIST.
 *
 * The id the kernel switches on, the dispatch, and the `--tracker yours`
 * command-line value are all derived from the row. The build fails if a
 * .bpf.c file here is missing from the list or the includes, if a listed
 * name has no file, or if names or ids collide -- see build.rs, which
 * applies the same checks to mechanisms/.
 *
 * THE LAST COLUMN, which mechanisms/ has no equivalent of: does this
 * tracker guarantee it never reports LESS than the true count? Count-Min
 * Sketch does, by construction, and that guarantee is the whole reason to
 * prefer it over structures that evict. Compare mode counts violations of
 * it, and that check is only meaningful for a tracker that claims it --
 * for one that can legitimately undercount (Space-Saving, a counting Bloom
 * filter with deletion, anything sampling) a non-zero count is expected
 * behaviour rather than a bug, and treating it as a bug would bury the
 * real signal. Declare it honestly; `false` disables the check rather than
 * weakening it.
 *
 * WHY THIS IS A LIST AND NOT A DIRECTORY SCAN: with a scan, which trackers
 * exist in a build depends on which files happen to be present that day.
 * Reproducing a number from the paper months later would mean
 * reconstructing the contents of a folder. A committed list makes "what
 * was actually compiled in" answerable from the repo.
 *
 * HISTORY, because the comment this replaces said the opposite: this was a
 * hand-written pair of if/else branches on `cms_tracker`, with a note
 * saying a third counting method was not anticipated. It became worth
 * generalising when the test trackers below were wanted -- and the two of
 * them promptly found what the pair could not, since a two-branch dispatch
 * cannot tell a routing bug from a working one.
 */

#include "exact.bpf.c"
#include "sketch.bpf.c"
#include "test_null.bpf.c"
#include "test_saturate.bpf.c"

/*
 *       id  name           prefix              never undercounts?
 */
#define CMS_TRACKER_LIST(X)						\
	X(0,  exact,         cms_exact,          true)			\
	X(1,  sketch,        cms_sketch,         true)			\
	X(2,  test_null,     cms_test_null,      false)			\
	X(3,  test_saturate, cms_test_saturate,  true)
