/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The mechanisms compiled into this build.
 *
 * ADDING ONE:
 *   1. Write yourthing.bpf.c in this folder, defining
 *      cms_mech_yourthing(struct task_struct *p, u64 vtime, u64 count)
 *      which returns the vtime to insert the task with.
 *   2. Add its #include below.
 *   3. Add a row to CMS_MECHANISM_LIST.
 *
 * That is all. The id the kernel switches on, the dispatch, and the
 * `--mechanism yourthing` command-line value are all derived from the
 * row -- there is no fourth place to register it and forget.
 *
 * The build fails if a .bpf.c file in this folder is missing from the
 * list or the includes, or if a listed name has no file, or if names or
 * ids collide. That check exists because an unlisted file compiles
 * perfectly happily: nothing references it, so nothing complains, and
 * the only symptom is that `--mechanism yourthing` reports an invalid
 * value later. Silent drift of exactly that kind has already cost this
 * project real time (paper Section 4.1's audit note).
 *
 * WHY THIS IS A LIST AND NOT A DIRECTORY SCAN: with a scan, which
 * strategies exist in a build depends on which files happen to be
 * present that day. Reproducing a number from the paper months later
 * would mean reconstructing the contents of a folder. A committed list
 * makes "what was actually compiled in" answerable from the repo, for
 * the same reason Phase 1 pins its seeds and hash functions.
 */

#include "none.bpf.c"
#include "penalty.bpf.c"
#include "boost.bpf.c"
#include "flat.bpf.c"

/*
 *       id  name      implementation
 */
#define CMS_MECHANISM_LIST(X)				\
	X(0,  none,     cms_mech_none)			\
	X(1,  penalty,  cms_mech_penalty)		\
	X(2,  boost,    cms_mech_boost)		\
	X(3,  flat,     cms_mech_flat)
