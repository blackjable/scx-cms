/* SPDX-License-Identifier: GPL-2.0 */
/*
 * "none" -- track wakeup frequency but never act on it.
 *
 * Scheduling behaviour is identical to unmodified scx_simple, so the
 * difference between this and a bare scx_simple run is the cost of the
 * tracking itself and nothing else. That makes it the control: it
 * separates "what does counting cost" from "what does acting on the
 * count do", which the Phase 1 Python work had no way to measure.
 */

static __always_inline u64 cms_mech_none(struct task_struct *p, u64 vtime,
					 u64 count)
{
	return vtime;
}
