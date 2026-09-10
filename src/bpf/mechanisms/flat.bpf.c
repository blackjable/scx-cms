/* SPDX-License-Identifier: GPL-2.0 */
/*
 * "flat" -- negative control. Penalize every task identically,
 * ignoring the tracked count entirely.
 *
 * This exists to answer an objection that would otherwise sink the
 * round 2 result. `penalty` improved the victim's p99 by 6.8x over
 * `none`, but `penalty` does two things at once: it consults the
 * tracked wakeup count, AND it perturbs vtime. If the improvement
 * comes from the perturbation rather than the count -- if simply
 * pushing everything back a few milliseconds happens to suit this
 * workload -- then the tracking is doing no work and the entire
 * premise of the project is unsupported by that experiment.
 *
 * `flat` isolates the perturbation. It applies cms_flat_ns to every
 * task at every enqueue with no reference to how often the task woke.
 * Run it at a value comparable to the adjustment `penalty` actually
 * applied:
 *
 *   flat ~= penalty  =>  the count is irrelevant here; the result is
 *                        about vtime perturbation and must not be
 *                        reported as evidence for wakeup tracking.
 *   flat <  penalty  =>  the discrimination between tasks is doing
 *                        the work, which is the claim the paper makes.
 *
 * A control is only worth running at a value that could actually
 * beat the treatment, so sweep cms_flat_ns rather than picking one
 * convenient number.
 */

const volatile u64 cms_flat_ns = 0;

static __always_inline u64 cms_mech_flat(struct task_struct *p, u64 vtime,
					 u64 count)
{
	u64 adj = cms_flat_ns;

	if (adj > cms_adjust_max_ns)
		adj = cms_adjust_max_ns;
	if (!adj)
		return vtime;

	__sync_fetch_and_add(&cms_penalties_applied, 1);

	return vtime + adj;
}
