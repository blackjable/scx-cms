/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Turns a tracked wakeup count into a scheduling decision.
 *
 * Both shapes are unproven and deliberately swappable. Phase 1's simulation
 * (paper Section 4.2.1) tested a penalty design and found sketch and exact
 * tracking produced byte-identical outcomes -- a genuine non-finding, left
 * unresolved rather than tuned into something more flattering. Its
 * boost-style comparison policy was found to be relying on oracle knowledge
 * of which task was latency-sensitive, and collapsed to no advantage once
 * that was removed. So there is no validated boost design to port here.
 *
 * The boost implemented below is therefore a first attempt, not a port:
 * with only a wakeup count to go on, the closest oracle-free stand-in for
 * "latency-sensitive" is "wakes infrequently relative to the churn around
 * it". Whether that is a useful proxy at all is exactly what the step 5
 * evaluation is meant to find out -- it should not be assumed to work.
 */

const volatile u32 cms_mechanism = CMS_MECHANISM_NONE;
const volatile u64 cms_penalty_ns = CMS_DFL_PENALTY_NS;
const volatile u64 cms_boost_ns = CMS_DFL_BOOST_NS;
const volatile u64 cms_boost_thresh = CMS_DFL_BOOST_THRESH;
const volatile u64 cms_adjust_max_ns = CMS_DFL_ADJUST_MAX_NS;

u64 cms_penalties_applied;
u64 cms_boosts_applied;

/*
 * Returns the vtime to insert @p with. Callers must apply the usual
 * accumulated-budget clamp AFTER this, so a boost cannot hand a task more
 * than one slice of credit.
 */
static __always_inline u64 cms_adjust_vtime(struct task_struct *p, u64 vtime)
{
	u64 count, adj;

	if (cms_mechanism == CMS_MECHANISM_NONE)
		return vtime;

	count = cms_query(task_identity(p));

	if (cms_mechanism == CMS_MECHANISM_PENALTY) {
		adj = count * cms_penalty_ns;
		if (adj > cms_adjust_max_ns)
			adj = cms_adjust_max_ns;
		if (!adj)
			return vtime;

		__sync_fetch_and_add(&cms_penalties_applied, 1);
		return vtime + adj;
	}

	if (cms_mechanism == CMS_MECHANISM_BOOST) {
		if (count >= cms_boost_thresh)
			return vtime;

		adj = (cms_boost_thresh - count) * cms_boost_ns;
		if (adj > cms_adjust_max_ns)
			adj = cms_adjust_max_ns;
		/*
		 * vtime starts at zero for the first tasks enabled after
		 * attach, so a boost can genuinely exceed it early on.
		 */
		if (adj > vtime)
			adj = vtime;
		if (!adj)
			return vtime;

		__sync_fetch_and_add(&cms_boosts_applied, 1);
		return vtime - adj;
	}

	return vtime;
}
