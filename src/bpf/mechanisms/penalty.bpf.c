/* SPDX-License-Identifier: GPL-2.0 */
/*
 * "penalty" -- deprioritize frequent wakers.
 *
 * Pushes a task later in the queue in proportion to how often it woke
 * during the tracking window, on the reasoning that a task waking
 * constantly is more likely to be background churn than something a
 * user is waiting on.
 *
 * Status: this is the shape Phase 1 actually tested. Its result was a
 * genuine non-finding -- sketch and exact tracking produced
 * byte-identical scheduling outcomes (paper Section 4.2.1) -- which
 * leaves two possibilities the simulation could not distinguish:
 * either the approximation is accurate enough never to change a
 * decision, or this mechanism does not lean on the count hard enough
 * for any difference to show. Do not read a null result here as
 * evidence for the first without ruling out the second.
 */

const volatile u64 cms_penalty_ns = CMS_DFL_PENALTY_NS;

u64 cms_penalties_applied;

static __always_inline u64 cms_mech_penalty(struct task_struct *p, u64 vtime,
					    u64 count)
{
	u64 adj = count * cms_penalty_ns;

	if (adj > cms_adjust_max_ns)
		adj = cms_adjust_max_ns;
	if (!adj)
		return vtime;

	__sync_fetch_and_add(&cms_penalties_applied, 1);

	return vtime + adj;
}
