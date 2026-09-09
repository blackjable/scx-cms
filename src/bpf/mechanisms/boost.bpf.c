/* SPDX-License-Identifier: GPL-2.0 */
/*
 * "boost" -- favor infrequent wakers.
 *
 * Moves a task earlier in the queue when it woke fewer than
 * --boost-threshold times during the tracking window.
 *
 * STATUS: UNVALIDATED. This is a first attempt, not a port of anything
 * that has been shown to work, and it should not be written up as
 * inheriting Phase 1's evidence.
 *
 * The reason there is nothing to port: Phase 1's boost-style policy was
 * found to be reading privileged knowledge of which task was actually
 * latency-sensitive, rather than inferring it. Once that was removed the
 * apparent advantage vanished entirely, collapsing to byte-identical
 * with plain fairness (paper Section 4.2.1). So no oracle-free boost
 * design has ever been shown to help.
 *
 * What is implemented here is the closest stand-in available from a
 * wakeup count alone: treat "wakes rarely relative to surrounding
 * churn" as a proxy for "something is waiting on this". That proxy may
 * simply be wrong -- a task can wake rarely because it is idle and
 * unimportant, which this cannot distinguish from rarely because it is
 * interactive and blocked on input.
 *
 * If this shows an advantage, that result deserves more suspicion than
 * a null one, in keeping with how every other unexpectedly favourable
 * finding in this project has been treated.
 */

const volatile u64 cms_boost_ns = CMS_DFL_BOOST_NS;
const volatile u64 cms_boost_thresh = CMS_DFL_BOOST_THRESH;

u64 cms_boosts_applied;

static __always_inline u64 cms_mech_boost(struct task_struct *p, u64 vtime,
					  u64 count)
{
	u64 adj;

	if (count >= cms_boost_thresh)
		return vtime;

	adj = (cms_boost_thresh - count) * cms_boost_ns;
	if (adj > cms_adjust_max_ns)
		adj = cms_adjust_max_ns;
	/*
	 * vtime starts at zero for tasks enabled right after attach, so a
	 * boost can genuinely exceed it before the clock has advanced.
	 */
	if (adj > vtime)
		adj = vtime;
	if (!adj)
		return vtime;

	__sync_fetch_and_add(&cms_boosts_applied, 1);

	return vtime - adj;
}
