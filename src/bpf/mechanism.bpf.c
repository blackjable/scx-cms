/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Turns a tracked wakeup count into a scheduling decision.
 *
 * This file holds only the selection machinery and the one knob every
 * mechanism shares. The mechanisms themselves live one per file in
 * mechanisms/, each carrying its own tunables and its own account of
 * what is and is not known about it -- see mechanisms/index.h.
 *
 * Nothing here is validated. Whether any of these shapes is the right
 * way to use a wakeup-frequency signal is open, which is why the choice
 * is made at launch rather than baked in.
 */

const volatile u32 cms_mechanism;

/* Shared ceiling on any single adjustment, whichever mechanism is active. */
const volatile u64 cms_adjust_max_ns = CMS_DFL_ADJUST_MAX_NS;

#include "mechanisms/index.h"

#define CMS_MECH_DISPATCH(id, name, fn)					\
	case id:							\
		return fn(p, vtime, count);

/*
 * Returns the vtime to insert @p with. Callers must apply the usual
 * accumulated-budget clamp AFTER this, so a boost cannot hand a task
 * more than one slice of credit.
 *
 * cms_mechanism is a load-time constant, so the verifier prunes every
 * branch but the selected one -- the switch costs nothing at run time.
 */
static __always_inline u64 cms_adjust_vtime(struct task_struct *p, u64 vtime)
{
	u64 count;

	/* Mechanism 0 is "none"; skip the query rather than pay for it. */
	if (!cms_mechanism)
		return vtime;

	count = cms_query(task_identity(p));

	switch (cms_mechanism) {
	CMS_MECHANISM_LIST(CMS_MECH_DISPATCH)
	}

	return vtime;
}
