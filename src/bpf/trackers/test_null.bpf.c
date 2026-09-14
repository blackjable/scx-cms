/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A tracker that stores nothing and always answers zero.
 *
 * NOT A COUNTING METHOD. This is a control, and it exists because every
 * control in this project so far has been on the *mechanism* axis --
 * `none` does nothing with the count, `flat` ignores the count -- and
 * there was never one on the *tracker* axis. So nothing checked that
 * selecting a tracker selects that tracker, or that a count of zero
 * propagates to the mechanism the way the code claims.
 *
 * WHAT IT PREDICTS, exactly rather than statistically. `cms_mech_penalty`
 * computes `adj = count * cms_penalty_ns` and returns `vtime` unchanged
 * when `adj` is zero, without touching `cms_penalties_applied`. So:
 *
 *     --tracker test_null --mechanism penalty
 *
 * must be indistinguishable from `--mechanism none`, and
 * `cms_penalties_applied` must be exactly 0 over any run of any length.
 * Not "small". Zero. See tests/regression.py.
 *
 * WHAT IT CATCHES. A dispatch that routed `--tracker test_null` to the
 * exact tracker -- the obvious failure mode when the tracker axis was
 * generalised from a hand-written if/else to a registered list -- would
 * report a non-zero count and a non-zero penalty count, and the assertion
 * fails. A two-tracker dispatch could not catch that, because with two
 * branches every routing bug still lands on a real tracker that produces
 * plausible numbers.
 *
 * It also gives the harness a positive control it lacked: run this against
 * `--mechanism none` in a benchmark matrix and the two rows must agree. If
 * they do not, the disagreement is in the measurement pipeline rather than
 * in anything about counting.
 *
 * Declared `never undercounts = false` in index.h. It undercounts
 * constantly and by design, which is exactly why compare mode's violation
 * check must be told not to count it as a fault.
 */

static __always_inline s32 cms_test_null_init(void)
{
	return 0;
}

static __always_inline void cms_test_null_increment(u64 id)
{
}

static __always_inline u64 cms_test_null_query(u64 id)
{
	return 0;
}

static __always_inline void cms_test_null_rotate(void)
{
}
