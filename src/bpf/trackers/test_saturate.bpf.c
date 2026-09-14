/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A tracker that stores nothing and always answers a count large enough to
 * saturate any mechanism reading it.
 *
 * NOT A COUNTING METHOD. The companion control to test_null, at the other
 * end of the range.
 *
 * WHAT IT PREDICTS, again exactly. `cms_mech_penalty` computes
 * `adj = count * cms_penalty_ns` and clamps it to `cms_adjust_max_ns`;
 * `cms_mech_flat` takes `cms_flat_ns` and clamps it the same way. So with
 * a count guaranteed to saturate the clamp:
 *
 *     --tracker test_saturate --mechanism penalty
 *
 * applies exactly `cms_adjust_max_ns` to every task that reaches the
 * mechanism -- which is identical to `--mechanism flat --flat-ns N` for
 * any N at or above the clamp. Not similar: the same arithmetic on the
 * same path. `cms_penalties_applied` must equal the number of enqueues
 * that reached the mechanism, and a benchmark row must land on top of the
 * count-blind control already in the archive.
 *
 * That second prediction is the one worth having. `flat` is the control
 * the whole project's headline rests on -- it dissolved 82% of a 6.8x
 * result -- and nothing has ever checked it from the other direction. If
 * `test_saturate + penalty` does NOT match `flat`, then either the clamp
 * is not doing what the code says or the two mechanisms diverge somewhere
 * unaccounted for, and the count-blind comparison needs re-examining
 * before anything else does.
 *
 * WHY THE VALUE IS WHAT IT IS. Large enough that `count * cms_penalty_ns`
 * saturates the clamp for any sane penalty, small enough that the multiply
 * cannot overflow u64 and wrap to something small -- which would silently
 * turn this control into a weak penalty and make it agree with nothing.
 * At 1e9 and a penalty of 1e9 ns the product is 1e18, inside u64's ~1.8e19.
 *
 * Declared `never undercounts = true` in index.h: it cannot report less
 * than the truth, since it reports more than any achievable count.
 */

#define CMS_TEST_SATURATE_COUNT ((u64)1000000000ULL)

static __always_inline s32 cms_test_saturate_init(void)
{
	return 0;
}

static __always_inline void cms_test_saturate_increment(u64 id)
{
}

static __always_inline u64 cms_test_saturate_query(u64 id)
{
	return CMS_TEST_SATURATE_COUNT;
}

static __always_inline void cms_test_saturate_rotate(void)
{
}
