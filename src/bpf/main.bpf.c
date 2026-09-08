/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx_cms -- a scx_simple-derived scheduler carrying a swappable
 * per-task identity abstraction (identity.bpf.c), built as the shell
 * for a Count-Min Sketch wakeup-frequency tracker (see the phase 2
 * handoff docs under .claude/sched_ext_phase2_handoff/).
 *
 * The scheduling policy itself is unmodified scx_simple: a global
 * weighted-vtime scheduler with an optional FIFO mode. What's new here
 * is `runnable`/`quiescent` calling task_identity() -- the swappable
 * PID/TGID/comm abstraction -- on every wakeup and sleep transition, so
 * the tracking logic has a stable place to plug into later without
 * touching this file again. No sketch or exact-counter tracking is
 * wired up yet; only the identity resolution and observability
 * (runnable_events/quiescent_events counters) exist so this builds and
 * runs on its own before any tracking logic lands.
 *
 * Original scx_simple:
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;

static u64 vtime_now;
UEI_DEFINE(uei);

/* Per-task identity, resolved once on wakeup and reused on the matching
 * sleep transition purely for observability (to confirm runnable and
 * quiescent agree on who a task is) -- not consumed by anything yet. */
struct task_ctx {
	u64 identity;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/* Observability only: confirms the identity hook fires on both the
 * wakeup and sleep side before any real tracker consumes it. */
volatile u64 runnable_events;
volatile u64 quiescent_events;

#include "identity.bpf.c"
#include "tracker.bpf.c"
#include "mechanism.bpf.c"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);			/* [local, global] */
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

s32 BPF_STRUCT_OPS(cms_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		stat_inc(0);	/* count local queueing */
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}

	return cpu;
}

void BPF_STRUCT_OPS(cms_enqueue, struct task_struct *p, u64 enq_flags)
{
	stat_inc(1);	/* count global queueing */

	if (fifo_sched) {
		scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;

		vtime = cms_adjust_vtime(p, vtime);

		/*
		 * Limit the amount of budget that an idling task can accumulate
		 * to one slice. Applied after the mechanism adjustment so that
		 * a boost is bounded by the same rule.
		 */
		if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;

		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime,
					 enq_flags);
	}
}

void BPF_STRUCT_OPS(cms_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_dsq_move_to_local(SHARED_DSQ, 0);
}

void BPF_STRUCT_OPS(cms_running, struct task_struct *p)
{
	if (fifo_sched)
		return;

	/*
	 * Global vtime always progresses forward as tasks start executing. The
	 * test and update can be performed concurrently from multiple CPUs and
	 * thus racy. Any error should be contained and temporary. Let's just
	 * live with it.
	 */
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(cms_stopping, struct task_struct *p, bool runnable)
{
	if (fifo_sched)
		return;

	/*
	 * Scale the execution time by the inverse of the weight and charge.
	 *
	 * Note that the default yield implementation yields by setting
	 * @p->scx.slice to zero and the following would treat the yielding task
	 * as if it has consumed all its slice. If this penalizes yielding tasks
	 * too much, determine the execution time by taking explicit timestamps
	 * instead of depending on @p->scx.slice.
	 */
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(cms_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, NULL,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return;

	tctx->identity = task_identity(p);
	cms_track_wakeup(tctx->identity);
	__sync_fetch_and_add(&runnable_events, 1);
}

void BPF_STRUCT_OPS(cms_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, NULL, 0);
	if (!tctx)
		return;

	/* Re-resolving here (rather than trusting the stored value) checks
	 * that runnable and quiescent agree on the same task's identity --
	 * relevant once `comm` is a candidate, since it can change between
	 * a task's wakeup and its next sleep. */
	if (tctx->identity != task_identity(p))
		return;

	__sync_fetch_and_add(&quiescent_events, 1);
}

void BPF_STRUCT_OPS(cms_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cms_init)
{
	s32 ret;

	ret = scx_bpf_create_dsq(SHARED_DSQ, -1);
	if (ret)
		return ret;

	return cms_tracker_init();
}

void BPF_STRUCT_OPS(cms_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(cms_ops,
	       .select_cpu		= (void *)cms_select_cpu,
	       .enqueue			= (void *)cms_enqueue,
	       .dispatch		= (void *)cms_dispatch,
	       .running			= (void *)cms_running,
	       .stopping		= (void *)cms_stopping,
	       .runnable		= (void *)cms_runnable,
	       .quiescent		= (void *)cms_quiescent,
	       .enable			= (void *)cms_enable,
	       .init			= (void *)cms_init,
	       .exit			= (void *)cms_exit,
	       .name			= "cms");
