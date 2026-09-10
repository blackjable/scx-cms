// SPDX-License-Identifier: GPL-2.0
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use anyhow::Result;
use clap::Parser;
use clap::ValueEnum;
use libbpf_rs::MapCore;
use log::info;
use log::warn;
use scx_utils::build_id;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::UserExitInfo;

const SCHEDULER_NAME: &str = "scx_cms";

fn full_version() -> String {
    build_id::full_version(env!("CARGO_PKG_VERSION"))
}

/// Which field of a task identifies it for the (not-yet-built)
/// wakeup-frequency tracker. Deliberately left selectable rather than
/// hardcoded -- see identity.bpf.c and the phase 2 delivery plan's
/// Section 2. Values here must stay in sync with `enum cms_identity_key`
/// in src/bpf/intf.h.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum IdentityKey {
    /// Fastest-churning, hardest for a co-located process to spoof.
    Pid,
    /// Survives thread churn within a process.
    Tgid,
    /// Coarsest; self-settable by the task (see the targeted-collision
    /// finding in the phase 1 paper draft before relying on this).
    Comm,
}

impl IdentityKey {
    fn as_bpf_const(self) -> u32 {
        match self {
            IdentityKey::Pid => 0,
            IdentityKey::Tgid => 1,
            IdentityKey::Comm => 2,
        }
    }
}

// The `--mechanism` values, generated from CMS_MECHANISM_LIST in
// src/bpf/mechanisms/index.h so the command line cannot drift from what is
// actually compiled into the scheduler. Register new mechanisms there.
include!(concat!(env!("OUT_DIR"), "/mechanisms.rs"));

/// Which counting method backs the tracker. Hand-written rather than
/// generated, unlike Mechanism: this is a fixed pair, not an extensible set.
/// Must match `enum cms_tracker_kind` in src/bpf/intf.h.
#[derive(Clone, Copy, Debug, PartialEq, ValueEnum)]
enum Tracker {
    /// Exact per-identity counts; memory grows with distinct tasks.
    Exact,
    /// Count-Min Sketch; fixed memory, approximate and never underestimates.
    Sketch,
}

impl Tracker {
    fn as_bpf_const(self) -> u32 {
        match self {
            Tracker::Exact => 0,
            Tracker::Sketch => 1,
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = SCHEDULER_NAME, version, disable_version_flag = true)]
struct Opts {
    /// Use FIFO scheduling instead of weighted vtime (unmodified from
    /// scx_simple).
    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    fifo: bool,

    /// Which per-task field the wakeup tracker keys its counters by.
    /// Deliberately not hardcoded -- see identity.bpf.c.
    #[clap(long, value_enum, default_value = "pid")]
    identity_key: IdentityKey,

    /// How tracked wakeup frequency affects scheduling. Defaults to `none`
    /// (track only), which leaves scheduling identical to scx_simple.
    #[clap(long, value_enum, default_value = "none")]
    mechanism: Mechanism,

    /// Which counting method backs the tracker. `exact` grows with the
    /// number of distinct tasks; `sketch` is fixed size but approximate.
    /// This is the study's independent variable.
    #[clap(long, value_enum, default_value = "exact")]
    tracker: Tracker,

    /// Sketch columns per row (--tracker sketch). Wider is more accurate.
    #[clap(long, default_value_t = 256)]
    sketch_width: u32,

    /// Sketch rows (--tracker sketch). Phase 1 found width buys more
    /// accuracy than depth at a fixed memory budget.
    #[clap(long, default_value_t = 4)]
    sketch_depth: u32,

    /// Re-seed each sketch buffer as it is recycled. Partially mitigates a
    /// targeted-collision attack; does not eliminate it.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    seed_rotation: bool,

    /// Feed both counters every wakeup and report how far apart they land,
    /// so sketch error is measured against the same event stream rather
    /// than against a different run. Measures accuracy, not latency --
    /// do not leave this on while benchmarking scheduling quality.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    compare: bool,

    /// Tracking window length; buffers rotate at this interval.
    #[clap(long, default_value_t = 1000)]
    window_ms: u64,

    /// Penalty applied per tracked wakeup, in ns (--mechanism penalty).
    #[clap(long, default_value_t = 1000)]
    penalty_ns: u64,

    /// Boost applied per wakeup below the threshold, in ns (--mechanism boost).
    #[clap(long, default_value_t = 1000)]
    boost_ns: u64,

    /// Wakeup count below which a task is boosted (--mechanism boost).
    #[clap(long, default_value_t = 8)]
    boost_threshold: u64,

    /// Flat per-enqueue vtime penalty ignoring the tracked count
    /// (--mechanism flat). Negative control for the penalty result.
    #[clap(long, default_value_t = 0)]
    flat_ns: u64,

    /// Entries in the exact tracker's hash. The exact tracker's memory
    /// budget, and the knob that makes it comparable against the sketch's.
    #[clap(long, default_value_t = 16384)]
    max_tracked: u32,

    /// Cap on any single vtime adjustment, in ns.
    #[clap(long, default_value_t = 20_000_000)]
    adjust_max_ns: u64,

    /// Print runnable/quiescent/dispatch counters every INTERVAL seconds.
    #[clap(long)]
    stats: Option<f64>,

    #[clap(short, long, action = clap::ArgAction::SetTrue)]
    debug: bool,

    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    started_at: std::time::Instant,
    compare: bool,
}

impl<'a> Scheduler<'a> {
    fn init(
        opts: &Opts,
        open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        try_set_rlimit_infinity();

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.debug);

        let mut skel = scx_ops_open!(skel_builder, open_object, cms_ops, None)?;

        // Size the sketch table to exactly what was asked for. Reporting a
        // memory saving means the table has to actually be that size, not a
        // maximum with the unused part quietly costing memory anyway.
        let cells = 2 * opts.sketch_width * opts.sketch_depth;
        skel.maps.cms_sketch.set_max_entries(cells)?;

        // Size the exact tracker's hash the same way, for the same reason.
        // Both maps exist in the BPF object whichever tracker is selected,
        // so a memory comparison that leaves this at its compile-time
        // ceiling measures the ceiling, not the tracker -- and the two
        // conditions come out byte-identical, which is exactly what the
        // first attempt at the round 3 sweep reported.
        //
        // Sizing it explicitly also makes the real experiment possible:
        // give exact and sketch matched budgets, shrink both, and see
        // which degrades first. Overwhelming a fixed-size exact map by
        // identity count alone is not reachable here -- exceeding 16,384
        // identities in a 1s window would need process lifetimes under
        // 4ms, which fork cannot deliver.
        skel.maps.cms_counts.set_max_entries(opts.max_tracked)?;

        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.cms_tracker = opts.tracker.as_bpf_const();
        rodata.cms_sketch_width = opts.sketch_width;
        rodata.cms_sketch_depth = opts.sketch_depth;
        rodata.cms_seed_rotation = opts.seed_rotation;
        rodata.cms_compare = opts.compare;
        rodata.fifo_sched = opts.fifo;
        rodata.cms_identity_key = opts.identity_key.as_bpf_const();
        rodata.cms_mechanism = opts.mechanism.as_bpf_const();
        rodata.cms_window_ns = opts.window_ms * 1_000_000;
        rodata.cms_penalty_ns = opts.penalty_ns;
        rodata.cms_boost_ns = opts.boost_ns;
        rodata.cms_boost_thresh = opts.boost_threshold;
        rodata.cms_flat_ns = opts.flat_ns;
        rodata.cms_adjust_max_ns = opts.adjust_max_ns;

        let mut skel = scx_ops_load!(skel, cms_ops, uei)?;
        let struct_ops = scx_ops_attach!(skel, cms_ops)?;

        Ok(Self {
            skel,
            struct_ops: Some(struct_ops),
            started_at: std::time::Instant::now(),
            compare: opts.compare,
        })
    }

    fn read_dsq_stat(&self, idx: u32) -> u64 {
        let key = idx.to_ne_bytes();
        let percpu_vals: Vec<Vec<u8>> = match self
            .skel
            .maps
            .stats
            .lookup_percpu(&key, libbpf_rs::MapFlags::ANY)
        {
            Ok(Some(vals)) => vals,
            _ => return 0,
        };

        percpu_vals
            .iter()
            .filter_map(|v| v.get(0..8))
            .map(|v| u64::from_ne_bytes(v.try_into().unwrap()))
            .fold(0u64, |acc, v| acc.saturating_add(v))
    }

    fn print_stats(&self) {
        let bss = self
            .skel
            .maps
            .bss_data
            .as_ref()
            .expect("bss_data missing -- BPF object has no .bss section");

        let local = self.read_dsq_stat(0);
        let global = self.read_dsq_stat(1);

        // What fraction of dispatches the mechanism could influence at all.
        //
        // select_cpu dispatches straight to the local queue whenever it finds
        // an idle CPU, bypassing enqueue -- where the mechanism lives --
        // entirely. On an unloaded system that is nearly every dispatch, so a
        // mechanism can be almost completely inert without anything looking
        // wrong. Reported on every line because otherwise a null result is
        // indistinguishable from a mechanism that never ran: if this is a
        // fraction of a percent, the comparison said nothing about the
        // mechanism, only about how idle the machine was.
        let reach = if local + global > 0 {
            global as f64 / (local + global) as f64 * 100.0
        } else {
            0.0
        };

        info!(
            "uptime={:>6.1}s  dispatch local={local} global={global} (mechanism reach {reach:.1}%)  \
             runnable={}  quiescent={}  windows={}  penalties={}  boosts={}",
            self.started_at.elapsed().as_secs_f64(),
            bss.runnable_events,
            bss.quiescent_events,
            bss.cms_window_rotations,
            bss.cms_penalties_applied,
            bss.cms_boosts_applied,
        );

        if !self.compare {
            return;
        }

        let samples = bss.cms_cmp_samples;
        if samples == 0 {
            return;
        }

        let exact = bss.cms_cmp_exact_sum;
        let sketch = bss.cms_cmp_sketch_sum;

        // Ratio of sums over every queried identity -- NOT the same statistic
        // as Phase 1's headline, which was the error on one tracked
        // latency-sensitive task. Both are meaningful; conflating them is not.
        let overestimate = if exact > 0 {
            (sketch as f64 - exact as f64) / exact as f64 * 100.0
        } else {
            0.0
        };

        info!(
            "  compare: samples={samples} exact_mean={:.1} sketch_mean={:.1} \
             overestimate={overestimate:+.1}% max_overshoot={}",
            exact as f64 / samples as f64,
            sketch as f64 / samples as f64,
            bss.cms_cmp_max_over,
        );

        // Count-Min must never undercount. A non-zero value here means the
        // port is wrong and every accuracy figure from this run is void.
        if bss.cms_cmp_underestimates > 0 {
            warn!(
                "  compare: {} UNDERESTIMATES -- sketch violated the \
                 never-undercount guarantee; this build is broken",
                bss.cms_cmp_underestimates
            );
        }
    }

    fn exited(&self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>, stats_interval: Option<Duration>) -> Result<UserExitInfo> {
        // Poll on a short fixed tick rather than sleeping for the stats
        // interval, so that how promptly the scheduler responds to Ctrl-C
        // does not depend on how often it was asked to print. Sleeping the
        // full interval meant --stats 60 took up to a minute to detach,
        // which looks like a hang and blocks anything scripting it.
        const TICK: Duration = Duration::from_millis(250);
        let mut next_print = std::time::Instant::now();

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            if let Some(interval) = stats_interval {
                let now = std::time::Instant::now();
                if now >= next_print {
                    self.print_stats();
                    next_print = now + interval;
                }
            }
            std::thread::sleep(TICK);
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!("{} {}", SCHEDULER_NAME, full_version());
        return Ok(());
    }

    simplelog::SimpleLogger::init(
        if opts.debug {
            simplelog::LevelFilter::Debug
        } else {
            simplelog::LevelFilter::Info
        },
        simplelog::Config::default(),
    )?;

    info!("{} {}", SCHEDULER_NAME, full_version());
    // Bounds the BPF side relies on for its loops; check here so the failure
    // is a clear message rather than a verifier rejection.
    if opts.sketch_width == 0 || opts.sketch_width > 4096 {
        bail!("--sketch-width must be 1..=4096 (got {})", opts.sketch_width);
    }
    if opts.sketch_depth == 0 || opts.sketch_depth > 8 {
        bail!("--sketch-depth must be 1..=8 (got {})", opts.sketch_depth);
    }

    info!(
        "Starting {} scheduler (fifo={}, identity_key={:?}, mechanism={:?}, window={}ms)",
        SCHEDULER_NAME, opts.fifo, opts.identity_key, opts.mechanism, opts.window_ms
    );

    // FIFO mode takes a different branch in enqueue and never consults the
    // mechanism, so the two flags are silently incompatible. Say so rather
    // than letting someone collect a run's worth of data from a scheduler
    // that was never applying the mechanism they asked for.
    if opts.fifo && opts.mechanism.as_bpf_const() != 0 {
        warn!(
            "--fifo bypasses the vtime path entirely, so --mechanism {:?} \
             will have no effect on this run",
            opts.mechanism
        );
    }

    if opts.tracker == Tracker::Sketch {
        info!(
            "Tracker: sketch, width={} depth={} seed_rotation={} \
             ({} bytes fixed, both buffers)",
            opts.sketch_width,
            opts.sketch_depth,
            opts.seed_rotation,
            2 * opts.sketch_width * opts.sketch_depth * 4,
        );
    } else {
        info!("Tracker: exact (memory grows with distinct identities)");
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })?;

    let stats_interval = opts.stats.map(Duration::from_secs_f64);

    let mut open_object = MaybeUninit::<libbpf_rs::OpenObject>::uninit();
    let mut sched = Scheduler::init(&opts, &mut open_object)?;
    sched.run(shutdown, stats_interval)?;

    info!("Scheduler exited");

    Ok(())
}
