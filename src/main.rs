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

use anyhow::Result;
use clap::Parser;
use clap::ValueEnum;
use libbpf_rs::MapCore;
use log::info;
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

        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.fifo_sched = opts.fifo;
        rodata.cms_identity_key = opts.identity_key.as_bpf_const();
        rodata.cms_mechanism = opts.mechanism.as_bpf_const();
        rodata.cms_window_ns = opts.window_ms * 1_000_000;
        rodata.cms_penalty_ns = opts.penalty_ns;
        rodata.cms_boost_ns = opts.boost_ns;
        rodata.cms_boost_thresh = opts.boost_threshold;
        rodata.cms_adjust_max_ns = opts.adjust_max_ns;

        let mut skel = scx_ops_load!(skel, cms_ops, uei)?;
        let struct_ops = scx_ops_attach!(skel, cms_ops)?;

        Ok(Self {
            skel,
            struct_ops: Some(struct_ops),
            started_at: std::time::Instant::now(),
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

        info!(
            "uptime={:>6.1}s  dispatches={}/{}  runnable={}  quiescent={}  windows={}  penalties={}  boosts={}",
            self.started_at.elapsed().as_secs_f64(),
            self.read_dsq_stat(0),
            self.read_dsq_stat(1),
            bss.runnable_events,
            bss.quiescent_events,
            bss.cms_window_rotations,
            bss.cms_penalties_applied,
            bss.cms_boosts_applied,
        );
    }

    fn exited(&self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>, stats_interval: Option<Duration>) -> Result<UserExitInfo> {
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            if let Some(interval) = stats_interval {
                self.print_stats();
                std::thread::sleep(interval);
            } else {
                std::thread::sleep(Duration::from_millis(250));
            }
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
    info!(
        "Starting {} scheduler (fifo={}, identity_key={:?}, mechanism={:?}, window={}ms)",
        SCHEDULER_NAME, opts.fifo, opts.identity_key, opts.mechanism, opts.window_ms
    );

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
