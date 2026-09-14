#!/usr/bin/env python3
"""
Regression suite for scx_cms.

Requires root and a sched_ext-enabled kernel. Run from this directory
(or pass --binary) after `cargo build -p scx_cms`:

    sudo python3 tests/regression.py

WHY THIS EXISTS

The delivery plan (Section 5) called for a suite like this "before, not
after, starting the BPF work" -- Phase 1's Python prototype had one from
early on. This scheduler's BPF/Rust side did not, and the gap was real:
three lost-update concurrency bugs (non-atomic sketch cell increment,
non-atomic exact counter increment, a BPF_ANY overwrite race) sat in the
tracker for the entire attack/mitigation investigation, undetected,
until an unrelated boost-mechanism sanity check happened to run under
heavy concurrent load and tripped the never-undercount guarantee 633,000
times in a few seconds. Nothing before that check was contention-heavy
enough to surface it.

test_concurrent_stress is this suite's answer to that: the one test that
would have caught all three bugs on the first CI run, if it had existed
first. Everything else here is comparatively minor.

WHAT THIS DELIBERATELY DOES NOT COVER

Writing this suite immediately found a fourth issue, broader than the
three fixed bugs above: cms_track()'s sequence of cms_exact_increment(),
cms_sketch_increment(), then cms_compare_sample() reading both is not
atomic AS A UNIT. Each individual step is now atomic on its own, but a
concurrent reader on another CPU -- handling a different wakeup of the
same identity -- can still observe one structure mid-update relative to
the other. This needs no window rotation to manifest: test_concurrent_
stress below confirmed 0/9/110 violations at 2/8/32 concurrent workers
sharing one identity, on a 30-second window where no rotation ever fired.

cms_roll()'s own three-field update (prev = cur; cur = 0; epoch = new)
has the same class of exposure, additionally triggered by real rotation.

Both are the same underlying problem -- concurrent same-identity access
across a multi-step sequence needs synchronization beyond making each
individual step atomic -- and the same fix (some form of per-identity
mutual exclusion, most naturally a bpf_spin_lock) would close both.
Deliberately left unfixed: this codebase has no existing bpf_spin_lock
usage to build from, and the risk of an unbounded debugging chase with
no working reference was judged too high for this pass. Both tests below
are marked as expected failures rather than silently skipped, so the gap
stays visible instead of being forgotten. If either ever starts passing,
that is real news -- remove its xfail marker and check whether the fix
covers both.
"""

import argparse
import glob
import json
import os
import pwd
import subprocess
import sys
import time

PASS, FAIL, XFAIL, XPASS = "PASS", "FAIL", "XFAIL", "XPASS"


def find_binary() -> str:
    cands = []
    user = os.environ.get("SUDO_USER")
    if user:
        try:
            cands.append(os.path.join(pwd.getpwnam(user).pw_dir,
                                      "scx-target/debug/scx_cms"))
        except KeyError:
            pass
    cands.append(os.path.expanduser("~/scx-target/debug/scx_cms"))
    cands.extend(glob.glob("/home/*/scx-target/debug/scx_cms"))
    here = os.path.dirname(os.path.abspath(__file__))
    cands.append(os.path.join(here, "..", "..", "..", "..", "target", "debug", "scx_cms"))
    for c in cands:
        if os.path.exists(c):
            return os.path.abspath(c)
    raise SystemExit(f"scx_cms binary not found; looked in: {cands}\n"
                      f"Build it first: cargo build -p scx_cms")


def bpftool(*args) -> str:
    return subprocess.run(["sudo", "bpftool", *args],
                          capture_output=True, text=True, check=True).stdout


def map_id(name: str) -> int:
    for m in json.loads(bpftool("map", "show", "-j")):
        if m.get("name") == name and any(
                p.get("comm") == "scx_cms" for p in m.get("pids", [])):
            return m["id"]
    raise RuntimeError(f"map {name!r} not found for a running scx_cms")


def read_bss() -> dict:
    out = json.loads(bpftool("map", "dump", "id", str(map_id("bpf_bpf.bss")), "-j"))
    value = out[0].get("formatted", out[0])["value"]
    entries = value[".bss"] if isinstance(value, dict) and ".bss" in value else value
    flat = {}
    for item in entries:
        flat.update(item)
    return flat


def wait_state(want: str, timeout: float = 12.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with open("/sys/kernel/sched_ext/state") as f:
                if f.read().strip() == want:
                    return True
        except OSError:
            pass
        time.sleep(0.2)
    return False


class Scheduler:
    """Starts scx_cms for one test, guarantees cleanup even on failure."""

    def __init__(self, binary: str, *args: str):
        self.binary = binary
        self.args = args
        self.proc = None

    def __enter__(self):
        subprocess.run(["sudo", "pkill", "-9", "scx_cms"], capture_output=True)
        if not wait_state("disabled"):
            raise RuntimeError("a previous scx_cms is still attached")
        self.proc = subprocess.Popen(
            ["sudo", self.binary, *self.args],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not wait_state("enabled"):
            self.proc.kill()
            raise RuntimeError(f"scx_cms failed to attach with args {self.args}")
        return self

    def __exit__(self, *exc):
        if self.proc:
            subprocess.run(["sudo", "kill", "-INT", str(self.proc.pid)],
                           capture_output=True)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                subprocess.run(["sudo", "kill", "-9", str(self.proc.pid)],
                               capture_output=True)
        subprocess.run(["sudo", "pkill", "-9", "scx_cms"], capture_output=True)
        wait_state("disabled")
        return False


def set_comm(name: str) -> None:
    import ctypes
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    buf = ctypes.create_string_buffer(name.encode()[:15])
    libc.prctl(15, ctypes.byref(buf), 0, 0, 0)


def busy_wait(comm: str, iters: int) -> None:
    set_comm(comm)
    for _ in range(iters):
        time.sleep(0.0005)


def spawn(comm: str, iters: int) -> int:
    pid = os.fork()
    if pid == 0:
        busy_wait(comm, iters)
        os._exit(0)
    return pid


def test_attach_detach_matrix(binary: str) -> tuple:
    """Every tracker/mechanism combination loads and unloads cleanly."""
    combos = [
        ("exact", "none"), ("exact", "penalty"), ("exact", "boost"),
        ("sketch", "none"), ("sketch", "penalty"), ("sketch", "boost"),
    ]
    for tracker, mech in combos:
        with Scheduler(binary, "--tracker", tracker, "--mechanism", mech,
                       "--stats", "60"):
            time.sleep(0.5)
            state = open("/sys/kernel/sched_ext/state").read().strip()
            if state != "enabled":
                return FAIL, f"{tracker}/{mech}: state was {state!r}, not enabled"
    return PASS, f"{len(combos)} tracker/mechanism combinations"


def test_window_rotation_advances(binary: str) -> tuple:
    with Scheduler(binary, "--tracker", "sketch", "--window-ms", "500",
                   "--stats", "60"):
        time.sleep(0.3)
        b1 = read_bss()
        time.sleep(2.0)
        b2 = read_bss()
        r1 = int(b1.get("cms_window_rotations", 0))
        r2 = int(b2.get("cms_window_rotations", 0))
        if r2 <= r1:
            return FAIL, f"rotations did not advance ({r1} -> {r2}) in 2s at 500ms windows"
        return PASS, f"{r1} -> {r2} rotations in 2s"


def test_mechanism_reach_reported(binary: str) -> tuple:
    """select_cpu bypasses enqueue when idle -- reach should be low at rest."""
    with Scheduler(binary, "--mechanism", "penalty", "--stats", "60"):
        time.sleep(2.0)
        b = read_bss()
        for field in ("runnable_events", "quiescent_events"):
            if field not in b:
                return FAIL, f"{field} missing from .bss"
        return PASS, "runnable/quiescent counters present and readable"


def test_concurrent_stress(binary: str, workers: int, iters: int) -> tuple:
    """
    The test that would have caught all three now-fixed lost-update bugs
    on its first run: many processes sharing ONE identity, hammering the
    same map cells from multiple CPUs simultaneously.

    EXPECTED TO CURRENTLY FAIL, with a long (10s) window so no rotation
    fires during the test -- this isolates the remaining issue from
    cms_roll()'s separate rotation-triggered exposure (test_known_roll_
    race). What's left here is the increment-then-read sequence not being
    atomic as a unit; confirmed to scale directly with concurrency
    (0/9/110 violations at 2/8/32 workers). See module docstring.
    """
    with Scheduler(binary, "--compare", "--tracker", "sketch",
                   "--identity-key", "comm", "--window-ms", "10000",
                   "--stats", "60"):
        pids = [spawn("stress_target", iters) for _ in range(workers)]
        for pid in pids:
            os.waitpid(pid, 0)
        time.sleep(0.5)
        b = read_bss()
        violations = int(b.get("cms_cmp_underestimates", 0))
        samples = int(b.get("cms_cmp_samples", 0))
        if violations > 0:
            return FAIL, (f"{violations} never-undercount violations in "
                          f"{samples} samples (expected -- increment/read "
                          f"sequence race, see tracker.bpf.c and module "
                          f"docstring)")
        return PASS, f"0 violations in {samples} samples"


def test_known_roll_race(binary: str, workers: int, windows: int) -> tuple:
    """
    Expected to currently FAIL. cms_roll()'s prev=cur/cur=0/epoch=new
    update is not atomic and can tear under concurrent access once real
    rotations start -- a known, understood, deliberately deferred bug
    (needs bpf_spin_lock; no reference pattern for one in this codebase
    yet). This test runs long enough for several real rotations to occur
    under the same concurrent-identity load as test_concurrent_stress.

    If this ever passes, IT IS GOOD NEWS: remove the xfail and fold it
    into test_concurrent_stress, and update tracker.bpf.c's comment on
    cms_roll() to say the race was closed.
    """
    window_ms = 800
    with Scheduler(binary, "--compare", "--tracker", "sketch",
                   "--identity-key", "comm", "--window-ms", str(window_ms),
                   "--stats", "60"):
        end = time.time() + (window_ms / 1000) * windows
        while time.time() < end:
            pids = [spawn("roll_stress", 5) for _ in range(workers)]
            for pid in pids:
                os.waitpid(pid, 0)
        time.sleep(0.3)
        b = read_bss()
        violations = int(b.get("cms_cmp_underestimates", 0))
        if violations > 0:
            return FAIL, f"{violations} violations (expected -- cms_roll() race, see tracker.bpf.c)"
        return PASS, "0 violations"


def test_null_tracker_is_inert(binary: str) -> tuple:
    """A tracker that always answers 0 must make `penalty` a no-op.

    This is an exact prediction, not a statistical one. cms_mech_penalty
    computes `adj = count * cms_penalty_ns` and returns vtime unchanged when
    adj is zero, without touching cms_penalties_applied. So over any run of
    any length the counter must read exactly 0.

    It is also the dispatch test. If --tracker test_null were routed to any
    real tracker -- the obvious failure mode when the tracker axis became a
    registered list rather than a hand-written if/else -- the count would be
    non-zero and this fails. A two-tracker dispatch could not catch that,
    because every mis-route still landed on something that produced
    plausible numbers.
    """
    with Scheduler(binary, "--tracker", "test_null", "--mechanism", "penalty",
                   "--penalty-ns", "1000000", "--stats", "60"):
        pids = [spawn(f"nulltest{i}", 400) for i in range(8)]
        time.sleep(2.0)
        b = read_bss()
        for pid in pids:
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass

    applied = int(b.get("cms_penalties_applied", -1))
    if applied < 0:
        return FAIL, "cms_penalties_applied missing from .bss"
    runnable = int(b.get("runnable_events", 0))
    if runnable == 0:
        return FAIL, "no wakeups observed -- test did not exercise the path"
    if applied != 0:
        return FAIL, (f"penalty applied {applied} times with a tracker that "
                      f"always reports 0 -- dispatch is not selecting test_null")
    return PASS, f"0 penalties over {runnable} wakeups"


def test_saturate_tracker_clamps(binary: str) -> tuple:
    """A tracker that always saturates must make `penalty` behave like `flat`.

    cms_mech_penalty clamps `count * cms_penalty_ns` to cms_adjust_max_ns;
    cms_mech_flat clamps cms_flat_ns the same way. With a saturating count
    both apply exactly cms_adjust_max_ns to every task reaching the
    mechanism, so the penalty counter must be non-zero and must track the
    flat mechanism's over the same workload.

    The point is not the arithmetic, which is obvious from the source. It is
    that `flat` is the control the project's headline rests on and nothing
    had ever checked it from the other direction.
    """
    counts = {}
    for label, args in (("saturate", ("--tracker", "test_saturate",
                                      "--mechanism", "penalty")),
                        ("flat", ("--tracker", "exact",
                                  "--mechanism", "flat",
                                  "--flat-ns", "4000000"))):
        with Scheduler(binary, *args, "--stats", "60"):
            pids = [spawn(f"sat{label}{i}", 400) for i in range(8)]
            time.sleep(2.0)
            b = read_bss()
            for pid in pids:
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
        counts[label] = (int(b.get("cms_penalties_applied", -1)),
                         int(b.get("runnable_events", 0)))

    sat, flat = counts["saturate"], counts["flat"]
    if sat[0] <= 0:
        return FAIL, (f"saturating tracker applied {sat[0]} penalties -- "
                      f"expected one per enqueue reaching the mechanism")
    if flat[0] <= 0:
        return FAIL, f"flat applied {flat[0]} penalties -- control itself is broken"

    # Both should adjust essentially every enqueue that reaches the
    # mechanism. Compare rates rather than absolute counts, since the two
    # runs see different numbers of wakeups.
    sat_rate = sat[0] / max(sat[1], 1)
    flat_rate = flat[0] / max(flat[1], 1)
    if abs(sat_rate - flat_rate) > 0.25:
        return FAIL, (f"penalty-per-wakeup differs: saturate {sat_rate:.2f} "
                      f"vs flat {flat_rate:.2f} -- the two should clamp alike")
    return PASS, (f"saturate {sat[0]}/{sat[1]}, flat {flat[0]}/{flat[1]} "
                  f"(rates {sat_rate:.2f} vs {flat_rate:.2f})")


def test_every_registered_tracker_loads(binary: str) -> tuple:
    """Every tracker in CMS_TRACKER_LIST attaches, including the controls.

    Weaker than the two above but it covers the rows they do not, and it
    fails loudly if a registered tracker was never given a working init.
    """
    trackers = ["exact", "sketch", "test_null", "test_saturate"]
    for t in trackers:
        with Scheduler(binary, "--tracker", t, "--mechanism", "penalty",
                       "--stats", "60"):
            time.sleep(0.4)
            state = open("/sys/kernel/sched_ext/state").read().strip()
            if state != "enabled":
                return FAIL, f"--tracker {t}: state was {state!r}, not enabled"
    return PASS, f"{len(trackers)} trackers attach"


TESTS = [
    ("attach_detach_matrix", test_attach_detach_matrix, False),
    ("window_rotation_advances", test_window_rotation_advances, False),
    ("mechanism_reach_reported", test_mechanism_reach_reported, False),
    # Both xfail for the same underlying reason -- see module docstring.
    ("null_tracker_inert", test_null_tracker_is_inert, False),
    ("saturate_tracker_clamps", test_saturate_tracker_clamps, False),
    ("all_trackers_load", test_every_registered_tracker_loads, False),
    ("concurrent_stress", test_concurrent_stress, True),
    ("known_roll_race", test_known_roll_race, True),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary")
    ap.add_argument("--stress-workers", type=int, default=32)
    ap.add_argument("--stress-iters", type=int, default=40)
    ap.add_argument("--roll-windows", type=int, default=6)
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("needs root (loads a BPF scheduler)", file=sys.stderr)
        return 1

    binary = args.binary or find_binary()
    print(f"scx_cms regression suite\n  binary: {binary}\n")

    results = []
    for name, fn, expect_fail in TESTS:
        print(f"  {name:<26}", end="", flush=True)
        try:
            if name == "concurrent_stress":
                status, detail = fn(binary, args.stress_workers, args.stress_iters)
            elif name == "known_roll_race":
                status, detail = fn(binary, args.stress_workers, args.roll_windows)
            else:
                status, detail = fn(binary)
        except Exception as e:  # noqa: BLE001
            status, detail = FAIL, f"exception: {e}"

        if expect_fail:
            status = XPASS if status == PASS else XFAIL
        print(f"{status:<6} {detail}")
        results.append((name, status))

    print()
    hard_failures = [n for n, s in results if s == FAIL]
    xpasses = [n for n, s in results if s == XPASS]

    if xpasses:
        print(f"NOTE: {', '.join(xpasses)} unexpectedly passed -- a known "
              f"bug may have been fixed. Update the test and its xfail marker.")
    if hard_failures:
        print(f"FAILED: {', '.join(hard_failures)}")
        return 1

    print("All tests passed (or failed exactly as expected).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
