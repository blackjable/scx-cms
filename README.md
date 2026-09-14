# scx_cms

An experimental `sched_ext` scheduler that tracks per-task wakeup
frequency and acts on it, built to answer one question: **can a
Count-Min Sketch replace exact per-task counters, saving memory without
hurting scheduling quality?**

Short answer: yes, with a cost. A sketch at 8.3 KB does what exact
counting needs 35.6 KB for — identical typical latency, a worse and
noisier tail. Full results, data and a rather long list of retractions
live in the research repo (see below).

## What it is

`scx_simple`'s scheduling policy (global weighted-vtime, optional FIFO)
unmodified, plus three things made swappable at **load time** rather
than compile time, so that comparisons hold everything else constant:

| axis | flag | options |
|---|---|---|
| how counts are stored | `--tracker` | `exact` (LRU hash), `sketch` (Count-Min) |
| what a "task" is | `--identity-key` | `pid`, `tgid`, `comm` |
| what the count does | `--mechanism` | `none`, `penalty`, `boost`, `flat` |

Both trackers are compiled in and the verifier eliminates the unselected
branch, so switching `--tracker` changes the counting method and nothing
else. That property is what makes the central comparison meaningful.

`--mechanism flat` is the count-blind control: it applies the same vtime
perturbation while ignoring the tracked count entirely. It exists because
comparing `penalty` against `none` conflates *consulting the count* with
*perturbing scheduling at all* — and when that control was finally built,
it reproduced about 82% of what had looked like a 6.8x win for tracking.

## Building

**This repository is not standalone.** `Cargo.toml` depends on
`scx_utils` and `scx_cargo` by relative path, and the BPF build uses
scx's tooling. Drop it into an scx checkout:

```
git clone https://github.com/sched-ext/scx.git
git clone <this repo> scx/scheds/experimental/scx_cms
cd scx && cargo build -p scx_cms
```

Developed against scx as of September 2026, kernel 6.19, aarch64. The
`sched_ext` support it needs landed in 6.12.

## Notable flags

```
--tracker exact|sketch        counting method (the study's variable)
--sketch-width N              columns per row (depth 2 outperformed the
--sketch-depth N              default depth 4 by 1.8x at equal memory)
--max-tracked N               exact tracker's entry count
--mechanism none|penalty|boost|flat
--identity-key pid|tgid|comm
--compare                     run BOTH trackers over the same wakeups and
                              report divergence, max overshoot, and any
                              never-undercount violations
--plain-map                   back the exact tracker with a plain hash
                              instead of an LRU (see below)
--hash-mix                    extra avalanche before the modulo
--conservative                conservative update (see caveat below)
--stats N                     periodic counters, including mechanism reach
```

## Two findings about BPF, not about sketches

**Bounded maps fail in different shapes, and only one failure is
legible.** Under overcommitment an `LRU_HASH` thrashes uniformly —
nothing accumulates, every query reads near 1 — while a plain
`BPF_MAP_TYPE_HASH` of identical capacity locks in whichever keys
arrived first, letting those reach ~200 while 83% of queries return
zero. Neither is usable below its working set, but a zero from the plain
hash means *not tracked*, where a low count from the LRU could equally
mean an idle task. That difference is what `--plain-map` exists for: it
is how you tell a tracker that has stopped working from one that is
working on quiet tasks.

> **Retracted:** an earlier version of this section claimed `LRU_HASH`
> stops behaving like an LRU when the map is small, and blamed BPF's
> per-CPU free lists. The measurements were right and the mechanism was
> invented. A 42-entry LRU retains counts normally with 8 or 20
> identities (medians 843.8 and 410.2 across five runs) and collapses
> only at 100 or 300 — a 164x separation — so the failure tracks
> *overcommitment* rather than map size, which is what any LRU does
> below its working set, and not news about BPF. The
> withdrawn prediction that the threshold scales with CPU count goes
> with it. See `REVISIONS.md` revision 12 in the research repository.

**Conservative update cannot be implemented safely here.** It requires
reading all *d* cells, taking the minimum and writing back atomically;
each cell needs its own `bpf_map_lookup_elem`; and the verifier rejects
a lock held across those calls with *"function calls are not allowed
while holding a lock"*. The `--conservative` implementation is therefore
lock-free and **races observably**, producing thousands of
never-undercount violations in every run. No rate is quoted because none
replicates: the same configuration gave 1,749 and then 1,036, and a
neighbouring variant moved 197 to 1,750. One violation is enough — that
guarantee is the reason to choose this structure. Included so the
measurement can be reproduced, not because it is usable.

## Known open issues

- **Increment-then-read is not atomic as a unit.** The regression suite
  in `tests/` carries this as an expected failure. Phase 6 measurements
  deliberately used distinct churn identities to keep this bug out of the
  results, which means the same-identity concurrent path is not exercised
  by any of them.
- `--conservative` is unsound, as above.

## Results, data, and what was retracted

The research repository holds the paper draft, the benchmark harnesses,
the raw output of every run, and a record of thirteen claims that were
made and then withdrawn — each tied to the file that produced it and the
file that overturned it.

The retractions are worth reading before trusting any number here. Eight
of the thirteen were caused by a faulty instrument rather than a faulty
hypothesis, and the controls that eventually caught them (a do-nothing
reference condition, a count-blind control) are reproducible with the
flags above.

Four were a different failure: the measurements were correct and an
untested mechanism was attached to them — including the one retracted
above, in this file, and the condition-ordering bias that reached a
paper and a blog post before a controlled test found no such effect.
