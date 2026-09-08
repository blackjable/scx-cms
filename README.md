# scx_cms

`scx_cms` is `scx_simple`'s scheduling policy (global weighted-vtime, with
an optional FIFO mode) unmodified, plus a swappable per-task identity
abstraction (`src/bpf/identity.bpf.c`) wired into the `runnable` and
`quiescent` callbacks.

## Status

This is the **exact-counter tier** of the study described in
`.claude/sched_ext_phase2_handoff/` at the repo root — see that folder's
`MANIFEST.md` for the full research history and design rationale before
changing anything here. The Count-Min Sketch tracker it will be compared
against does not exist yet.

What exists today:

- `task_identity()` resolves a task to a PID, TGID, or FNV-1a hash of
  `comm`, selectable via `--identity-key` (default: `pid`). Which of the
  three to actually use is an open, evidence-based decision — not resolved
  here on purpose (see the delivery plan's Section 2: `comm` is
  self-settable by a task, which matters once a hash-collision attack
  against the tracker is a demonstrated risk).
- An exact per-identity wakeup counter with rotating dual-buffer windowing
  (`tracker.bpf.c`), porting the scheme validated in Phase 1 — a query sums
  the current and previous window, older data is discarded. Window length
  is set by `--window-ms`.
- A swappable mechanism (`mechanism.bpf.c`) turning that count into a
  scheduling decision: `--mechanism none|penalty|boost`. **Neither penalty
  nor boost is validated.** Phase 1 found no measurable sketch-vs-exact
  difference under penalty, and never successfully tested an oracle-free
  boost at all; `boost` here is a first attempt awaiting evaluation, not a
  port of something known to work.
- No sketch and no adversarial mitigation yet — those come from
  `.claude/sched_ext_phase2_handoff/02_validated_python_code/` in a later
  step.

## Usage

```
scx_cms [--fifo] [--identity-key pid|tgid|comm]
        [--mechanism none|penalty|boost] [--window-ms MS]
        [--penalty-ns N] [--boost-ns N] [--boost-threshold N]
        [--adjust-max-ns N] [--stats INTERVAL] [-d|--debug]
```

Note that `--mechanism none` leaves scheduling behaviour identical to
`scx_simple` while still tracking, which is what isolates tracking
overhead from mechanism effect.

`--fifo` and the rest of the scheduling behavior are unchanged from
`scx_simple`; see its original doc comment in `src/bpf/main.bpf.c` for
the policy description.
