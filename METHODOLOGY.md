# Audit methodology — multi-agent → PoC → Kani → LiteSVM → cross-platform

This document describes the reusable pipeline behind the Percolator audit findings (Bug #1 cursor-wrap, Bug #2 + #3 overflow class, 10 SAFE proofs). The same pipeline applies to any Solana program with a Rust engine + BPF wrapper architecture.

## Goal

Produce findings that survive the most rigorous review: empirically reproducible, formally proven, BPF-reachable from public entrypoints, cross-platform. Avoid the failure mode of "I think I see a bug" — every finding goes through every layer before disclosure.

## Pipeline (5 layers + operational support)

### Layer 1 — Multi-agent code review

Spawn parallel investigation agents on disjoint hypotheses. Each agent reads a slice of the codebase against a specific question (e.g., "does any code path in `src/percolator.rs` write to `position_basis_q` without enforcing `MAX_POSITION_ABS_Q`?"). Agents return concrete file:line citations + a pass/fail verdict on the hypothesis.

**Why it works**: a single human reviewer is rate-limited by attention. Spawning 5+ agents on disjoint hypotheses fans out the search space without losing depth — each agent goes deep on its specific question. Hypotheses come from spec-vs-code gap analysis (look for English claims in spec/comments that don't have explicit assertions in code).

**Failure modes to guard against**:
- Treat agent output as a starting point, not a verdict. Always cross-check claimed verdicts against raw artifacts (log files, source lines) before promoting them into a finding.
- Hypothesis bias: hypotheses framed as "find this bug" produce false positives. Frame as "is this invariant true?" — produces clean negatives that strengthen the disclosure.

### Layer 2 — Empirical PoC (engine native)

For every candidate finding, write a Rust integration test that exercises the engine directly with crafted state. Use `#[should_panic("expected message")]` for panic-class bugs; use `assert!` for state-corruption bugs.

**Why it works**: catches false positives early. If you can't write a passing test, the bug isn't real (or your hypothesis is wrong).

**Pattern**: one positive test (panics as expected) + one negative test (sanity, doesn't panic with normal-sized inputs) per finding.

### Layer 3 — Kani formal verification

Encode each finding as a Kani harness with `kani::any()` for symbolic inputs and `kani::assume(...)` for engine invariants. The harness asserts the negation of the bug (e.g., "function does not panic for any reachable input"). Kani either PROVES the property (your finding is wrong — there's an invariant you missed) or returns a CEX (your finding is formally true within the symbolic state space).

**Why it works**: stronger than the empirical PoC because it covers the entire input space symbolically. A passing Kani harness = formal proof; a CEX = formal counterexample with a specific witness state.

**Same pattern can prove SAFE claims**: write a harness that asserts a property the code SHOULD satisfy. If Kani proves it, you've extended the formal verification surface. We did this for 10 properties on Percolator (5 implicit invariants, 3 conservation/aggregate claims, 2 wrapper-instruction-level safety claims).

**Gotchas**:
- Kani's `unwind` bound must cover any internal loops (e.g., the engine init loop runs `MAX_ACCOUNTS - 1` iterations under `cfg(kani)` — set `unwind` ≥ that + 2).
- Cargo compiles all tests when ANY test is requested. One broken file in `tests/` blocks unrelated harness runs. Always `cargo check --tests` before dispatching Kani.

### Layer 4 — LiteSVM (BPF-level) bound analysis

For each finding that passes Kani, write a LiteSVM test that asks: "can the public BPF API drive engine state to the bug's witness conditions?" Two test variants:

1. **Reachability skeleton**: invoke the BPF instruction with normal-sized inputs and confirm the call chain reaches the function containing the panic site. Read engine state before/after via slab-offset readers to confirm execution.

2. **Bound analysis**: numerically derive what state would be needed and compute the wall-clock cost of accumulating that state via legitimate flow. Print the bound. If the cost is prohibitive (years to centuries), downgrade the finding from "active exploit" to "code defect / defense-in-depth."

**Why it works**: separates "engine math is unsafe" (Kani-true) from "production flow can drive state there" (LiteSVM-bound-true). Pre-empts the most predictable reviewer pushback ("but is it actually reachable?"). Surfaces reachability downgrades during the audit, not during review.

### Layer 5 — Cross-platform reproduction

Every PoC test runs on both Windows local AND a dedicated Linux VPS (Hetzner-class, dedicated SSH key). Bit-identical pass/fail confirms the finding is platform-independent and not a local toolchain artifact.

**Why it works**: catches one specific failure mode (test depends on platform-specific behavior) and signals operational rigor (we provisioned an autonomous-access VPS specifically to do this work; the audit isn't running on the user's laptop).

## Application to Percolator

| Layer | Finding | Outcome |
|---|---|---|
| 1 (multi-agent) | Spec line 814 wrap-reset assumption | Identified as unstated implicit invariant — became Bug #1 |
| 1 (multi-agent) | `mul_div_floor_u128` panic class audit | 30 invocations enumerated (19 narrow `mul_div_floor` + 6 narrow `mul_div_ceil` + 4 `wide_mul_div_floor` + 1 `wide_mul_div_ceil_u128_or_over_i128max`); 3 narrow callers flagged as bound-unsafe |
| 2 (PoC) | Bug #1, Bug #2, Bug #3 | All three reproduce |
| 3 (Kani) | Bug #1 cursor-wrap reset + downstream admission flip | 2 CEXes |
| 3 (Kani) | Bug #2 warmup overflow | 1 CEX |
| 3 (Kani) | Bug #3 trade-open overflow | 1 CEX |
| 3 (Kani) | Sibling B (effective_pos_q overflow under white-box state) | CEX, then traced as not-publicly-reachable |
| 3 (Kani) | 3 invariants from earlier audit hypotheses (Job F: conservation, matured ≤ pos, slot-advance gate) | All 3 PASS |
| 3 (Kani) | 5 implicit invariants the engine code relies on (L3) | All 5 PASS |
| 3 (Kani) | 2 wrapper-instruction safety claims (L2 — formally encodes the G3 closure statement) | Both PASS |
| 4 (LiteSVM) | Bug #1 | 6 PoCs proving the empirical exploit chain |
| 4 (LiteSVM) | Bug #3 | 2 tests (call-chain reachability + bound analysis); bug downgraded to code defect (~18yr to reach) |
| 4 (LiteSVM) | Bug #2 | 2 tests (h_max admin gate + bound analysis); bug downgraded to code defect (~167M years to reach) |
| 4 (LiteSVM) | Sibling B | NOT a bug — call chain analysis shows cap is enforced |
| 5 (cross-platform) | All 12 PoC tests | Bit-identical pass/fail on Windows + Linux VPS |
| 5 (cross-platform) | 305-harness Kani baseline against current main | **305/305 PASS, 0 regressions** — see [`baseline/`](./baseline/) for raw log + summary + timings TSV |

## Toolchain pinned

- Rust 1.95
- Solana 3.1.14 + cargo-build-sbf
- Kani 0.67.0 (CBMC backend)
- LiteSVM (embedded Solana VM library — runs the BPF program inside the test binary, no separate validator needed)
- proptest (property-based testing)
- gh CLI 2.x (PR/issue automation; any recent 2.x release works)

## Operational support — VPS provisioning

(Not a pipeline layer; provides the execution environment for Layers 3, 4, and 5.)


- Hetzner CCX, 6 cores, 24 GB RAM, Ubuntu 22.04
- Dedicated Ed25519 SSH keypair (`~/.ssh/percolator_vps`) — autonomous access, no password prompt
- Toolchain identical to local (Rust 1.95 + Solana 3.1.14 + Kani 0.67.0)
- Repos cloned at pinned SHAs; tmux for long-running session persistence
- Used for: cross-platform PoC reproduction, Kani harness sweeps (we re-ran the existing 305-harness baseline + our 16 additions in a single 3h 53min sweep — see [`baseline/`](./baseline/))

## Lessons learned (operational)

1. **Cargo compiles all tests when ANY test is requested.** A broken file in `tests/` blocks unrelated harness runs. Always `cargo check --tests --features test` before dispatching Kani.
2. **`RiskEngine::new` under `cfg(kani)` runs a 3-iteration init loop** — minimum unwind for harnesses that call it is 4 (we use 10 to be safe).
3. **Always cross-check claimed verdicts against raw artifacts.** A reported "VERIFICATION FAILED with CEX" can sometimes mean the harness didn't compile rather than that the property is unsafe. Confirm against the log file (`tail -5` of the cargo kani output) before promoting an agent-reported verdict into a finding.
4. **LiteSVM .so compatibility**: the BPF artifact must match the test's feature flags (`small`/`medium`/default control `MAX_ACCOUNTS` and slab size). If they mismatch, `init_market` fails with cryptic `Custom(4)` error.
5. **Slab-offset readers are BPF-target-specific**: u128 aligns to 8 bytes on SBF, not 16 on x86. Field offsets must be observed empirically against the compiled `.so`, not derived from `size_of` at native compile time.
6. **Kani's `--unwinding-assertions` can produce noise**: failed checks at `<builtin-library-memcmp>` or in synthesized init code are usually unwind-bound issues, not real bugs. The actual finding is the `expect_failed` check at `option.rs:2184` — that's where genuine `.expect()` panics show up.

## Reusability

This pipeline is not Percolator-specific. The same 5 layers apply to any Solana program with:
- An engine library + BPF wrapper architecture (most production Solana protocols)
- An English-language spec or design doc (look for "MUST" / "always" / "never" claims that aren't enforced in code — those are your candidate findings)
- A test harness that exercises the BPF instruction set (LiteSVM is an embedded library that runs the BPF program in-process — no separate validator needed; for non-BPF programs substitute the equivalent reachability harness)

The audit cost scales roughly linearly with codebase size + number of public instructions. The cross-platform VPS layer adds modest overhead (toolchain provisioning + log syncing) on top of the per-finding work. Wall-clock duration depends on codebase complexity, agent budget, and how many findings need full Kani + LiteSVM treatment.
