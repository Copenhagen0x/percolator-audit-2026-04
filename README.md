# Percolator audit — April 2026

Independent security audit of the Percolator perpetual DEX (engine + BPF wrapper).

**Audit window**: April 2026
**Engine pin**: [`aeyakovenko/percolator`](https://github.com/aeyakovenko/percolator) @ `master` sha `5940285`
**Wrapper pin**: [`aeyakovenko/percolator-prog`](https://github.com/aeyakovenko/percolator-prog) @ `main` sha `c447686`
**Auditor**: Kirill Sakharuk ([@Copenhagen0x](https://github.com/Copenhagen0x))

> **Continuous monitoring**: this target is audited 24/7 by [SENTINEL](https://github.com/Copenhagen0x/audit-pipeline-cli) — every upstream commit on the engine or wrapper triggers a multi-agent hunt cycle.

## TL;DR

| # | Finding | Class |
|---|---|---|
| 1 | Cursor-wrap atomically resets consumption budget without absorbing volatility (`engine:6155`) | **Active bug** |
| 2 | `advance_profit_warmup` panics on `mul_div_floor_u128` overflow (`engine:4680`) | Code defect — Kani-true but ~167M years to reach via legitimate flow at default caps |
| 3 | `account_equity_trade_open_raw` panics on `mul_div_floor_u128` overflow (`engine:3915`) | Code defect — Kani-true but ~18 years to reach via legitimate flow at default caps |
| Sibling B | `effective_pos_q_checked` overflow under white-box state (`engine:2642`) | Not a bug — cap enforced at all real callers; defense-in-depth recommendation only |

Plus:
- **10 new Kani SAFE proofs** formalizing claims your code already satisfies (including 2 that formally prove your G3 closure statement at the wrapper level).
- **Re-run of your full 305-harness Kani baseline** against current main → **305/305 PASS, 0 regressions** ([baseline/](./baseline/)).
- **100K + 1M case proptest sweeps** across 10 fuzzers — all PASS.

The single uniform fix (`mul_div_floor_u128` → `wide_mul_div_floor_u128`, U256 helper that already exists in your codebase) closes Bugs #2, #3, and the Sibling B concern in one swap.

## How to read this repo

| Path | What it is |
|---|---|
| [`DISCLOSURE.md`](./DISCLOSURE.md) | Canonical disclosure document — the full write-up with Kani CEXes, LiteSVM bound analyses, and call chains |
| [`EXEC_BRIEF.md`](./EXEC_BRIEF.md) | One-page reference — every finding in one table |
| [`METHODOLOGY.md`](./METHODOLOGY.md) | The 5-layer audit pipeline (multi-agent → PoC → Kani → LiteSVM bound → cross-platform) |
| [`tests/engine/`](./tests/engine/) | All 7 new files for `aeyakovenko/percolator` — 5 Kani harnesses + 2 native PoCs |
| [`tests/wrapper/`](./tests/wrapper/) | All 5 new files for `aeyakovenko/percolator-prog` — 4 LiteSVM PoCs + 1 regression-guard test |
| [`RAW_KANI_RESULTS.md`](./RAW_KANI_RESULTS.md) | Verification times + verdicts for the 10 new SAFE proofs |
| [`RECOMMENDED_PATCH.md`](./RECOMMENDED_PATCH.md) | Exact `git diff` for the uniform overflow-class fix (closes Bug #2 + Bug #3 + Sibling B in 3 one-token swaps) |
| [`baseline/`](./baseline/) | Re-run of the full 305-harness Kani baseline against current main: **305/305 PASS, 0 regressions** |
| [`LICENSE`](./LICENSE) | CC BY 4.0 — full text and scope notes |

## How to reproduce

Each test file's docstring has the precise reproduction steps. In short:

**Native engine tests** (Bugs #2, #3 panic PoCs, Bug #1 Kani CEXes, all 10 SAFE proofs):
```bash
cd <clone of aeyakovenko/percolator @ 5940285>
cp /path/to/tests/engine/*.rs tests/
cargo test --features test --test test_v9_warmup_overflow --test test_v11_l1_trade_open_overflow
cargo kani --tests --features test --harness <harness_name>
```

**LiteSVM tests** (Bug #1 reproducers + Bugs #2/#3 bound analysis):
```bash
cd <clone of aeyakovenko/percolator-prog @ c447686>
cp /path/to/tests/wrapper/*.rs tests/

# Build the BPF artifact (one-time per source change):
cargo build-sbf
# OR for the small-MAX_ACCOUNTS variant (faster compile, MAX_ACCOUNTS=256):
#   cargo build-sbf --features small

# Run the tests (default-MAX_ACCOUNTS=4096 build is the one verified locally + on VPS):
cargo test --test test_v6_cursor_wrap_consumption_reset
cargo test --test test_v8_cursor_wrap_natural_drift
cargo test --test test_v11_l1_trade_open_overflow_litesvm
cargo test --test test_v11_l1_warmup_overflow_litesvm
# If you built with --features small above, also pass --features small here.
```

**Cross-platform reproduction**: every PoC test in this repo was run on both Windows local (where it was authored) and a Linux VPS (Hetzner CCX, dedicated SSH key). Bit-identical pass/fail.

## Toolchain pinned

- Rust 1.95
- Solana 3.1.14 + cargo-build-sbf
- Kani 0.67.0 (CBMC backend, nightly-2025-11-21 toolchain)
- LiteSVM (embedded Solana VM library — runs the BPF program inside the test binary, no separate validator needed)
- proptest

## Scope notes (read before judging severity)

- **Bug #1 surface is unconditional**; value-extraction surface is config-conditional (`h_min < h_max` markets).
- **Bugs #2 and #3 are NOT exploitable at production caps.** The Kani CEXes prove the engine math fails on engine-permitted state, but the LiteSVM bound analyses show that legitimate trade flow at default caps cannot drive state to the unsafe range in any realistic time horizon. They are disclosed as defense-in-depth + uniform-fix recommendation, not as active threats.
- **Sibling B is NOT a bug.** Disclosed for audit-trail completeness as a defense-in-depth recommendation only.
- The 10 new Kani SAFE proofs formally verify conservation, the matured ≤ pos invariant, and 8 other implicit invariants against current main — see [DISCLOSURE.md](./DISCLOSURE.md) for the full list.

## License

Documentation in this repo is released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Test code is released under the same license as the upstream repos it targets (MIT/Apache, per `aeyakovenko/percolator` and `aeyakovenko/percolator-prog`).

## Contact

For questions, corrections, or follow-up: open an issue on this repo or contact via the auditor's GitHub profile linked above.
