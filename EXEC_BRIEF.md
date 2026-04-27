# Percolator audit — one-page brief

**Auditor**: Kirill Sakharuk (`Copenhagen0x`) | **Date**: 2026-04-26 | **Engine sha**: `5940285` | **Wrapper sha**: `c447686`

## What we found

| # | Finding | Class | Strongest evidence |
|---|---|---|---|
| **1** | Cursor-wrap atomically resets consumption budget without absorbing volatility (`src/percolator.rs:6155`) | **Active bug** | 6 LiteSVM PoCs + 2 Kani CEXes |
| **2** | `advance_profit_warmup` panics on `mul_div_floor_u128` overflow (`src/percolator.rs:4680`) | Code defect — Kani-true but ~167M years to reach via legitimate flow at default caps | Native PoC + Kani CEX + LiteSVM bound analysis |
| **3** | `account_equity_trade_open_raw` panics on `mul_div_floor_u128` overflow (`src/percolator.rs:3915`) | Code defect — Kani-true but ~18 years to reach via legitimate flow at default caps | Native PoC + Kani CEX + LiteSVM call-chain test + LiteSVM bound analysis |
| Sibling B | `effective_pos_q_checked` overflow under white-box state (`src/percolator.rs:2642`) | Not a bug — cap enforced at all real callers | Audit trail (negative result) |

## Bonus deliverables

- **10 new Kani SAFE proofs** — formalize claims your code already satisfies. Two specifically prove your G3 closure statement: "CU exhaustion does not silently commit a partial Phase 2 sweep; the transaction aborts and rolls back."
- **Re-run of your full 305-harness Kani baseline** against current main → **305/305 PASS, 0 regressions**.
- **100K + 1M case proptest sweeps** across 10 fuzzers → all PASS.

## Single uniform fix (closes Bugs #2, #3, Sibling B)

Replace `mul_div_floor_u128` with `wide_mul_div_floor_u128` (U256 intermediate, already in your codebase) at three engine sites: 4680, 3915, and 2642. Output range unchanged because the quotient is bounded by the smaller operand. **Cost: zero — the helper exists.**

Exact diff in [`./RECOMMENDED_PATCH.md`](./RECOMMENDED_PATCH.md).

## Scope notes

- Bug #1 surface is unconditional; value-extraction is config-conditional (`h_min < h_max` markets).
- Bugs #2 + #3 are NOT exploitable at production caps — disclosed as defense-in-depth + uniform fix recommendation.
- Sibling B is NOT a bug — disclosed as defense-in-depth recommendation only.

## Methodology

Multi-agent code review → empirical PoC → Kani formal verification → LiteSVM BPF-level reachability → cross-platform reproduction (Windows + Linux VPS). Documented in `METHODOLOGY.md`. Reusable for any Solana program.

## Files (relative to research repo root)

| | Path |
|---|---|
| Disclosure (full) | [`./DISCLOSURE.md`](./DISCLOSURE.md) |
| Methodology | [`./METHODOLOGY.md`](./METHODOLOGY.md) |
| Raw Kani results | [`./RAW_KANI_RESULTS.md`](./RAW_KANI_RESULTS.md) |
| Recommended patch (exact diff) | [`./RECOMMENDED_PATCH.md`](./RECOMMENDED_PATCH.md) |
| Bug #1 | `tests/wrapper/test_v6_cursor_wrap_consumption_reset.rs`, `tests/wrapper/test_v8_cursor_wrap_natural_drift.rs`, `tests/engine/proofs_v9_findings_pack.rs` (h1, h5) |
| Bug #2 | `tests/engine/test_v9_warmup_overflow.rs`, `tests/engine/proofs_v9_warmup_overflow.rs`, `tests/wrapper/test_v11_l1_warmup_overflow_litesvm.rs` |
| Bug #3 | `tests/engine/test_v11_l1_trade_open_overflow.rs`, `tests/engine/proofs_v11_l1_overflow_siblings.rs`, `tests/wrapper/test_v11_l1_trade_open_overflow_litesvm.rs` |
| 10 SAFE proofs | `tests/engine/proofs_v9_findings_pack.rs`, `tests/engine/proofs_v11_l2_catchup_e2e.rs`, `tests/engine/proofs_v11_l3_implicit_invariants.rs` |
| Baseline re-run | [`./baseline/`](./baseline/) |
