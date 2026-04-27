# Percolator Audit Disclosure — narrower reproducer + overflow code-defect class + formal SAFE proofs

**Auditor**: Kirill Sakharuk (GitHub: `Copenhagen0x`)
**Date**: 2026-04-26
**Engine pin**: `aeyakovenko/percolator @ master` (sha `5940285`)
**Wrapper pin**: `aeyakovenko/percolator-prog @ main` (sha `c447686`)
**Method**: Multi-agent code review → empirical PoC → Kani formal verification → LiteSVM bound analysis → cross-platform reproduction

---

## What this disclosure delivers

**One active bug (Bug #1)**, **two engine-level code defects (Bugs #2, #3)** in a single overflow pattern (both Kani-confirmed but practically unreachable at default caps per LiteSVM bound analysis), **ten new Kani SAFE proofs** (formally proving claims your code already satisfies but didn't have explicit harnesses for), and a re-run of your full 305-harness Kani baseline against current main showing **305/305 PASS, 0 regressions**.

Direct response to your Issue #54 closure invitation:

> "If there is a concrete state transition that commits partial progress incorrectly, please open that as a narrower reproducer."

Bug #1 below is exactly that — the cursor-wrap atomic block commits a consumption-budget reset without the corresponding volatility absorption. Bugs #2 and #3 are sibling instances of the same `mul_div_floor_u128` panic class; both have Kani CEXes confirming the math fails on engine-permitted state. The LiteSVM bound analysis on both shows neither is exploitable at production caps in any realistic time horizon, so they are disclosed as a single defense-in-depth class with a uniform fix rather than as active threats. The 10 SAFE proofs strengthen the formal-verification surface around current main.

---

## Bug #1 — Cursor-wrap atomically resets consumption budget without absorbing volatility

**Concrete state transition** (engine `src/percolator.rs`, line 6155, inside atomic block lines 6149–6158 of `keeper_crank_not_atomic`):

```rust
if sweep_end >= wrap_bound {
    self.rr_cursor_position = 0;                              // OK
    self.sweep_generation = self.sweep_generation.checked_add(1)?;  // OK
    self.price_move_consumed_bps_this_generation = 0;         // <-- BUG
} else {
    self.rr_cursor_position = sweep_end;
}
```

**Why it commits partial progress incorrectly**:

The reset implies "this is a fresh generation — start a new consumption budget." The trigger (`sweep_end >= wrap_bound`) is purely call-count arithmetic. `KeeperCrank` is permissionless and unbounded — no rate-limit, no min-interval. Same-slot/same-price cranks DON'T increment `price_move_consumed_bps_this_generation` (engine line 2854: `price_move_active = false` when `oracle_price == self.last_oracle_price`). An attacker spam-cranks at constant `(slot, price)` for FREE w.r.t. consumption, walks the cursor to wrap, and the wrap atomically zeros the consumption budget.

**Spec-vs-code gap**: spec line 814 specifies "wrap → reset budget atomically". The spec assumes "wrap = generation rollover = real-volatility window expired." The code lets an attacker DECOUPLE cursor wraparound from real volatility absorption. The implicit assumption in the spec doesn't hold under permissionless cranking.

**Downstream effect**: consumption-gate at engine lines 1792 and 1870:
```rust
if self.price_move_consumed_bps_this_generation >= threshold {
    return Ok(admit_h_max);  // SLOW LANE
}
```
After forced wrap, threshold check fails → admission returns to FAST LANE (`admit_h_min`). New positive PnL admits with shorter warmup horizon, matures faster.

**Cost**: ~$0.05 per wrap on default deployment (MAX_ACCOUNTS=4096 → 64 cranks × ~5000 lamports/tx).

**Severity**:
- **Bug surface: unconditionally reachable** in any market config — the consumption-budget reset *will* commit on any market that gets enough permissionless cranks to wrap the cursor.
- **Value extraction surface is config-conditional**:
  - Requires `params.h_min < params.h_max` (asymmetric admission pair) so that the FAST/SLOW lane choice produces materially different warmup horizons. With symmetric `h_min == h_max`, the post-wrap admission still flips lanes but the resulting horizon is identical, so there's no economic benefit to extract.
  - Requires the `admission_residual_lane` path to be reachable for the attacker's account (i.e. fresh positive PnL admission flowing through `admit_fresh_reserve_h_lock` with consumption < threshold) so the attacker actually receives the FAST-LANE horizon for their newly-introduced PnL.
- In markets that satisfy both conditions, post-wrap PnL admits with `admit_h_min` instead of `admit_h_max`, matures sooner, and becomes withdrawable on a shorter cycle than the spec's intent. The economic value scales with the size of the PnL admitted in the post-wrap window and the gap between `h_min` and `h_max`.

**Empirical evidence** (LiteSVM, `tests/wrapper/`):
- `test_v6_cursor_wrap_consumption_reset.rs` — 4 tests against `--features small` BPF (MAX_ACCOUNTS=256)
  - Cursor offset readers verified
  - Permissionless cranks proven unbounded at same-slot AND under drifting oracle
  - **Killer test**: seed `consumption=7.7e12`, spam-crank, read back **0** post-wrap
- `test_v8_cursor_wrap_natural_drift.rs` — 2 tests against default BPF (MAX_ACCOUNTS=4096)
  - **Real oracle drift, no seeding**: consumption 5.6e11 (above 5e11 threshold) → **0** after 48 attacker spam-cranks
  - **Downstream effect proven**: admission gate took different branch post-wrap (`reserved_pnl` 291428 → 292593 — different horizon admit)

**Formal evidence** (Kani, `tests/engine/proofs_v9_findings_pack.rs`):
- `proof_h1_cursor_wrap_implies_real_volatility_absorption` → **CEX in 44s** (Kani returned witness state where wrap fires with consumption=0)
- `proof_h5_cursor_wrap_unlocks_fast_lane` → **CEX in 100s** (Kani returned witness state where post-wrap admission flips slow→fast — full exploit chain formalized)

**Suggested fix**: defer the consumption reset until real volatility absorption is observed, or rate-limit `KeeperCrank` so the wrap event is bounded by oracle-time.

---

## Bug #2 — `advance_profit_warmup` overflow — **code defect, not exploitable at default caps**

**Concrete state transition** (engine `src/percolator.rs`, line 4680):

```rust
let sched_total = if elapsed >= a.sched_horizon as u128 {
    a.sched_anchor_q
} else {
    mul_div_floor_u128(a.sched_anchor_q, elapsed, a.sched_horizon as u128)
};
```

`mul_div_floor_u128` (wide_math.rs line 1600):
```rust
pub fn mul_div_floor_u128(a: u128, b: u128, d: u128) -> u128 {
    assert!(d > 0, "mul_div_floor_u128: division by zero");
    let p = a.checked_mul(b).expect("mul_div_floor_u128: a*b overflow");  // <-- PANIC
    p / d
}
```

**Why it commits partial progress incorrectly**: the Solana tx aborts mid-step in `advance_profit_warmup`, leaving the account state untouched on-chain. But every subsequent `touch_account_live_local` / `finalize_touched_accounts_post_live` that walks this account re-triggers the panic. The account is bricked from the warmup pipeline. KeeperCrank Phase 2 RR sweep walks every account in cursor range, so the bricked account also bricks every crank that includes its idx.

**Engine math IS unsafe — Kani CEX confirms** (`tests/engine/proofs_v9_warmup_overflow.rs`):
- `proof_advance_profit_warmup_does_not_panic` → **VERIFICATION FAILED** in 1.5s — Kani returned CEX confirming the overflow panic is reachable on engine-permitted state
- Native engine PoC at `tests/engine/test_v9_warmup_overflow.rs` panics with the expected message — passes local + VPS

**Reachability bound analysis (LiteSVM, this is what matters)** (`tests/wrapper/test_v11_l1_warmup_overflow_litesvm.rs`):

Two reachability sides for `sched_anchor_q × elapsed > 2^128`:

| Side | Gate | Bound to fire overflow |
|---|---|---|
| A — `elapsed` | Admin sets `params.h_max` (no upper bound enforced by `validate_params_fast_shape`) | With sched_anchor_q at engine cap (1e32), need elapsed > 4.2M slots ≈ **~24 days** of horizon at 500ms/slot. Reasonable for long-horizon markets. |
| B — `sched_anchor_q` | Account accumulates positive PnL through trade flow | With h_max = 2^30 (~17yr-horizon at 500ms/slot), need sched_anchor_q > 2^98 ≈ 3.17e29. At default per-saturated-slot gain ≈ 3e13, slots needed ≈ 1e16 ≈ **~167 million years** of wall-clock at 500 ms/slot (2 slots/sec, conservative for Solana mainnet) |

**Reachability finding**: Bug #2 is a **real code defect** (Kani-confirmed), and the admin-side gate is open (h_max can be any u64). The state-accumulation side is prohibitive at default caps — even with admin choosing high h_max, accumulating sched_anchor_q to the unsafe range requires ~167M years of legitimate flow. **Disclosed as defense-in-depth, not as an active threat.**

**Two LiteSVM tests both PASS local + VPS**:
- `test_v11_l1_warmup_overflow_bound_analysis` — quantifies both reachability sides
- `test_v11_l1_warmup_h_max_admin_gate_documented` — documents that engine doesn't cap h_max

**Suggested fix**: replace `mul_div_floor_u128` with `wide_mul_div_floor_u128` (already in codebase, U256 intermediate). One swap closes Bug #2, Bug #3, and Sibling B uniformly. The output range is unchanged because the quotient is bounded by `sched_anchor_q ≤ MAX_ACCOUNT_POSITIVE_PNL` which fits in u128.

---

## Bug #3 — `account_equity_trade_open_raw` overflow (Bug #2 sibling) — **code defect, not exploitable at default caps**

**Concrete state transition** (engine `src/percolator.rs`, line 3914-3915):

```rust
let g_num = core::cmp::min(residual, pnl_pos_tot_trade_open);
mul_div_floor_u128(pos_pnl_trade_open, g_num, pnl_pos_tot_trade_open)  // <-- PANIC site
```

Same `mul_div_floor_u128` panic line as Bug #2 (wide_math.rs:1600).

**Public-API call chain** (verified empirically with LiteSVM PoC at `tests/wrapper/test_v11_l1_trade_open_overflow_litesvm.rs`):

1. `TradeNoCpi` BPF instruction (wrapper)
2. → `execute_trade_with_matcher` (wrapper)
3. → `execute_trade_not_atomic` (engine line 5237)
4. → `enforce_one_side_margin` (engine line 5660)
5. → `is_above_initial_margin_trade_open` (defined at engine line 3944, called from `enforce_one_side_margin` at engine line 5715)
6. → `account_equity_trade_open_raw` (defined at engine line 3865) — **PANIC at line 3915**

**Engine math IS unsafe — Kani CEX confirms** (`tests/engine/proofs_v11_l1_overflow_siblings.rs`):
- `proof_trade_open_raw_g_num_does_not_panic` → **VERIFICATION FAILED** in 12.4s — Kani returned CEX
- Native engine PoC (`tests/engine/test_v11_l1_trade_open_overflow.rs`) panics with the expected message — passes local + VPS

**Reachability bound analysis (LiteSVM, this is what matters)** (`tests/wrapper/test_v11_l1_trade_open_overflow_litesvm.rs`):

For overflow `pos_pnl × g_num > 2^128 (~3.4e38)`:
- `g_num ≤ MAX_VAULT_TVL = 1e16 (~2^54)`
- Need `pos_pnl > 3.4e22 (~2^75)`
- Engine permits `pos_pnl ≤ MAX_ACCOUNT_POSITIVE_PNL = 1e32 (~2^106)` — so the threshold is engine-permitted, but how do we get there from legitimate trade flow?
- Per saturated slot, max PnL gain ≈ notional × `max_price_move_bps_per_slot` = `1e16/IM_bps × 3 bps` = `1e17 × 3e-4 = 3e13`
- Slots needed: `3.4e22 / 3e13 ≈ 1e9 slots ≈ ~18 years of wall-clock at 500 ms/slot (2 slots/sec, conservative for Solana mainnet)`

**Reachability finding**: Bug #3 is a **real code defect** (the engine math demonstrably fails on engine-permitted state — Kani proved it, native PoC fires it), **but it is not exploitable via legitimate trade flow at default caps within any realistic time horizon**. Disclosed as a defense-in-depth class finding because the prevention-class fix is the same one that closes Bug #2.

**Two LiteSVM tests both PASS local + VPS**:
- `test_v11_l1_trade_nocpi_reaches_panic_site` — TradeNoCpi successfully traverses the call chain through `account_equity_trade_open_raw` for normal-sized inputs (call-chain reachability skeleton)
- `test_v11_l1_trade_open_overflow_bound_analysis` — quantifies the unreachability bound numerically and prints the analysis

**Suggested fix**: same as Bug #2 — replace with `wide_mul_div_floor_u128`. One swap closes Bug #2, Bug #3, and the Sibling B concern below. Cost: zero — the U256 helper already exists in your codebase.

---

## Sibling B (NOT a bug) — `effective_pos_q_checked` (engine line 2642)

For audit-trail completeness: a Kani CEX exists for `mul_div_floor_u128(abs_basis, a_side, a_basis)` at engine line 2642, but only via white-box state mutation. All real callers of `set_position_basis_q_inner` enforce `MAX_POSITION_ABS_Q` via `attach_effective_position_inner` (cap check at engine line 2263; `set_position_basis_q` invocations at lines 2255, 2269, 2271) or pass zero (`settle_side_effects_live` zero invocations at lines 2704+2737, `reconcile_resolved_not_atomic` zero invocation at line 6741). **Public-API path is safe in current code.**

**Defense-in-depth recommendation**: push the `MAX_POSITION_ABS_Q` cap check into `set_position_basis_q_inner` itself. Eliminates the entire reachability concern for any future caller that lands at line 2642 without going through `attach_effective_position`.

---

## Prevention-class fix (one fix closes Bugs #2, #3, and the Sibling-B concern)

The pattern under all three findings is identical: a `mul_div_floor_u128` site whose intermediate product can exceed `u128::MAX` even when the mathematical result fits. The codebase already has `wide_mul_div_floor_u128` (U256 intermediate) for exactly this reason.

We audited every `mul_div_floor_u128` / `mul_div_ceil_u128` invocation in `src/percolator.rs` (30 invocations total: 19 narrow `mul_div_floor_u128`, 6 narrow `mul_div_ceil_u128`, plus 5 already using wide variants — 4 `wide_mul_div_floor_u128` + 1 `wide_mul_div_ceil_u128_or_over_i128max`). Most narrow callers are bounded safely by their input domains; the unsafe sites are:

| Engine line | Function | Inputs | Worst-case product |
|---|---|---|---|
| 4680 | `advance_profit_warmup` | sched_anchor_q (1e32) × elapsed (1e19) | 1e51 |
| 3915 | `account_equity_trade_open_raw` | pos_pnl (1e32) × g_num (1e16) | 1e48 |
| 2642 | `effective_pos_q_checked` | abs_basis × a_side | 1e29 (currently safe) |

A patch that swaps these three sites (and the equivalent `mul_div_ceil_u128` sites where the bounds analysis suggests overflow) for their `wide_*` counterparts would eliminate the entire pattern.

---

## Formal SAFE proofs (10 new Kani harnesses formalizing claims your code satisfies)

Beyond the bug findings, we wrote 10 new Kani harnesses that PASS — formalizing implicit and explicit safety claims your code already satisfies. These extend your formal-verification surface.

### From Job F (proofs_v9_findings_pack.rs)
| Harness | Encodes |
|---|---|
| `proof_h2_finalize_preserves_conservation` | Agent R conservation claim |
| `proof_h3_set_pnl_with_reserve_matured_le_pos` | Agent N+C matured ≤ pos invariant |
| `proof_h4_market_slot_advance_requires_real_signal` | Agent X liveness claim |

### From v11-L2 (proofs_v11_l2_catchup_e2e.rs) — directly responds to your G3 closure
| Harness | Encodes |
|---|---|
| `proof_l2_catchup_partial_preserves_conservation` | CatchupAccrue partial sweep preserves V = I + C + P + R |
| `proof_l2_catchup_complete_advances_to_now_slot` | Slot transitions only on complete sweep |

This formally proves your G3 statement: **"CU exhaustion does not silently commit a partial Phase 2 sweep; the transaction aborts and rolls back."**

### From v11-L3 (proofs_v11_l3_implicit_invariants.rs) — implicit invariants the audit identified as worth formalizing
| Harness | Encodes implicit invariant |
|---|---|
| `proof_l3a_prepare_resolved_touch_preserves_matured` | reserved_pnl drain at lines 4432-4448 only safe when `pnl_matured_pos_tot = pnl_pos_tot` |
| `proof_l3b_begin_full_drain_reset_snapshots_correctly` | K/F snapshot before zeroing live K/F at 3352-3422 |
| `proof_l3c_empty_sweep_produces_v_equals_i` | sweep_empty_market_surplus only fires when 8 gating counters all zero |
| `proof_l3d_advance_profit_warmup_promotion_preserves_horizon_bounds` | pending→sched promotion preserves h_min ≤ horizon ≤ h_max |
| `proof_l3e_phantom_dust_bound_respects_side_cap` | dust counter bounded ≤ MAX_OI_SIDE_Q under all increment paths |

---

## Methodology + reproducibility

**Toolchain**:
- Rust 1.95 + Solana 3.1.14 + Kani 0.67.0
- LiteSVM (embedded Solana VM library — runs the BPF program inside the test binary, no separate validator needed)
- proptest (property-based testing)

**Cross-platform reproduction**: All native engine PoC tests (Bugs #1, #2, #3) and all LiteSVM (BPF) PoC + bound-analysis tests were run on both Windows (local) and Linux (Hetzner VPS) — bit-identical pass/fail.

**Engine robustness coverage**:
- 100K-case proptest sweep across 10 fuzz harnesses → all PASS
- 1M-case state-machine proptest push → all PASS
- Your existing 305-harness Kani baseline re-run against current main → **305/305 PASS, 0 regressions**. See [`baseline/`](./baseline/) for raw log + summary + per-harness timings TSV

**File inventory** (paths relative to research repo root):

| Type | File |
|---|---|
| Bug #1 LiteSVM PoC | `tests/wrapper/test_v6_cursor_wrap_consumption_reset.rs` |
| Bug #1 LiteSVM PoC (default BPF) | `tests/wrapper/test_v8_cursor_wrap_natural_drift.rs` |
| Bug #1 Kani CEX | `tests/engine/proofs_v9_findings_pack.rs` (h1, h5) |
| Bug #2 native PoC | `tests/engine/test_v9_warmup_overflow.rs` |
| Bug #2 Kani CEX | `tests/engine/proofs_v9_warmup_overflow.rs` |
| Bug #2 LiteSVM bound analysis | `tests/wrapper/test_v11_l1_warmup_overflow_litesvm.rs` |
| Bug #3 native PoC | `tests/engine/test_v11_l1_trade_open_overflow.rs` |
| Bug #3 Kani CEX | `tests/engine/proofs_v11_l1_overflow_siblings.rs` |
| Bug #3 LiteSVM PoC + bound analysis | `tests/wrapper/test_v11_l1_trade_open_overflow_litesvm.rs` |
| 10 SAFE proofs | `tests/engine/proofs_v9_findings_pack.rs`, `tests/engine/proofs_v11_l2_catchup_e2e.rs`, `tests/engine/proofs_v11_l3_implicit_invariants.rs` |

---

## Scope notes

- The 10 new Kani SAFE proofs in this audit formally verify conservation (`V = I + C + P + R`), the matured ≤ pos invariant, the K/F snapshot-before-mutate property, and 7 other implicit invariants against current main. See the SAFE proofs section for the full list.
- **Bug #1**: value-extraction surface is **config-conditional** (`h_min < h_max` markets). The wrap-reset state transition itself is unconditionally reachable.
- **Bug #2**: code defect (Kani-confirmed math failure on engine-permitted state). LiteSVM bound analysis: even with admin extreme `h_max`, reaching the overflow via legitimate PnL accumulation requires ~167 million years of wall-clock at 500 ms/slot (2 slots/sec, conservative for Solana mainnet). Disclosed as defense-in-depth, fixed uniformly with Bug #3.
- **Bug #3**: code defect (Kani-confirmed math failure on engine-permitted state). LiteSVM bound analysis: required state takes ~18 years of wall-clock to accumulate via legitimate trade flow at default caps (using 500 ms/slot, conservative for Solana mainnet). Disclosed as defense-in-depth, fixed uniformly with Bug #2.
- **Sibling B**: NOT a bug in current code (cap enforced at all real callers), only a defense-in-depth recommendation.

The distinction between "engine math fails on adversarial state" (Bugs #2, #3, Sibling B — code defects) and "production flow can drive state there" (Bug #1 only — active bug) is material. The LiteSVM bound analysis is what separates them.
