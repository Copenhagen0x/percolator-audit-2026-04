# Raw Kani results — 10 new SAFE proofs

This file lists the 10 new Kani harnesses written during this audit. All ten passed (SAFE = formally verified) against `aeyakovenko/percolator @ 5940285`.

**Environment**: Hetzner VPS (6-core), Ubuntu 22.04, Kani 0.67.0, nightly-2025-11-21 toolchain. Each harness runs single-threaded; verification times below are walltime, not CPU time.

**Source of timings**: extracted from the bulk baseline sweep run on 2026-04-26 (start 21:25 local, end 01:18 local). Raw TSV available at [`baseline/kani_baseline_timings.tsv`](./baseline/kani_baseline_timings.tsv); raw cargo-kani log at [`baseline/kani_baseline_full.log.gz`](./baseline/kani_baseline_full.log.gz).

**Cumulative verification time for all 10 SAFE proofs: 161.07 seconds (~2 min 41 sec)** in the bulk-sweep environment (faster than individual runs because the workspace was pre-compiled).

---

## Proof results table

| # | Harness | File | Time (s) | Verdict | What it formalizes |
|---|---|---|---|---|---|
| 1 | `proof_h2_finalize_preserves_conservation` | `tests/engine/proofs_v9_findings_pack.rs` | **29.88** | SUCCESSFUL | After `finalize_touched_accounts_post_live`, the conservation identity `V = I + C + P + R` holds for all reachable touched-set states |
| 2 | `proof_h3_set_pnl_with_reserve_matured_le_pos` | `tests/engine/proofs_v9_findings_pack.rs` | **7.08** | SUCCESSFUL | For all reachable engine states, `pnl_matured_pos_tot ≤ pnl_pos_tot` is preserved by `set_pnl_with_reserve` |
| 3 | `proof_h4_market_slot_advance_requires_real_signal` | `tests/engine/proofs_v9_findings_pack.rs` | **54.73** | SUCCESSFUL | The engine's `last_market_slot` only advances when accrue is called with a strictly newer slot — no stale-slot regressions |
| 4 | `proof_l2_catchup_partial_preserves_conservation` | `tests/engine/proofs_v11_l2_catchup_e2e.rs` | **7.67** | SUCCESSFUL | Wrapper-level: `CatchupAccrue` partial sweep preserves `V = I + C + P + R` (formal proof of the G3 closure statement) |
| 5 | `proof_l2_catchup_complete_advances_to_now_slot` | `tests/engine/proofs_v11_l2_catchup_e2e.rs` | **2.58** | SUCCESSFUL | `CatchupAccrue` only advances `last_market_slot` on a complete sweep — partial sweeps roll back atomically |
| 6 | `proof_l3a_prepare_resolved_touch_preserves_matured` | `tests/engine/proofs_v11_l3_implicit_invariants.rs` | **3.34** | SUCCESSFUL | `prepare_account_for_resolved_touch` (engine 4432-4448) zeroes `reserved_pnl` only when `pnl_matured_pos_tot = pnl_pos_tot` already holds — no payout-undercollateralization |
| 7 | `proof_l3b_begin_full_drain_reset_snapshots_correctly` | `tests/engine/proofs_v11_l3_implicit_invariants.rs` | **2.22** | SUCCESSFUL | `begin_full_drain_reset` (engine 3352-3422) snapshots K/F into `K_epoch_start_*`/`F_epoch_start_*` BEFORE zeroing live K/F; epoch increments by exactly 1; mode transitions to `ResetPending` |
| 8 | `proof_l3c_empty_sweep_produces_v_equals_i` | `tests/engine/proofs_v11_l3_implicit_invariants.rs` | **41.97** | SUCCESSFUL | `sweep_empty_market_surplus_to_insurance` (engine 4006-4038) only fires when all 8 gating counters are zero; post-sweep `V = I` holds and conservation preserved |
| 9 | `proof_l3d_advance_profit_warmup_promotion_preserves_horizon_bounds` | `tests/engine/proofs_v11_l3_implicit_invariants.rs` | **2.12** | SUCCESSFUL | After pending→scheduled bucket promotion in `advance_profit_warmup`, `sched_horizon ∈ [h_min, h_max]` always holds — no division-by-zero or `CorruptState` on next call |
| 10 | `proof_l3e_phantom_dust_bound_respects_side_cap` | `tests/engine/proofs_v11_l3_implicit_invariants.rs` | **9.48** | SUCCESSFUL | `phantom_dust_bound_*_q` cumulative bound never exceeds `MAX_OI_SIDE_Q` under any sequence of `inc_phantom_dust_bound[_by]` calls |

---

## Per-file rollup

| File | Harnesses | Total time (s) |
|---|---|---|
| `proofs_v9_findings_pack.rs` | 3 SAFE proofs (h2, h3, h4) | 91.69 |
| `proofs_v11_l2_catchup_e2e.rs` | 2 SAFE proofs (l2a, l2b) | 10.25 |
| `proofs_v11_l3_implicit_invariants.rs` | 5 SAFE proofs (l3a–e) | 59.13 |
| **Total** | **10 SAFE proofs** | **161.07** |

Note: `proofs_v9_findings_pack.rs` also contains 2 CEX-finding harnesses (`h1`, `h5`) for Bug #1, and `proofs_v9_warmup_overflow.rs` + `proofs_v11_l1_overflow_siblings.rs` contain CEX harnesses for Bugs #2 and #3. Those are the FAILED-verification ones (Kani returned counterexamples) — see DISCLOSURE.md for their analysis.

---

## How to reproduce

```bash
# Clone aeyakovenko/percolator at the pinned sha
git clone https://github.com/aeyakovenko/percolator
cd percolator
git checkout 5940285

# Drop in the new harness files (engine repo's tests/ is a flat directory)
cp /path/to/this-repo/tests/engine/proofs_v9_findings_pack.rs       tests/
cp /path/to/this-repo/tests/engine/proofs_v11_l2_catchup_e2e.rs     tests/
cp /path/to/this-repo/tests/engine/proofs_v11_l3_implicit_invariants.rs tests/

# Run each SAFE proof individually
for harness in \
  proof_h2_finalize_preserves_conservation \
  proof_h3_set_pnl_with_reserve_matured_le_pos \
  proof_h4_market_slot_advance_requires_real_signal \
  proof_l2_catchup_partial_preserves_conservation \
  proof_l2_catchup_complete_advances_to_now_slot \
  proof_l3a_prepare_resolved_touch_preserves_matured \
  proof_l3b_begin_full_drain_reset_snapshots_correctly \
  proof_l3c_empty_sweep_produces_v_equals_i \
  proof_l3d_advance_profit_warmup_promotion_preserves_horizon_bounds \
  proof_l3e_phantom_dust_bound_respects_side_cap; do
    cargo kani --tests --features test --harness "$harness"
done
```

Expected: 10 × `VERIFICATION:- SUCCESSFUL`. Per-harness times will vary by hardware and whether the workspace was pre-compiled; the values above are from the bulk sweep on a 6-core Hetzner CCX VPS.

---

## What's NOT in this file

- The 2 Bug #1 Kani CEXes (`proof_h1_cursor_wrap_implies_real_volatility_absorption`, `proof_h5_cursor_wrap_unlocks_fast_lane`) — covered in DISCLOSURE.md Bug #1 section.
- The Bug #2 Kani CEX (`proof_advance_profit_warmup_does_not_panic`) — covered in DISCLOSURE.md Bug #2 section.
- The Bug #3 Kani CEX (`proof_trade_open_raw_g_num_does_not_panic`) — covered in DISCLOSURE.md Bug #3 section.
- Sibling B Kani CEXes (`proof_risk_notional_from_eff_q_does_not_panic`, `proof_effective_pos_q_does_not_panic`) — covered in DISCLOSURE.md Sibling B section.
- The 305-harness baseline re-run of the existing proofs — see `baseline/`.
