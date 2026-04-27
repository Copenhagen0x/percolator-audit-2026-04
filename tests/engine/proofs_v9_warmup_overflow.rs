//! Kani harness for Bug #2 — `advance_profit_warmup` panic on `mul_div_floor_u128` overflow.
//!
//! This formal-verification harness encodes the property:
//!
//!   "For all valid engine states + valid `idx`, `advance_profit_warmup` does not panic."
//!
//! If Kani PROVES the property, our finding is invalid (we missed a precondition that
//! prevents the overflow). If Kani returns a counterexample (CEX), the CEX is a
//! formally-derived witness state that drives `mul_div_floor_u128` past `u128::MAX`.
//!
//! This is a STRONGER statement than the empirical PoC because it covers the full
//! input space symbolically rather than the specific witness we hand-crafted.

#![cfg(kani)]

use percolator::*;

#[kani::proof]
#[kani::unwind(2)]
fn proof_advance_profit_warmup_does_not_panic() {
    // Construct an engine with bounded but symbolic params.
    // We give Kani the freedom to pick `h_max` up to a value just above
    // the overflow threshold; Kani searches the space.
    let h_max: u64 = kani::any();
    kani::assume(h_max > 0);
    kani::assume(h_max <= 1u64 << 32); // bound the search space

    let h_min: u64 = kani::any();
    kani::assume(h_min > 0);
    kani::assume(h_min <= h_max);

    let params = RiskParams {
        maintenance_margin_bps: 500,
        initial_margin_bps: 1000,
        trading_fee_bps: 10,
        max_accounts: 64,
        liquidation_fee_bps: 100,
        liquidation_fee_cap: i128::U128::new(1_000_000),
        min_liquidation_abs: i128::U128::new(0),
        min_nonzero_mm_req: 10,
        min_nonzero_im_req: 11,
        h_min,
        h_max,
        resolve_price_deviation_bps: 1000,
        max_accrual_dt_slots: 100,
        max_abs_funding_e9_per_slot: 10_000,
        min_funding_lifetime_slots: 10_000_000,
        max_active_positions_per_side: 64,
        max_price_move_bps_per_slot: 3,
    };

    let mut engine = RiskEngine::new(params);

    // Materialize one account at slot 0. Filter CEX where deposit fails
    // for unrelated reasons (param invariants, bitmap state, etc.) — we
    // care about the panic in `advance_profit_warmup`, not the setup.
    let idx: usize = 0;
    let dep_result = engine.deposit_not_atomic(idx as u16, 1, 100);
    kani::assume(dep_result.is_ok());

    // Symbolic positive PnL bounded by MAX_ACCOUNT_POSITIVE_PNL.
    let pnl_u: u128 = kani::any();
    kani::assume(pnl_u > 0);
    kani::assume(pnl_u <= MAX_ACCOUNT_POSITIVE_PNL);

    let pnl: i128 = pnl_u as i128;
    engine.accounts[idx].pnl = pnl;
    engine.pnl_pos_tot = pnl_u;
    engine.accounts[idx].reserved_pnl = pnl_u;

    // Place all of the PnL in the scheduled bucket.
    engine.accounts[idx].sched_present = 1;
    engine.accounts[idx].sched_remaining_q = pnl_u;
    engine.accounts[idx].sched_anchor_q = pnl_u;
    engine.accounts[idx].sched_start_slot = 0;
    engine.accounts[idx].sched_horizon = h_max;
    engine.accounts[idx].sched_release_q = 0;

    // Symbolic current_slot bounded by h_max (so the else-branch fires).
    let current_slot: u64 = kani::any();
    kani::assume(current_slot < h_max);
    engine.current_slot = current_slot;

    // Property: this should not panic for any valid input.
    // Kani will return a CEX when (sched_anchor_q × current_slot) > u128::MAX.
    let _ = engine.advance_profit_warmup(idx);
}
