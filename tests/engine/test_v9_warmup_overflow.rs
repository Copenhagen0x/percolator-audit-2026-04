//! V9 — `advance_profit_warmup` panics on `mul_div_floor_u128` overflow.
//!
//! # Concrete state transition
//!
//! Engine line ~4677-4681 in `advance_profit_warmup`:
//! ```ignore
//! let sched_total = if elapsed >= a.sched_horizon as u128 {
//!     a.sched_anchor_q
//! } else {
//!     mul_div_floor_u128(a.sched_anchor_q, elapsed, a.sched_horizon as u128)
//! };
//! ```
//!
//! `mul_div_floor_u128` (wide_math.rs):
//! ```ignore
//! pub fn mul_div_floor_u128(a: u128, b: u128, d: u128) -> u128 {
//!     assert!(d > 0, "mul_div_floor_u128: division by zero");
//!     let p = a.checked_mul(b).expect("mul_div_floor_u128: a*b overflow");
//!     p / d
//! }
//! ```
//!
//! `expect("a*b overflow")` panics the program when `sched_anchor_q × elapsed > u128::MAX`.
//!
//! # Reachability
//!
//! - `MAX_ACCOUNT_POSITIVE_PNL = 10^32 ≈ 2^106.3` — engine constant
//! - `validate_params_fast_shape` enforces `h_max > 0` but NO upper bound
//! - For overflow: `sched_anchor_q × elapsed > 2^128`
//! - At `sched_anchor_q ≈ 2^100` (well under MAX_ACCOUNT_POSITIVE_PNL),
//!   need `elapsed > 2^28 ≈ 2.68 × 10^8` slots
//! - With `h_max ≈ 2^30` slots configured, `elapsed = h_max - 1 ≈ 2^30`
//! - Product: 2^100 × 2^30 = 2^130 > 2^128 → PANIC
//!
//! # Impact tier
//!
//! Availability / DoS for the affected account. Solana tx-level rollback
//! prevents persistent state corruption, but every subsequent
//! `touch_account_live_local` / `finalize_touched_accounts_post_live`
//! that walks this account re-triggers the panic. The account is
//! effectively bricked. KeeperCrank Phase 2 RR sweep walks every account
//! in cursor range, so the bricked account also bricks every crank that
//! includes its idx in the sweep window.
//!
//! # Suggested fix
//!
//! Replace `mul_div_floor_u128` with `wide_mul_div_floor_u128` (already in
//! the codebase, uses U256 intermediate). Output range unchanged because
//! the quotient is bounded by `sched_anchor_q ≤ MAX_ACCOUNT_POSITIVE_PNL`
//! which fits in u128.

#![cfg(feature = "test")]

use percolator::*;

fn extreme_h_max_params() -> RiskParams {
    RiskParams {
        maintenance_margin_bps: 500,
        initial_margin_bps: 1000,
        trading_fee_bps: 10,
        max_accounts: 64,
        liquidation_fee_bps: 100,
        liquidation_fee_cap: i128::U128::new(1_000_000),
        min_liquidation_abs: i128::U128::new(0),
        min_nonzero_mm_req: 10,
        min_nonzero_im_req: 11,
        h_min: 1,
        // CRITICAL: extreme h_max. validate_params_fast_shape doesn't bound this.
        h_max: 1u64 << 30, // ~1.07 billion slots
        resolve_price_deviation_bps: 1000,
        max_accrual_dt_slots: 100,
        max_abs_funding_e9_per_slot: 10_000,
        min_funding_lifetime_slots: 10_000_000,
        max_active_positions_per_side: MAX_ACCOUNTS as u64,
        max_price_move_bps_per_slot: 3,
    }
}

fn add_user_test(engine: &mut RiskEngine, _fee_payment: u128) -> Result<u16> {
    let idx = engine.free_head;
    if idx == u16::MAX || (idx as usize) >= MAX_ACCOUNTS {
        return Err(RiskError::Overflow);
    }
    engine.deposit_not_atomic(idx, 1, 100)?;
    Ok(idx)
}

#[test]
#[should_panic(expected = "a*b overflow")]
fn v9_advance_profit_warmup_native_mul_panic() {
    let mut engine = RiskEngine::new(extreme_h_max_params());
    let idx = add_user_test(&mut engine, 0).unwrap() as usize;

    // Plant an extreme positive PnL — bounded by MAX_ACCOUNT_POSITIVE_PNL
    // (1e32 ≈ 2^106) at the engine surface. We materialize at 2^100 to
    // stay well under the cap while still triggering overflow.
    let huge_pnl: i128 = 1i128 << 100;
    let huge_u: u128 = huge_pnl as u128;

    engine.accounts[idx].pnl = huge_pnl;
    engine.pnl_pos_tot = huge_u;
    engine.accounts[idx].reserved_pnl = huge_u;

    // Plant a scheduled bucket with anchor = huge_u, horizon = h_max.
    engine.accounts[idx].sched_present = 1;
    engine.accounts[idx].sched_remaining_q = huge_u;
    engine.accounts[idx].sched_anchor_q = huge_u;
    engine.accounts[idx].sched_start_slot = 0;
    engine.accounts[idx].sched_horizon = engine.params.h_max;
    engine.accounts[idx].sched_release_q = 0;

    // Advance the clock so that `elapsed` is just under `sched_horizon`,
    // forcing the `mul_div_floor_u128` else-branch.
    engine.current_slot = engine.params.h_max - 1;

    // Product: 2^100 × (2^30 - 1) ≈ 2^130 > u128::MAX = 2^128 - 1
    // checked_mul returns None → expect("a*b overflow") panics.
    let _ = engine.advance_profit_warmup(idx);
}

/// Sanity: with default h_max small, the product stays in u128 and the
/// helper returns Ok. Confirms the panic above is config-driven, not
/// spec-driven.
#[test]
fn v9_advance_profit_warmup_safe_with_small_h_max() {
    fn small_h_max_params() -> RiskParams {
        let mut p = extreme_h_max_params();
        p.h_max = 100; // canonical small horizon
        p
    }
    let mut engine = RiskEngine::new(small_h_max_params());
    let idx = add_user_test(&mut engine, 0).unwrap() as usize;

    let huge_pnl: i128 = 1i128 << 100;
    let huge_u: u128 = huge_pnl as u128;

    engine.accounts[idx].pnl = huge_pnl;
    engine.pnl_pos_tot = huge_u;
    engine.accounts[idx].reserved_pnl = huge_u;

    engine.accounts[idx].sched_present = 1;
    engine.accounts[idx].sched_remaining_q = huge_u;
    engine.accounts[idx].sched_anchor_q = huge_u;
    engine.accounts[idx].sched_start_slot = 0;
    engine.accounts[idx].sched_horizon = engine.params.h_max;
    engine.accounts[idx].sched_release_q = 0;

    engine.current_slot = engine.params.h_max - 1;

    // 2^100 × 99 ≈ 2^106.6 — fits in u128. No panic.
    let res = engine.advance_profit_warmup(idx);
    assert!(res.is_ok(), "small h_max keeps product in u128: {:?}", res);
}
