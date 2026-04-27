//! Kani harnesses for Bug #2 SIBLINGS — `mul_div_floor_u128`/`mul_div_ceil_u128`
//! call sites in `src/percolator.rs` that take the cheap (panicking) path
//! instead of `wide_mul_div_floor_u128`/`wide_mul_div_ceil_u128_or_over_i128max`.
//!
//! Each harness encodes:
//!
//!   "For all valid engine states reachable from public entrypoints, the
//!    target call site does not panic."
//!
//! If Kani returns a counterexample (CEX), we have a new Bug #2 sibling
//! reachable through the public surface.
//!
//! Sites under test:
//!   1. `account_equity_trade_open_raw` (L3915)
//!         mul_div_floor_u128(pos_pnl_trade_open, g_num, pnl_pos_tot_trade_open)
//!         pos_pnl ≤ 1e32; g_num ≤ residual ≤ 1e16; product ≤ 1e48 ≫ u128::MAX
//!
//!   2. `risk_notional_from_eff_q` (L3779)
//!         mul_div_ceil_u128(eff.unsigned_abs(), oracle_price, POS_SCALE)
//!         eff ≤ 1e29 (when adl_a_basis = 1); oracle_price ≤ 1e12;
//!         product ≤ 1e41 ≫ u128::MAX
//!
//!   3. `effective_pos_q_checked` (L2642)
//!         mul_div_floor_u128(abs_basis, a_side, a_basis)
//!         (Already u128-safe under attach_effective_position cap, but
//!         position_basis_q can also be set via paths that bypass the cap;
//!         Kani searches for any reachable corruption.)

#![cfg(kani)]

use percolator::*;

// ----------------------------------------------------------------------------
// Shared helpers
// ----------------------------------------------------------------------------

/// Build a stock RiskParams with a symbolic admission window. The other
/// params are clamped to the canonical "healthy" defaults so the harness
/// only has to reason about the few fields that materially affect the
/// arithmetic call sites under test.
fn symbolic_params() -> RiskParams {
    RiskParams {
        maintenance_margin_bps: 500,
        initial_margin_bps: 1000,
        trading_fee_bps: 10,
        max_accounts: 4, // matches MAX_ACCOUNTS under kani
        liquidation_fee_bps: 100,
        liquidation_fee_cap: i128::U128::new(1_000_000),
        min_liquidation_abs: i128::U128::new(0),
        min_nonzero_mm_req: 10,
        min_nonzero_im_req: 11,
        h_min: 1,
        h_max: 1u64 << 32,
        resolve_price_deviation_bps: 1000,
        max_accrual_dt_slots: 100,
        max_abs_funding_e9_per_slot: 10_000,
        min_funding_lifetime_slots: 10_000_000,
        max_active_positions_per_side: 4,
        max_price_move_bps_per_slot: 3,
    }
}

// ----------------------------------------------------------------------------
// Sibling 1 — account_equity_trade_open_raw (line 3915)
// ----------------------------------------------------------------------------
//
// Call:
//     mul_div_floor_u128(pos_pnl_trade_open, g_num, pnl_pos_tot_trade_open)
//
// Bounds:
//     pos_pnl_trade_open ≤ MAX_ACCOUNT_POSITIVE_PNL = 1e32
//     g_num             = min(residual, pnl_pos_tot_trade_open)
//                          residual ≤ vault ≤ MAX_VAULT_TVL = 1e16
//
// 1e32 × 1e16 = 1e48 ≫ u128::MAX (3.4e38) → checked_mul().expect() PANIC.

#[kani::proof]
#[kani::unwind(10)]
fn proof_trade_open_raw_g_num_does_not_panic() {
    let params = symbolic_params();
    let mut engine = RiskEngine::new(params);

    // Materialize one account so deposits/aggregates are well-formed.
    let idx: usize = 0;
    let dep = engine.deposit_not_atomic(idx as u16, 1, 100);
    kani::assume(dep.is_ok());

    // Symbolic per-account positive PnL up to its hard cap.
    let pos_pnl: u128 = kani::any();
    kani::assume(pos_pnl > 0);
    kani::assume(pos_pnl <= MAX_ACCOUNT_POSITIVE_PNL);

    // Wire the account state so account_equity_trade_open_raw enters the
    // mul_div_floor_u128 branch with adversarial-but-valid inputs.
    engine.accounts[idx].pnl = pos_pnl as i128;
    engine.accounts[idx].reserved_pnl = 0;
    engine.pnl_pos_tot = pos_pnl;

    // Symbolic vault that can dominate the senior_sum, leaving residual large.
    // residual = vault − (c_tot + insurance) → bounded by MAX_VAULT_TVL.
    let vault_v: u128 = kani::any();
    kani::assume(vault_v > 0);
    kani::assume(vault_v <= MAX_VAULT_TVL);
    engine.vault = i128::U128::new(vault_v);

    // c_tot stays as deposit; insurance balance is zero by default. No
    // additional state needed — kani picks pos_pnl and vault to drive
    // pos_pnl_trade_open × g_num past u128::MAX.

    // candidate_trade_pnl = 0 keeps pos_pnl_trade_open == pos_pnl, which
    // maximizes the size of the multiplicand under test.
    let acct = engine.accounts[idx];
    let _ = engine.account_equity_trade_open_raw(&acct, idx, 0);
}

// ----------------------------------------------------------------------------
// Sibling 2 — risk_notional_from_eff_q (line 3779)
// ----------------------------------------------------------------------------
//
// Call (inside try_notional → notional_checked → risk_notional_from_eff_q):
//     mul_div_ceil_u128(eff.unsigned_abs(), oracle_price as u128, POS_SCALE)
//
// Bounds:
//     eff comes from effective_pos_q_checked. The check `effective_abs >
//     i128::MAX` returns Err(CorruptState), so eff ≤ i128::MAX = 1.7e38.
//     With abs_basis ≤ MAX_POSITION_ABS_Q = 1e14 (only via attach_effective_
//     position, NOT via raw set_position_basis_q which lacks that cap) and
//     a_side ≤ ADL_ONE = 1e15 and a_basis ≥ 1, eff ≤ 1e29.
//     oracle_price ≤ MAX_ORACLE_PRICE = 1e12.
//
// 1e29 × 1e12 = 1e41 ≫ u128::MAX → checked_mul().expect() PANIC if Kani
// can drive eff toward 1e29 (i.e. adl_a_basis ≈ 1).

#[kani::proof]
#[kani::unwind(10)]
fn proof_risk_notional_from_eff_q_does_not_panic() {
    let params = symbolic_params();
    let mut engine = RiskEngine::new(params);

    let idx: usize = 0;
    let dep = engine.deposit_not_atomic(idx as u16, 1, 100);
    kani::assume(dep.is_ok());

    // Symbolic effective-position drivers.
    //   abs_basis × a_side / a_basis = effective_abs
    // Maximize effective_abs by making a_basis small and abs_basis × a_side
    // large but still ≤ u128::MAX so the inner mul does not overflow first.
    let abs_basis: u128 = kani::any();
    kani::assume(abs_basis > 0);
    kani::assume(abs_basis <= MAX_POSITION_ABS_Q);

    let a_side: u128 = kani::any();
    kani::assume(a_side > 0);
    kani::assume(a_side <= ADL_ONE);

    let a_basis: u128 = kani::any();
    kani::assume(a_basis > 0);
    kani::assume(a_basis <= ADL_ONE);

    // Drive position_basis_q directly to the symbolic abs_basis (positive
    // long side). This bypasses the attach_effective_position cap on
    // purpose — adversarial corrupted state per Kani search.
    engine.accounts[idx].position_basis_q = abs_basis as i128;
    engine.accounts[idx].adl_a_basis = a_basis;
    engine.accounts[idx].adl_epoch_snap = engine.adl_epoch_long;
    engine.adl_mult_long = a_side;

    // Symbolic oracle price within validated band.
    let oracle_price: u64 = kani::any();
    kani::assume(oracle_price > 0);
    kani::assume(oracle_price <= MAX_ORACLE_PRICE);

    // Property: try_notional must not panic for any reachable state.
    // (Returning Err is fine; only checked_mul().expect() panic is a sibling.)
    let _ = engine.try_notional(idx, oracle_price);
}

// ----------------------------------------------------------------------------
// Sibling 3 — effective_pos_q_checked (line 2642)
// ----------------------------------------------------------------------------
//
// Call:
//     mul_div_floor_u128(abs_basis, a_side, a_basis)
//
// Bounds:
//     abs_basis = position_basis_q.unsigned_abs(). Bounded only by
//     attach_effective_position_inner (≤ MAX_POSITION_ABS_Q = 1e14). The
//     lower-level set_position_basis_q_inner has NO size cap — only a
//     per-side count cap. If any path reaches set_position_basis_q without
//     going through attach_effective_position, abs_basis can be u64-class
//     or larger.
//     a_side ≤ ADL_ONE = 1e15.
//
// In healthy operation: 1e14 × 1e15 = 1e29 ≪ u128::MAX. SAFE.
// Under corruption (abs_basis > 1e14): may reach u128::MAX. PANIC?
//
// This harness searches for a valid call sequence that drives the inner
// product past u128::MAX without first failing a public postcondition.

#[kani::proof]
#[kani::unwind(10)]
fn proof_effective_pos_q_does_not_panic() {
    let params = symbolic_params();
    let mut engine = RiskEngine::new(params);

    let idx: usize = 0;
    let dep = engine.deposit_not_atomic(idx as u16, 1, 100);
    kani::assume(dep.is_ok());

    // Symbolic basis WITHOUT going through attach_effective_position — this
    // models any state-corruption path (set_position_basis_q called by
    // settle_side_effects_*, finalize_*, etc.) that does not enforce the
    // 1e14 cap.
    let abs_basis: u128 = kani::any();
    kani::assume(abs_basis > 0);
    // Allow the symbolic basis to range up to roughly the i128::MAX
    // boundary — the upper edge of what the ADL/PnL paths can encode in
    // a single position field without the cap check kicking in.
    kani::assume(abs_basis <= (i128::MAX as u128));

    let a_side: u128 = kani::any();
    kani::assume(a_side > 0);
    kani::assume(a_side <= ADL_ONE);

    let a_basis: u128 = kani::any();
    kani::assume(a_basis > 0);
    kani::assume(a_basis <= ADL_ONE);

    engine.accounts[idx].position_basis_q = abs_basis as i128;
    engine.accounts[idx].adl_a_basis = a_basis;
    engine.accounts[idx].adl_epoch_snap = engine.adl_epoch_long;
    engine.adl_mult_long = a_side;

    // Property: try_effective_pos_q must not panic. Returning Err is fine.
    let _ = engine.try_effective_pos_q(idx);
}
