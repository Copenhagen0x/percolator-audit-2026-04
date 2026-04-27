//! v9 findings-pack — Kani harnesses formalizing the audit deliverables.
//!
//! Layout:
//!   H1  cursor-wrap consumption reset (Bug #1)         expected: VERIFICATION FAILED (CEX)
//!   H2  finalize_touched_accounts_post_live conserves  expected: PASS
//!   H3  set_pnl_with_reserve maintains matured<=pos    expected: PASS
//!   H4  liveness clock advance requires real signal    expected: PASS
//!   H5  cursor wrap flips downstream admission lane    expected: VERIFICATION FAILED (CEX)
//!
//! H1 + H5 are the formal versions of the empirical Bug #1 PoC. H2-H4
//! formalize SAFE-claims from the v7-v9 audit pipelines.

#![cfg(kani)]

mod common;
use common::*;

// ============================================================================
// Param helpers — Kani-tractable variants of zero_fee_params/default_params
// ============================================================================

/// Engine config tuned for cursor-wrap proofs. `max_accounts = 4` is the
/// smallest tractable slab (matches `--features small_4`); on this footprint
/// a single crank with `rr_window_size = 4` walks the entire deployment in
/// one call, forcing a cursor wraparound (`sweep_end >= wrap_bound`) on
/// every invocation. That is exactly the trigger the H1/H5 properties need.
fn wrap_friendly_params() -> RiskParams {
    let mut p = zero_fee_params();
    p.max_accounts = MAX_ACCOUNTS as u64;
    p.h_min = 1;
    p.h_max = 4;
    p
}

// ============================================================================
// H1 — Bug #1 formalization: cursor-wrap reset implies real volatility absorbed.
// ============================================================================
//
// Property:
//   "If `keeper_crank_not_atomic` causes a cursor wrap (sweep_generation
//    increments by 1 within this single call), then the value of
//    `price_move_consumed_bps_this_generation` immediately BEFORE the wrap
//    must have been > 0 — proving that real volatility was actually absorbed
//    in the generation that we are now ending."
//
// Pre-state seeded with `price_move_consumed_bps_this_generation == 0`.
// Attacker calls the crank with `oracle_price == last_oracle_price` so the
// price_move_active gate (engine line 2854) is false and `consumed_this_step`
// is 0. The crank's Phase 2 sweep walks `rr_window_size` indices; with the
// cursor at 0 and the window equal to `max_accounts`, the wrap branch fires
// on this single call. The asserted property is then violated:
// sweep_generation incremented but the per-generation consumption never
// crossed 0.
//
// Expected outcome: VERIFICATION FAILED with a CEX matching the empirical
// PoC at `repos/percolator-prog/tests/test_v6_cursor_wrap_consumption_reset.rs`.

#[kani::proof]
#[kani::unwind(8)]
#[kani::solver(cadical)]
fn proof_h1_cursor_wrap_implies_real_volatility_absorption() {
    let mut engine = RiskEngine::new(wrap_friendly_params());

    // Pre-state: cursor at 0, sweep_generation arbitrary but bounded so the
    // checked_add(1) in the wrap branch cannot itself error out (which
    // would mask the property being formalized).
    let gen0: u8 = kani::any();
    let consumption_pre: u128 = 0; // KEY: zero consumption before crank

    engine.rr_cursor_position = 0;
    engine.sweep_generation = gen0 as u64;
    engine.price_move_consumed_bps_this_generation = consumption_pre;

    // Symbolic but bounded oracle price; constant across the crank to keep
    // `price_move_active = false` (engine line 2854: equal price → no
    // consumption, no oracle drift, no real volatility).
    let oracle_price: u32 = kani::any();
    kani::assume(oracle_price > 0);
    kani::assume((oracle_price as u64) <= MAX_ORACLE_PRICE);

    let init_slot = engine.current_slot;
    engine.last_oracle_price = oracle_price as u64;
    engine.fund_px_last = oracle_price as u64;
    engine.last_market_slot = init_slot;

    // Phase 2 window equals slab size so wrap fires on this call.
    let rr_window_size = engine.params.max_accounts;

    // No keeper-priority candidates; Phase 1 is a no-op.
    let candidates: [(u16, Option<LiquidationPolicy>); 0] = [];

    let res = engine.keeper_crank_not_atomic(
        init_slot,
        oracle_price as u64,
        &candidates,
        0,         // max_revalidations
        0i128,     // funding_rate_e9 — zero, so funding_active = false
        1,         // admit_h_min
        engine.params.h_max,
        None,      // no consumption-threshold gate (irrelevant for H1)
        rr_window_size,
    );
    kani::assume(res.is_ok());

    // POST-STATE.
    let gen1 = engine.sweep_generation;
    let consumption_post = engine.price_move_consumed_bps_this_generation;

    let wrapped = gen1 == (gen0 as u64).wrapping_add(1);

    // PROPERTY (the one we expect Kani to refute):
    //   "if wrapped, then consumption was nonzero before the wrap fired"
    //
    // Encoded as: NOT (wrapped AND consumption_pre == 0 AND consumption_post == 0).
    //
    // The CEX shows wrap fired, pre was 0, post is 0 — i.e. budget reset
    // committed without any real volatility absorption.
    assert!(
        !(wrapped && consumption_pre == 0 && consumption_post == 0),
        "Bug #1: cursor wrap reset consumption budget without real volatility"
    );
}

// ============================================================================
// H2 — Conservation across finalize_touched_accounts_post_live (Agent R claim).
// ============================================================================
//
// Property:
//   "After finalize_touched_accounts_post_live returns Ok on a valid
//    pre-state, the conservation invariant V >= C + I still holds."
//
// finalize is the post-live sweep that performs whole-only auto-conversion
// of released positive PnL into capital and a fee-debt sweep. The whole-only
// branch reads from V's residual; the fee sweep moves funds between
// capital and protocol_fee_pool. Neither operation should violate V >= C + I.
//
// Expected outcome: PASS.

#[kani::proof]
#[kani::unwind(4)]
#[kani::solver(cadical)]
fn proof_h2_finalize_preserves_conservation() {
    let mut engine = RiskEngine::new(zero_fee_params());
    let idx = add_user_test(&mut engine, 0).unwrap() as usize;

    // Plant a deposit so capital is nonzero and the conservation
    // pre-condition is non-trivially satisfied.
    let dep: u16 = kani::any();
    kani::assume(dep > 0 && dep <= 10_000);
    engine
        .deposit_not_atomic(idx as u16, dep as u128, DEFAULT_SLOT)
        .unwrap();
    kani::assume(engine.check_conservation());

    // Build a context that finalize will iterate over. A single touched
    // account exercises the whole-only branch and the fee-debt sweep
    // without inflating the symbolic state.
    let mut ctx = InstructionContext::new_with_admission(0, engine.params.h_max);
    ctx.add_touched(idx as u16);

    let res = engine.finalize_touched_accounts_post_live(&ctx);
    kani::assume(res.is_ok());

    assert!(
        engine.check_conservation(),
        "finalize_touched_accounts_post_live broke V >= C + I"
    );
}

// ============================================================================
// H3 — Counter consistency for pnl_pos_tot (Agent N + C claim).
// ============================================================================
//
// Property:
//   "After every successful set_pnl_with_reserve call,
//    pnl_matured_pos_tot <= pnl_pos_tot."
//
// This is DIFFERENT from `proof_set_pnl_maintains_pnl_pos_tot` in
// proofs_invariants.rs: that proof verifies pnl_pos_tot agrees with the
// account's PnL after specific paths. Here we verify the EXIT-postcondition
// `matured <= pos` for arbitrary entry state and arbitrary delta direction
// (positive increase via UseAdmissionPair, negative decrease via
// NoPositiveIncreaseAllowed).
//
// Expected outcome: PASS.

#[kani::proof]
#[kani::unwind(4)]
#[kani::solver(cadical)]
fn proof_h3_set_pnl_with_reserve_matured_le_pos() {
    let mut engine = RiskEngine::new(zero_fee_params());
    // Modest residual so admission can land on either lane symbolically.
    engine.vault = U128::new(10_000);
    let idx = add_user_test(&mut engine, 0).unwrap() as usize;

    // Symbolic but bounded entry PnL (positive). Reach it via the admission
    // path so reserved_pnl + pnl_matured_pos_tot are coherent on entry.
    let entry: u8 = kani::any();
    kani::assume(entry > 0);
    let mut ctx = InstructionContext::new_with_admission(0, engine.params.h_max);
    let r0 = engine.set_pnl_with_reserve(
        idx,
        entry as i128,
        ReserveMode::UseAdmissionPair(0, engine.params.h_max),
        Some(&mut ctx),
    );
    kani::assume(r0.is_ok());
    // Entry-invariant for the property: matured <= pos.
    kani::assume(engine.pnl_matured_pos_tot <= engine.pnl_pos_tot);

    // Symbolic transition. Three modes are covered:
    //  - UseAdmissionPair with new_pnl > entry (positive increase)
    //  - NoPositiveIncreaseAllowed with new_pnl <= entry (decrease / flat)
    //  - ImmediateReleaseResolvedOnly is rejected in Live, so skipped here.
    let new_pnl: i16 = kani::any();
    kani::assume(new_pnl > i16::MIN);

    if (new_pnl as i128) > (entry as i128) {
        let mut ctx2 = InstructionContext::new_with_admission(0, engine.params.h_max);
        let r = engine.set_pnl_with_reserve(
            idx,
            new_pnl as i128,
            ReserveMode::UseAdmissionPair(0, engine.params.h_max),
            Some(&mut ctx2),
        );
        kani::assume(r.is_ok());
    } else {
        let r = engine.set_pnl_with_reserve(
            idx,
            new_pnl as i128,
            ReserveMode::NoPositiveIncreaseAllowed,
            None,
        );
        kani::assume(r.is_ok());
    }

    // Exit-postcondition.
    assert!(
        engine.pnl_matured_pos_tot <= engine.pnl_pos_tot,
        "set_pnl_with_reserve must preserve pnl_matured_pos_tot <= pnl_pos_tot"
    );
}

// ============================================================================
// H4 — Liveness clock cannot bump without a genuine signal (Agent X claim).
// ============================================================================
//
// Engine note:
//   The engine surface does not own a `last_good_oracle_slot` /
//   `oracle_target_publish_time` pair — those live in the wrapper's Pyth
//   adapter. The closest engine-level analogue is the `last_market_slot`
//   advance gate inside `accrue_market_to`, which embodies the same
//   replay-protection principle: the on-chain clock cannot move forward
//   without a fresh, monotonic external signal.
//
// Property:
//   "If accrue_market_to returns Ok and `last_market_slot` strictly
//    advances (post > pre), then there was a genuine new signal — either
//    `now_slot > pre` (real time elapsed) OR oracle/funding caused the
//    advance. Crucially: when total_dt == 0 AND oracle_price ==
//    last_oracle_price (engine line 2833), the function returns early
//    without bumping last_market_slot."
//
// Encoded as: if last_market_slot advanced after Ok, then either
// `now_slot > pre_last_market_slot` or `oracle_price != pre_last_oracle_price`
// (both observable to the caller).
//
// Expected outcome: PASS.

#[kani::proof]
#[kani::unwind(4)]
#[kani::solver(cadical)]
fn proof_h4_market_slot_advance_requires_real_signal() {
    let mut engine = RiskEngine::new(zero_fee_params());

    let pre_slot: u32 = kani::any();
    kani::assume(pre_slot > 0);
    let pre_oracle: u32 = kani::any();
    kani::assume(pre_oracle > 0);
    kani::assume((pre_oracle as u64) <= MAX_ORACLE_PRICE);

    engine.current_slot = pre_slot as u64;
    engine.last_market_slot = pre_slot as u64;
    engine.last_oracle_price = pre_oracle as u64;
    engine.fund_px_last = pre_oracle as u64;

    // Symbolic call inputs.
    let now_slot: u32 = kani::any();
    let oracle_price: u32 = kani::any();
    kani::assume(oracle_price > 0);
    kani::assume((oracle_price as u64) <= MAX_ORACLE_PRICE);
    // Pre-state legality: now >= current_slot, now >= last_market_slot.
    kani::assume(now_slot as u64 >= engine.current_slot);
    kani::assume(now_slot as u64 >= engine.last_market_slot);

    // Bound funding rate within engine envelope.
    let fr: i32 = kani::any();
    kani::assume((fr.unsigned_abs() as u128) <= MAX_ABS_FUNDING_E9_PER_SLOT as u128);

    // Snapshot pre values BEFORE the call.
    let pre_lms = engine.last_market_slot;
    let pre_lop = engine.last_oracle_price;

    let r = engine.accrue_market_to(now_slot as u64, oracle_price as u64, fr as i128);
    kani::assume(r.is_ok());

    let post_lms = engine.last_market_slot;

    // PROPERTY: if last_market_slot strictly advanced, the caller must have
    // supplied a genuinely new signal — either time moved forward
    // (now_slot > pre_lms) or oracle moved (oracle_price != pre_lop).
    if post_lms > pre_lms {
        assert!(
            (now_slot as u64) > pre_lms || (oracle_price as u64) != pre_lop,
            "last_market_slot advanced without a fresh time/oracle signal"
        );
    }
}

// ============================================================================
// H5 — Cursor wrap flips downstream admission lane (full exploit chain).
// ============================================================================
//
// Property (negated by the harness — Kani should refute the safety claim):
//   "set_pnl_with_reserve, when run with a finite consumption-threshold
//    gate, MUST NOT switch from the slow lane (admit_h_max) to the fast
//    lane (admit_h_min) inside a single call sequence that the attacker
//    fully controls — in particular, a same-slot/same-price keeper crank
//    that wraps the cursor must not unlock the fast lane."
//
// Setup:
//   1. Pre-state primed so consumption_pre >= threshold (slow lane is the
//      current decision).
//   2. Capture the slow-lane admission via a dry-run set_pnl_with_reserve
//      call against `admit_fresh_reserve_h_lock` BEFORE the crank.
//   3. Run the keeper crank at constant slot/price (bug trigger).
//   4. Re-query admission post-wrap. The threshold gate is now bypassed
//      because consumption_post == 0; if residual permits, admission
//      returns admit_h_min.
//
// Expected outcome: VERIFICATION FAILED (CEX).
//
// Implementation note: we exercise the exit decision via direct calls to
// `admit_fresh_reserve_h_lock` rather than full set_pnl_with_reserve to
// keep the symbolic branching tractable for Kani. The lane decision is the
// observable output of the bug.

#[kani::proof]
#[kani::unwind(8)]
#[kani::solver(cadical)]
fn proof_h5_cursor_wrap_unlocks_fast_lane() {
    let mut engine = RiskEngine::new(wrap_friendly_params());

    // ------------------------------------------------------------------
    // Pre-state.
    // ------------------------------------------------------------------
    // Set up residual large enough that residual-lane admission would
    // return admit_h_min (fast lane) when allowed by the threshold gate.
    let dep: u16 = kani::any();
    kani::assume(dep >= 1_000 && dep <= 5_000);
    let idx = add_user_test(&mut engine, 0).unwrap() as usize;
    engine
        .deposit_not_atomic(idx as u16, dep as u128, DEFAULT_SLOT)
        .unwrap();
    // Deposit increased vault and c_tot equally; bump vault further so the
    // residual (V - C - I) is strictly positive.
    let extra: u16 = kani::any();
    kani::assume(extra >= 1_000 && extra <= 5_000);
    engine.vault = U128::new(engine.vault.get() + extra as u128);

    // Threshold (in scaled bps) chosen so a small `consumption_pre` already
    // crosses it and forces the slow lane.
    let threshold_whole_bps: u8 = kani::any();
    kani::assume(threshold_whole_bps >= 1);
    let threshold_scaled = (threshold_whole_bps as u128) * PRICE_MOVE_CONSUMPTION_SCALE;
    let consumption_pre: u128 = threshold_scaled.saturating_add(1);

    engine.rr_cursor_position = 0;
    engine.sweep_generation = 0;
    engine.price_move_consumed_bps_this_generation = consumption_pre;

    // Constant oracle / slot so the crank does not absorb any new
    // consumption (bug trigger pattern).
    let oracle_price: u32 = kani::any();
    kani::assume(oracle_price > 0);
    kani::assume((oracle_price as u64) <= MAX_ORACLE_PRICE);
    engine.last_oracle_price = oracle_price as u64;
    engine.fund_px_last = oracle_price as u64;

    let admit_h_min: u64 = 1;
    let admit_h_max: u64 = engine.params.h_max;

    // ------------------------------------------------------------------
    // PRE-CRANK admission decision (slow-lane proof).
    // ------------------------------------------------------------------
    let mut ctx_pre = InstructionContext::new_with_admission_and_threshold(
        admit_h_min,
        admit_h_max,
        Some(threshold_whole_bps as u128),
    );
    let h_eff_pre = engine
        .admit_fresh_reserve_h_lock(idx, 1u128, &mut ctx_pre, admit_h_min, admit_h_max);
    kani::assume(h_eff_pre.is_ok());
    let h_pre = h_eff_pre.unwrap();
    // Filter to states where the slow lane was actually engaged pre-crank.
    kani::assume(h_pre == admit_h_max);

    // ------------------------------------------------------------------
    // Attacker crank — same slot, same price, no real volatility.
    // ------------------------------------------------------------------
    let init_slot = engine.current_slot;
    engine.last_market_slot = init_slot;
    let rr_window_size = engine.params.max_accounts;
    let candidates: [(u16, Option<LiquidationPolicy>); 0] = [];

    let r = engine.keeper_crank_not_atomic(
        init_slot,
        oracle_price as u64,
        &candidates,
        0,
        0i128,
        admit_h_min,
        admit_h_max,
        None,                 // no threshold gate on the crank itself
        rr_window_size,
    );
    kani::assume(r.is_ok());

    // The bug fires on this call.
    kani::assume(engine.sweep_generation == 1);
    kani::assume(engine.price_move_consumed_bps_this_generation == 0);

    // ------------------------------------------------------------------
    // POST-CRANK admission decision (should remain slow lane if safe).
    // ------------------------------------------------------------------
    let mut ctx_post = InstructionContext::new_with_admission_and_threshold(
        admit_h_min,
        admit_h_max,
        Some(threshold_whole_bps as u128),
    );
    let h_eff_post = engine
        .admit_fresh_reserve_h_lock(idx, 1u128, &mut ctx_post, admit_h_min, admit_h_max);
    kani::assume(h_eff_post.is_ok());
    let h_post = h_eff_post.unwrap();

    // SAFETY CLAIM (the one Kani should refute):
    //   "If the slow lane was engaged pre-crank, the lane decision MUST
    //    remain slow post-crank when no real volatility was absorbed."
    //
    // Encoded as: post must equal pre.
    assert!(
        h_post == admit_h_max,
        "Bug #1 downstream: cursor wrap flipped admission from slow to fast lane"
    );
}
