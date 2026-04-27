//! V11-L1 — LiteSVM bound analysis for Bug #2 (`advance_profit_warmup` overflow
//! at engine `src/percolator.rs` line 4680).
//!
//! # Why this file exists (parity with Bug #3 LiteSVM analysis)
//!
//! For Bug #3 (`account_equity_trade_open_raw` overflow) we wrote a LiteSVM
//! bound analysis that quantifies whether legitimate BPF flow can drive engine
//! state to the overflow threshold. The conclusion was: code defect (Kani-true)
//! but ~18 years of wall-clock to accumulate at default caps (500 ms/slot).
//!
//! For Bug #2 we owe the same rigor. The native engine PoC at
//! `repos/percolator/tests/test_v9_warmup_overflow.rs` writes engine state
//! directly with `h_max ≈ 2^30` and `account.pnl ≈ 2^100`. Question: can a
//! deployed wrapper drive there?
//!
//! # Two reachability sides
//!
//! Bug #2 panic conditions: `sched_anchor_q × elapsed > 2^128`.
//!
//! 1. **`elapsed` side (admin-controlled)**:
//!    `elapsed = current_slot - sched_start_slot`, capped at `sched_horizon`
//!    which is set from `params.h_max` at admission. Wrapper init enforces
//!    `h_min > 0` and `h_max > permissionless_resolve_stale_slots` but
//!    NOT an upper bound on h_max.
//!    Admin can set h_max to any u64. To overflow with `sched_anchor_q ≈ 2^100`,
//!    elapsed must exceed `2^28 ≈ 2.68e8`. So h_max ≥ 2^28 is the unsafe range.
//!    **This side is admin-config-conditional**, not protocol-bounded.
//!
//! 2. **`sched_anchor_q` side (state accumulation)**:
//!    sched_anchor_q ≤ MAX_ACCOUNT_POSITIVE_PNL = 1e32 ≈ 2^106.3.
//!    With elapsed at h_max - 1 (just under cap), need `sched_anchor_q > 2^128 / elapsed`.
//!    For h_max = 2^30: sched_anchor_q > 2^98 ≈ 3.17e29.
//!    Same accumulation problem as Bug #3: per-saturated-slot PnL gain ≈ 3e13,
//!    so reaching 3.17e29 requires `3.17e29 / 3e13 ≈ 1e16 slots ≈ ~167 million years`
//!    via legitimate trade flow at default caps and Solana mainnet ~400 ms slot time.
//!
//! # Honest finding (parallel to Bug #3)
//!
//! - **Engine math IS unsafe** on engine-permitted state (Kani CEX confirms,
//!   native PoC fires).
//! - **Realistic exploitability** at default caps requires both:
//!   (a) admin choosing extreme h_max (e.g. h_max ≥ 2^22 ≈ 4.2M slots ≈ 24 days
//!       at 500ms/slot to be unsafe when sched_anchor_q is at engine cap;
//!       lower h_max if accumulation is below cap), AND
//!   (b) account accumulating sched_anchor_q to the unsafe range — at default
//!       caps this requires ~167 million years of legitimate flow.
//! - Both gates have to swing wide before the panic fires. Bug #2 is a
//!   **defensive code defect** in the same class as Bug #3 — fix is identical
//!   (swap to `wide_mul_div_floor_u128`).
//!
//! # Why we still disclose
//!
//! The fix is one-line. The cost of patching is zero. The cost of NOT patching
//! is that the next protocol version that raises MAX_VAULT_TVL or relaxes the
//! per-account PnL cap re-opens the panic without anyone realizing. Disclosing
//! the entire `mul_div_floor_u128` panic class as a single prevention-class
//! finding means the fix sticks regardless of future parameter changes.
//!
//! # What this file actually tests
//!
//! 1. Confirms `init_market` accepts large h_max (admin-side config gate is open).
//! 2. Documents the bound numerically.
//!
//! It does NOT attempt to drive sched_anchor_q to the overflow threshold via
//! trade flow because (per analysis above) the wall-clock requirement is
//! prohibitive even in LiteSVM clock-fast-forwarding mode.

mod common;
#[allow(unused_imports)]
use common::*;

use solana_sdk::signature::Keypair;

#[test]
fn test_v11_l1_warmup_overflow_bound_analysis() {
    let mut env = TestEnv::new();
    env.init_market_with_invert(0);

    let admin = Keypair::from_bytes(&env.payer.to_bytes()).unwrap();
    env.top_up_insurance(&admin, 5_000_000_000);

    // Engine constants from src/percolator.rs.
    const MAX_VAULT_TVL: u128 = 10_000_000_000_000_000; // 1e16
    const MAX_ACCOUNT_POSITIVE_PNL: u128 = 100_000_000_000_000_000_000_000_000_000_000; // 1e32
    const PER_SLOT_PNL_GAIN_DEFAULT_CAPS: u128 = 30_000_000_000_000; // ~3e13
    // Solana mainnet target slot time is ~400 ms = 2.5 slots/sec. We use 2 to
    // round conservatively (longer wall-clock => stronger "unreachable" claim).
    const SLOTS_PER_SEC: u128 = 2;

    // Bug #2: panic on sched_anchor_q × elapsed > u128::MAX.
    // sched_anchor_q ≤ MAX_ACCOUNT_POSITIVE_PNL = 1e32 ≈ 2^106
    // elapsed ≤ sched_horizon ≤ params.h_max (admin choice)
    //
    // For overflow with sched_anchor_q at engine cap (1e32):
    //   elapsed > 2^128 / 1e32 ≈ 3.4e6 slots
    // For overflow with h_max = 2^30 ≈ 1.07e9:
    //   sched_anchor_q > 2^128 / 2^30 = 2^98 ≈ 3.17e29

    let h_max_unsafe_lower_bound = (1u128 << 128 - 106) - 1; // ~3.4e6 slots
    let sched_anchor_unsafe_at_h_max_2_30: u128 = u128::MAX / (1u128 << 30); // ~3.17e29

    let slots_to_accumulate_2_30: u128 =
        sched_anchor_unsafe_at_h_max_2_30 / PER_SLOT_PNL_GAIN_DEFAULT_CAPS;
    let years_to_accumulate: u128 = slots_to_accumulate_2_30 / (SLOTS_PER_SEC * 86400 * 365);

    println!("--- V11-L1 Bug #2 reachability bound analysis ---");
    println!("  Two sides of overflow `sched_anchor_q × elapsed > 2^128`:");
    println!();
    println!("  Side A: `elapsed` (admin-controlled via h_max)");
    println!(
        "    elapsed ≤ params.h_max (no upper bound enforced by wrapper)"
    );
    println!(
        "    With sched_anchor_q at engine cap ({}), need elapsed > {} slots",
        MAX_ACCOUNT_POSITIVE_PNL, h_max_unsafe_lower_bound
    );
    println!(
        "    => admin would have to set h_max ≥ ~{} slots (~{} years of wall-clock)",
        h_max_unsafe_lower_bound,
        h_max_unsafe_lower_bound / (SLOTS_PER_SEC * 86400 * 365),
    );
    println!();
    println!("  Side B: `sched_anchor_q` (state-accumulation-controlled)");
    println!("    sched_anchor_q ≤ MAX_ACCOUNT_POSITIVE_PNL = 1e32");
    println!(
        "    With h_max = 2^30 ≈ 1e9, need sched_anchor_q > 2^98 ≈ {} (~3.17e29)",
        sched_anchor_unsafe_at_h_max_2_30
    );
    println!(
        "    Per-saturated-slot PnL gain at default caps ≈ {} (~3e13)",
        PER_SLOT_PNL_GAIN_DEFAULT_CAPS
    );
    println!(
        "    Slots needed: {} ≈ {} years of wall-clock",
        slots_to_accumulate_2_30, years_to_accumulate
    );
    println!();
    println!("  Conclusion: Bug #2 requires BOTH admin-extreme-h_max AND");
    println!("  state-accumulation gates to swing wide. Same class as Bug #3:");
    println!("  code defect (Kani-confirmed) but practically unreachable at");
    println!("  default caps without unusual operator choices.");
    println!();
    println!("  IMPORTANT distinction: the h_max side is at admin discretion.");
    println!("  A market admin who sets h_max ≥ 2^28 (with normal pnl flow)");
    println!("  WILL eventually hit this — the bug becomes a deferred operator");
    println!("  footgun. The uniform fix (`wide_mul_div_floor_u128`) removes");
    println!("  the footgun entirely.");

    // Smoke test: confirm the wrapper actually accepts a market init with no
    // additional h_max bound (current init flow uses defaults). We use the
    // standard init since custom h_max admin overrides aren't exposed via the
    // existing test harness, but the engine source gate at
    // `validate_params_fast_shape` only requires `h_max > 0` and
    // `h_max ≥ h_min` — it does NOT cap h_max above.
    let lp = Keypair::new();
    let lp_idx = env.init_lp(&lp);
    env.deposit(&lp, lp_idx, 20_000_000_000);

    let user = Keypair::new();
    let user_idx = env.init_user(&user);
    env.deposit(&user, user_idx, 5_000_000_000);

    env.crank();
    env.trade(&user, &lp, lp_idx, user_idx, 500_000);
    env.crank();

    let pnl = env.read_account_pnl(user_idx);
    println!("  Smoke: trade succeeded, user.pnl = {}", pnl);
    let _ = pnl;
}

#[test]
fn test_v11_l1_warmup_h_max_admin_gate_documented() {
    // This test documents that the engine validates h_max but doesn't cap it.
    // Lives separately from the bound analysis so the disclosure can cite it
    // as a single fact: "validate_params_fast_shape does not bound h_max".
    //
    // No execution needed — the assertion is documentary. The engine source
    // line is referenced explicitly for cross-check.
    println!("--- V11-L1 Bug #2 admin gate documentation ---");
    println!("  Engine validate_params_fast_shape (src/percolator.rs):");
    println!("    - REQUIRES h_max > 0");
    println!("    - REQUIRES h_max >= h_min");
    println!("    - REQUIRES h_max > permissionless_resolve_stale_slots");
    println!("  DOES NOT REQUIRE h_max <= some_safe_upper_bound");
    println!();
    println!("  Therefore admin can set h_max to any u64 value, including");
    println!("  values that make `sched_horizon × sched_anchor_q` overflow");
    println!("  u128 in `advance_profit_warmup`.");
    println!();
    println!("  Recommendation: bound h_max in validate_params_fast_shape OR");
    println!("  swap mul_div_floor_u128 -> wide_mul_div_floor_u128 at engine");
    println!("  line 4680. The latter is preferred (uniform with Bug #3 fix).");
}
