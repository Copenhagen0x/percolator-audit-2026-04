# Recommended patch — uniform overflow class fix

**Scope**: closes Bug #2, Bug #3, and the Sibling B reachability concern in three one-token swaps.

**Cost**: zero. The U256-intermediate helper (`wide_mul_div_floor_u128`) already exists in `src/wide_math.rs` (defined at line 1618) and is already in scope in `src/percolator.rs` (`use wide_math::{...wide_mul_div_floor_u128, ...}` at line 158, already used at lines 3625, 3771, 6287, 6847).

**Output range**: unchanged. All three sites produce a quotient that's mathematically bounded ≤ smaller operand (which fits in u128 per existing engine invariants). The wide variant only widens the *intermediate product*, not the final result.

---

## The diff

### Site 1 — Bug #2 (`advance_profit_warmup`, engine line 4680)

```diff
@@ src/percolator.rs:4677-4681 @@
         let sched_total = if elapsed >= a.sched_horizon as u128 {
             a.sched_anchor_q
         } else {
-            mul_div_floor_u128(a.sched_anchor_q, elapsed, a.sched_horizon as u128)
+            wide_mul_div_floor_u128(a.sched_anchor_q, elapsed, a.sched_horizon as u128)
         };
```

**Why safe**: quotient is bounded by `sched_anchor_q ≤ MAX_ACCOUNT_POSITIVE_PNL = 1e32` (engine constant at `src/percolator.rs:138`). 1e32 < u128::MAX = ~3.4e38. The wide variant's `try_into_u128()` post-check (`wide_math.rs:1622-1623`) will never fail at this site.

---

### Site 2 — Bug #3 (`account_equity_trade_open_raw`, engine line 3915)

```diff
@@ src/percolator.rs:3914-3915 @@
             let g_num = core::cmp::min(residual, pnl_pos_tot_trade_open);
-            mul_div_floor_u128(pos_pnl_trade_open, g_num, pnl_pos_tot_trade_open)
+            wide_mul_div_floor_u128(pos_pnl_trade_open, g_num, pnl_pos_tot_trade_open)
         };
```

**Why safe**: quotient is `pos_pnl_trade_open × g_num / pnl_pos_tot_trade_open`. Since `g_num = min(residual, pnl_pos_tot_trade_open) ≤ pnl_pos_tot_trade_open`, the quotient is bounded by `pos_pnl_trade_open ≤ MAX_ACCOUNT_POSITIVE_PNL = 1e32 < u128::MAX`. Wide post-check never fires.

---

### Site 3 — Sibling B (`effective_pos_q_checked`, engine line 2642) — defense-in-depth

```diff
@@ src/percolator.rs:2641-2642 @@
         let abs_basis = basis.unsigned_abs();
-        let effective_abs = mul_div_floor_u128(abs_basis, a_side, a_basis);
+        let effective_abs = wide_mul_div_floor_u128(abs_basis, a_side, a_basis);
```

**Why safe**: the existing post-check at line 2644 (`if effective_abs > i128::MAX as u128 { return Err(RiskError::CorruptState); }`) already validates the quotient is ≤ i128::MAX < u128::MAX. Wide post-check would also pass.

**Note**: this site is currently safe under the public API (cap enforced at all real callers — see DISCLOSURE.md Sibling B section). Patching it is defense-in-depth: removes the "if any future caller bypasses the cap" reachability concern and prevents the same overflow class from re-emerging if MAX_VAULT_TVL or MAX_ACCOUNT_POSITIVE_PNL are ever raised.

---

## Verification plan

After applying the three swaps, the four CEX harnesses that currently FAIL should turn green:

1. `proof_advance_profit_warmup_does_not_panic` — currently CEX, would PASS post-patch (Bug #2 closed)
2. `proof_trade_open_raw_g_num_does_not_panic` — currently CEX, would PASS post-patch (Bug #3 closed)
3. `proof_risk_notional_from_eff_q_does_not_panic` — currently CEX, would PASS post-patch (transitive: this harness reaches the Sibling B site through `try_notional`)
4. `proof_effective_pos_q_does_not_panic` — currently CEX, would PASS post-patch (Sibling B closed)

The native PoC tests should also flip behavior:
- `v9_advance_profit_warmup_native_mul_panic` (currently `#[should_panic]`) — would need `#[should_panic]` REMOVED post-patch (no longer panics)
- `v11_l1_trade_open_raw_native_mul_panic` (currently `#[should_panic]`) — same

LiteSVM tests are unaffected (they exercise normal-sized state, no panic either way).

Toly's existing 305-harness baseline is unaffected (none of those harnesses test these three sites for overflow).

## Equivalent `mul_div_ceil_u128` consideration

The same panic class exists in `mul_div_ceil_u128` (defined at `wide_math.rs:1605`, panic at line 1607). We audited 30 invocations total in `src/percolator.rs` (see DISCLOSURE.md "Prevention-class fix" section): 19 narrow `mul_div_floor_u128`, 6 narrow `mul_div_ceil_u128`, plus 5 already using the wide variants. Only the three narrow callers above produce intermediate products that can exceed u128::MAX under engine-permitted state. The remaining 22 narrow callers are bounded safely by their input domains and don't need the wide variant.

If you want to take a stricter "no `mul_div_floor/ceil` outside wide variants anywhere in safety-critical paths" stance, that's a separate refactor; the three swaps above close the actually-unsafe sites.

## Single-commit suggestion

```
Subject: arith: use wide intermediate at three mul_div_floor_u128 sites

Three call sites in `src/percolator.rs` produce intermediate products
that can exceed u128::MAX under engine-permitted state:

  - src/percolator.rs:4680  (advance_profit_warmup)
  - src/percolator.rs:3915  (account_equity_trade_open_raw)
  - src/percolator.rs:2642  (effective_pos_q_checked)

Swap each to wide_mul_div_floor_u128 (already in scope, already used
at lines 3625, 3771, 6287, 6847). Quotient is bounded by the smaller
operand at each site, so output range is unchanged and the wide
variant's try_into_u128 post-check cannot fail.
```
