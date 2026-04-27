# Kani baseline re-run — the existing harnesses against current main

This directory contains the raw output of re-running the full Kani proof suite (`cargo kani --tests --features test`) from `aeyakovenko/percolator` @ `5940285` against current main.

**Headline result: Toly baseline = 305/305 PASS, 0 regressions.**

## Files

| File | What it is |
|---|---|
| [`kani_baseline_summary.txt`](./kani_baseline_summary.txt) | Headline + per-harness breakdown + sanity-check math (start here) |
| [`kani_baseline_timings.tsv`](./kani_baseline_timings.tsv) | One row per harness: `name<TAB>verdict<TAB>seconds`. 321 rows |
| [`kani_baseline_full.log.gz`](./kani_baseline_full.log.gz) | Raw `cargo kani` stdout/stderr, gzip-compressed (8.1 MB compressed, 173 MB uncompressed) |

## How to read the numbers

`cargo kani --tests --features test` automatically picks up every file in `tests/` matching `proofs_*.rs` with `#[kani::proof]` annotations. We dropped 5 new test files into the engine's `tests/` directory during the audit, contributing 16 additional harnesses to the sweep. The summary file separates Toly's baseline (305 harnesses) from our additions (16 harnesses) so the regression-check math is obvious.

| | Total | PASS | FAIL |
|---|---|---|---|
| **Toly baseline** | 305 | **305** | **0** |
| Our additions | 16 | 10 (SAFE proofs) | 6 (3 expected CEXes + 3 unwind-noise — see summary file) |
| **Combined run** | 321 | 315 | 6 |

**Environment**: Hetzner VPS (6-core, Ubuntu 22.04, Kani 0.67.0, Rust 1.95). Identical toolchain to local audit environment.

**Walltime**: ~3h 53min serial (start 21:25 local Sunday, end 01:18 local Monday).

## Reproduction

```bash
git clone https://github.com/aeyakovenko/percolator
cd percolator
git checkout 5940285
# Optionally drop in our additions:
cp /path/to/research-repo/tests/engine/*.rs tests/
cargo kani --tests --features test
```

Expected: same numbers as above, ± a few percent on per-harness times depending on hardware.
