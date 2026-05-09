# Profiles A vs B

Two build variants, selected via the `POLY1305_PROFILE_LONG` ca65 define. One profile per PRG (v0.3.x); v0.4.0 may support bimodal builds.

| Aspect | Profile A (`POLY1305_PROFILE_LONG=1`) | Profile B (undefined) |
|--------|---------------------------------------|----------------------|
| Nickname | "Long-message optimized" | "Short-message optimized" / portable |
| Poly1305 multiply | Shoup per-r tables (272 entries) | Quarter-square + branchless `ct_mul_8x8` |
| RAM tables | `r_tab_lo/hi` at `$6000..$7FFF` (8 KB) + `sqtab` (1 KB) = ~9 KB | `sqtab` only (1 KB) |
| `poly1305_init` | ~186 k cy (incremental Shoup ripple-add, S11) | ~87 k cy (sqtab-only) |
| `poly1305_block` (n=1024) | 11,948 cy | 37,844 cy |
| `aead_encrypt` (n=0) | 186,182 cy | 84,560 cy |
| `aead_encrypt` (n=1024) | 1,686,764 cy (−71.8% vs S0 baseline) | 3,259,490 cy (−45.4% vs S0) |
| Amortization point | ~256 bytes (table-build cost recoups) | N/A |
| REU support | `POLY1305_REU=1` backs sqtab to REU bank 0; restore via `poly1305_reu_restore` | None |
| REU configurability (unreleased) | `POLY1305_REU_BANK` (def 0), `POLY1305_REU_OFFSET` (def `$0000`) — issue #19, PR #20 | N/A |
| Workload fit | WireGuard data packets (~1280 B), TLS 1.3 bulk records | WireGuard handshakes, TLS alerts, stock C64 (no REU) |

**Profile selection rule of thumb**: long-lived sessions with bulk traffic ⇒ A; short bursts or hardware without REU ⇒ B.

## Build internals
- Profile A: `ca65 -DPOLY1305_PROFILE_LONG=1 src/lib/poly1305_lib.s -o build/profile-a/poly1305_lib.o`
- Profile B: same source, no flag, output to `build/profile-b/`.
- `ld65 -C src/c64.cfg -Ln build/profile-X/labels.txt $(X_OBJS) -o build/profile-X/c64_chacha20_poly1305.prg`
- After link, the active profile's PRG + labels are copied to `build/` root for the test harness.

## CT verdict per profile
- Profile A: GREEN — Shoup tables are CT by construction (data-independent indexing).
- Profile B: GREEN as of v0.3.0 — `ct_mul_8x8` is branchless (F3 fix). Design memo: `docs/design/ct_mul_8x8.md`.
