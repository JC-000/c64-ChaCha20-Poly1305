#!/usr/bin/env python3
"""bench_turbo_sweep.py — wall-clock turbo-scaling sweep on Ultimate hardware.

Issue #44: confirm the AEAD hot paths carry no wall-clock-anchored floor
(REU DMA or other ~1 MHz-anchored work) by benching the same PRG at
multiple CPU turbo speeds on an Ultimate 64 / C64 Ultimate.

Method: the CIA #1 chained Timer A+B wrapper (shared with
benchmark_chacha20_poly1305.py) counts CIA ticks. On Ultimate hardware
the CIA keeps ticking at the stock PAL phi2 rate (~985 kHz) regardless
of CPU turbo, so ticks are approximately wall-clock microseconds. If a
routine scales cleanly with CPU clock, ticks at N MHz ~= ticks at
1 MHz / N; any speed-invariant component (REU DMA, I/O-anchored waits)
shows up as a floor that does not divide. Wrapper overhead is
re-calibrated at every speed (the CIA-arming I/O stores do not scale
with CPU clock, so overhead is speed-dependent).

All samples for all speeds are taken within a single power-on session,
per the c64-nist-curves finding that the U64 jiffy/CIA rate can drift
slightly at 48 MHz relative to other runs — within-run ratios are clean.

Usage:
    U64_HOST=... python3 tools/bench_turbo_sweep.py \
        [--speeds 1,16,48,64] [--samples 3] [--md docs/BENCH_TURBO_SWEEP.md]

U64-only (turbo has no VICE equivalent). Requires a prior
`make profile-a` (or profile-b) build. Always restores turbo to 1 MHz
on exit — the device is shared and leftover turbo state corrupts other
agents' CIA-based measurements (see project memory).
"""

import argparse
import os
import sys
import time

from c64_test_harness import (
    Labels,
    create_manager,
    wait_for_text,
    write_bytes,
    keyboard,
)
from c64_test_harness.backends.ultimate64_helpers import set_turbo_mhz

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import benchmark_chacha20_poly1305 as bench  # noqa: E402
from _u64_helpers import run_subroutine  # noqa: E402

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
)
DEFAULT_BUILD_PRG = os.path.join(
    PROJECT_ROOT, "build", "c64_chacha20_poly1305.prg"
)
DEFAULT_BUILD_LBL = os.path.join(PROJECT_ROOT, "build", "labels.txt")

# PAL phi2 — CIA tick rate on Ultimate hardware regardless of CPU turbo.
CIA_HZ = 985_248.0


def _routine_targets(target, labels):
    """(name, wrapper_target_addr, n_samples_multiplier) triples.

    Setups are re-run per speed: poly1305_block's shim install and
    aead_encrypt's buffer seeding are idempotent, and poly1305_init /
    state priming are cheap at any speed.
    """
    transport = target.transport
    out = []

    bench.setup_chacha20_block(transport, labels)
    out.append(("chacha20_block", labels["chacha20_block"], 5))

    addr = bench._u64_setup_poly1305_block(target, labels)
    out.append(("poly1305_block", addr, 5))

    addr = bench.setup_aead_encrypt(transport, labels, 1024)
    out.append(("aead_encrypt n=1024", addr, 1))

    return out


def run_sweep(speeds, samples):
    labels = Labels.from_file(DEFAULT_BUILD_LBL)
    rows = []  # (speed, name, ticks_min, spread)
    skipped = []
    mgr = create_manager(backend="u64")
    with mgr:
        with mgr.instance() as target:
            transport = target.transport
            client = getattr(transport, "client", None) or transport._client
            product = client.get_info().get("product", "unknown")
            print(f"Device: {product}")

            client.reset()
            time.sleep(2.0)
            set_turbo_mhz(client, 1)
            try:
                _ = wait_for_text(transport, "READY", timeout=30.0)
                with open(DEFAULT_BUILD_PRG, "rb") as f:
                    prg = f.read()
                load_addr = prg[0] | (prg[1] << 8)
                write_bytes(transport, load_addr, prg[2:])
                keyboard.send_text(transport, "RUN\r")
                time.sleep(2.0)
                _ = wait_for_text(transport, "READY", timeout=30.0)

                bench.install_wrapper(transport)

                for mhz in speeds:
                    try:
                        set_turbo_mhz(client, mhz)
                    except Exception as exc:  # firmware-rejected speed
                        skipped.append((mhz, str(exc)))
                        print(f"-- {mhz} MHz: rejected by firmware "
                              f"({exc}); skipping")
                        continue
                    time.sleep(0.5)
                    overhead, spread = bench._u64_calibrate(
                        target, samples=15
                    )
                    print(f"-- {mhz} MHz: wrapper overhead {overhead} "
                          f"ticks (spread {spread})")

                    for name, addr, mult in _routine_targets(target, labels):
                        bench.patch_target(transport, addr)
                        vals = []
                        for _ in range(samples * mult):
                            run_subroutine(
                                target, bench.LONG_WRAPPER_ADDR,
                                timeout=600.0,
                            )
                            vals.append(
                                bench.read_timer(transport) - overhead
                            )
                        ticks = min(vals)
                        rows.append(
                            (mhz, name, ticks, max(vals) - ticks)
                        )
                        print(f"   {name:22s} {ticks:>9d} ticks "
                              f"(~{ticks / CIA_HZ * 1e3:.2f} ms wall, "
                              f"spread {max(vals) - ticks})")
            finally:
                # Device is shared: never leave turbo enabled.
                set_turbo_mhz(client, 1)
    return product, rows, skipped


def render_md(product, rows, samples):
    speeds = sorted({r[0] for r in rows})
    names = []
    for r in rows:
        if r[1] not in names:
            names.append(r[1])
    base = {r[1]: r[2] for r in rows if r[0] == 1}

    lines = []
    lines.append(f"| routine | " + " | ".join(
        f"{s} MHz wall" for s in speeds) + " | speedup @ max | ideal |")
    lines.append("|---------" + "|--------:" * (len(speeds) + 2) + "|")
    for name in names:
        cells = []
        for s in speeds:
            ticks = next(
                (r[2] for r in rows if r[0] == s and r[1] == name), None
            )
            cells.append(
                f"{ticks / CIA_HZ * 1e3:,.2f} ms" if ticks else "n/a"
            )
        smax = speeds[-1]
        tmax = next(
            (r[2] for r in rows if r[0] == smax and r[1] == name), None
        )
        if tmax and name in base:
            cells.append(f"**{base[name] / tmax:.1f}x**")
            cells.append(f"{smax}x")
        else:
            cells.extend(["n/a", "n/a"])
        lines.append(f"| `{name}` | " + " | ".join(cells) + " |")
    header = (
        f"Measured on {product}, CIA #1 chained-timer wrapper "
        f"(ticks ~= wall-clock at PAL phi2 regardless of turbo), min of "
        f"{samples} samples per cell, single power-on session, "
        f"`tools/bench_turbo_sweep.py`.\n\n"
    )
    return header + "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--speeds", default="1,16,48,64",
                    help="comma-separated turbo MHz values (default "
                         "1,16,48,64; 1 is the scaling anchor)")
    ap.add_argument("--samples", type=int, default=3)
    ap.add_argument("--md", default=None,
                    help="write a markdown table to this path")
    args = ap.parse_args()

    speeds = [int(s) for s in args.speeds.split(",")]
    if speeds[0] != 1:
        sys.exit("--speeds must start with 1 (the scaling anchor)")
    if not os.path.exists(DEFAULT_BUILD_PRG):
        sys.exit(f"{DEFAULT_BUILD_PRG} not found — run `make profile-a` "
                 f"(or profile-b) first")
    if not (os.environ.get("U64_HOST")):
        sys.exit("U64_HOST not set (this sweep is hardware-only)")
    os.environ.setdefault("C64_BACKEND", "u64")

    product, rows, skipped = run_sweep(speeds, args.samples)

    md = render_md(product, rows, args.samples)
    print("\n" + md)
    if skipped:
        print("Skipped speeds: " +
              ", ".join(f"{m} MHz ({why})" for m, why in skipped))
    if args.md:
        with open(args.md, "w") as f:
            f.write(md)
        print(f"Wrote {args.md}")


if __name__ == "__main__":
    main()
