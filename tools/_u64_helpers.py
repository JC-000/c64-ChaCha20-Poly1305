"""Backend-agnostic JSR shim and U64 cycle measurement helpers.

The c64-test-harness ``jsr()`` requires a binary monitor breakpoint and is
VICE-only. On Ultimate 64 we install a flag-driven trampoline at $0360 and
poll a sentinel byte to detect completion. The four v0.4.0 tools that
exercise ChaCha20-Poly1305 use ``run_subroutine()`` so the same call sites
work on both backends.

Trampoline layout at $0360 (24 bytes), built once per session::

    $0360: 20 LO HI       JSR <target>             ; user routine
    $0363: 8D 51 03       STA $0351                ; reflect A -> status
    $0366: A9 42          LDA #$42
    $0368: 8D 50 03       STA $0350                ; sentinel = $42 (done)
    $036B: AD 52 03       LDA $0352                ; read re-arm flag
    $036E: F0 FB          BEQ $036B                ; park while flag = 0
    $0370: A9 00          LDA #$00
    $0372: 8D 52 03       STA $0352                ; clear flag
    $0375: 4C 60 03       JMP $0360                ; restart for next run

State scratch:
    $0350 sentinel       ($00 -> $42 done)
    $0351 status         (post-JSR A reflection)
    $0352 re-arm flag    (host writes $01 to fire next iteration)

Re-arm protocol per call: rewrite the JSR operand if the target changed,
zero the sentinel, then write $01 to $0352. The CPU exits the parking
BEQ, clears the flag, and re-enters the trampoline body.

Initial trigger after run_prg(): install the trampoline, then drive
``SYS 864`` through the keyboard buffer via ``send_text``. BASIC executes
the SYS, the CPU enters $0360, and parks at $036B awaiting re-arms.
"""

from __future__ import annotations

import socket
import time
from typing import Any

from c64_test_harness import (
    execute as _execute,
    keyboard as _keyboard,
    read_bytes,
    write_bytes,
)


_SENTINEL_DONE = 0x42
_REARM_FIRE = 0x01
_STATE_ATTR = "_u64_shim_state"


class _SessionState:
    """Per-target trampoline bookkeeping (attached as a private attribute)."""

    __slots__ = ("installed", "last_addr")

    def __init__(self) -> None:
        self.installed = False
        self.last_addr: int | None = None


def _get_state(target: Any) -> _SessionState:
    s = getattr(target, _STATE_ATTR, None)
    if s is None:
        s = _SessionState()
        setattr(target, _STATE_ATTR, s)
    return s


def _build_trampoline(
    addr: int,
    sentinel_addr: int,
    status_addr: int,
    rearm_addr: int,
    trampoline_addr: int,
) -> bytes:
    return bytes([
        0x20, addr & 0xFF, (addr >> 8) & 0xFF,
        0x8D, status_addr & 0xFF, (status_addr >> 8) & 0xFF,
        0xA9, _SENTINEL_DONE,
        0x8D, sentinel_addr & 0xFF, (sentinel_addr >> 8) & 0xFF,
        0xAD, rearm_addr & 0xFF, (rearm_addr >> 8) & 0xFF,
        0xF0, 0xFB,
        0xA9, 0x00,
        0x8D, rearm_addr & 0xFF, (rearm_addr >> 8) & 0xFF,
        0x4C, trampoline_addr & 0xFF, (trampoline_addr >> 8) & 0xFF,
    ])


def _u64_install_and_trigger(
    target: Any,
    addr: int,
    sentinel_addr: int,
    status_addr: int,
    rearm_addr: int,
    trampoline_addr: int,
) -> None:
    """Write the full trampoline and inject SYS <trampoline_addr> via the keyboard buffer."""
    transport = target.transport
    code = _build_trampoline(addr, sentinel_addr, status_addr, rearm_addr, trampoline_addr)
    write_bytes(transport, trampoline_addr, code)
    write_bytes(transport, sentinel_addr, bytes([0x00]))
    write_bytes(transport, status_addr, bytes([0x00]))
    write_bytes(transport, rearm_addr, bytes([0x00]))
    _ = read_bytes(transport, sentinel_addr, 1)
    _keyboard.send_text(transport, f"SYS {trampoline_addr}\r")


def _u64_rearm(
    target: Any,
    addr: int,
    last_addr: int | None,
    sentinel_addr: int,
    status_addr: int,
    rearm_addr: int,
    trampoline_addr: int,
) -> None:
    """Re-arm a parked trampoline for another iteration."""
    transport = target.transport
    if addr != last_addr:
        write_bytes(transport, trampoline_addr + 1, bytes([addr & 0xFF, (addr >> 8) & 0xFF]))
    write_bytes(transport, sentinel_addr, bytes([0x00]))
    write_bytes(transport, status_addr, bytes([0x00]))
    _ = read_bytes(transport, sentinel_addr, 1)
    write_bytes(transport, rearm_addr, bytes([_REARM_FIRE]))


def _u64_poll_sentinel(target: Any, sentinel_addr: int, timeout: float) -> None:
    transport = target.transport
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if read_bytes(transport, sentinel_addr, 1)[0] == _SENTINEL_DONE:
            return
        time.sleep(0.05)
    raise TimeoutError(
        f"U64 trampoline did not complete within {timeout}s at sentinel ${sentinel_addr:04X}"
    )


def run_subroutine(
    target: Any,
    addr: int,
    *,
    client: Any | None = None,
    timeout: float = 30.0,
    sentinel_addr: int = 0x0350,
    status_addr: int = 0x0351,
    trampoline_addr: int = 0x0360,
    rearm_addr: int = 0x0352,
) -> int:
    """Call ``addr`` on either backend; return register A (or its U64 reflection)."""
    backend = getattr(target, "backend", None)
    transport = target.transport
    if backend == "vice":
        regs = _execute.jsr(transport, addr, timeout=timeout)
        return int(regs.get("a", regs.get("A", 0)) or 0)
    if backend != "u64":
        raise ValueError(f"unsupported target.backend {backend!r}")

    s = _get_state(target)
    if not s.installed:
        _u64_install_and_trigger(
            target, addr, sentinel_addr, status_addr, rearm_addr, trampoline_addr,
        )
        s.installed = True
        s.last_addr = addr
    else:
        _u64_rearm(
            target, addr, s.last_addr,
            sentinel_addr, status_addr, rearm_addr, trampoline_addr,
        )
        s.last_addr = addr

    _u64_poll_sentinel(target, sentinel_addr, timeout)
    return int(read_bytes(transport, status_addr, 1)[0])


def _local_ip_for(host: str) -> str:
    """Return the local IP that would route to *host* (for stream destination)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((host, 9))
        return s.getsockname()[0]
    finally:
        s.close()


def measure_cycles(
    target: Any,
    client: Any,
    addr: int,
    *,
    samples: int = 5,
    mhz: int = 1,
    capture_port: int = 11002,
    capture_settle_seconds: float = 0.5,
    capture_drain_seconds: float = 0.5,
    per_iteration_timeout: float = 30.0,
) -> list[int]:
    """Run ``addr`` ``samples`` times under DebugCapture and return cycle deltas."""
    backend = getattr(target, "backend", None)
    if backend != "u64":
        raise RuntimeError(f"measure_cycles requires u64 backend, got {backend!r}")
    if client is None:
        raise ValueError("client is required for measure_cycles on u64")

    from c64_test_harness import set_turbo_mhz
    from c64_test_harness.backends.u64_debug_capture import DebugCapture

    if mhz != 1:
        raise ValueError("DebugCapture is only cycle-accurate at 1 MHz")
    set_turbo_mhz(client, mhz)
    time.sleep(capture_settle_seconds)

    local = _local_ip_for(client.host)
    deltas: list[int] = []
    cap = DebugCapture(port=capture_port)
    cap.start()
    started = False
    try:
        client.stream_debug_start(f"{local}:{capture_port}")
        started = True
        for _ in range(samples):
            run_subroutine(target, addr, client=client, timeout=per_iteration_timeout)
            time.sleep(capture_settle_seconds)
    finally:
        if started:
            try:
                client.stream_debug_stop()
            except Exception:
                pass
        time.sleep(capture_drain_seconds)
        result = cap.stop()

    cycles_per_sample = result.total_cycles // max(samples, 1)
    for _ in range(samples):
        deltas.append(cycles_per_sample)
    return deltas
