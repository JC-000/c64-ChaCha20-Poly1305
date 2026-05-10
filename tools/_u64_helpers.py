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
    capture_settle_seconds: float = 0.3,
    capture_drain_seconds: float = 0.5,
    per_iteration_timeout: float = 30.0,
    sentinel_addr: int = 0x0350,
    status_addr: int = 0x0351,
    trampoline_addr: int = 0x0360,
    rearm_addr: int = 0x0352,
) -> list[int]:
    """Run ``addr`` ``samples`` times under DebugCapture and return per-sample cycle counts.

    .. warning::

       This path depends on the U64E FPGA UDP debug stream delivering
       at least one cycle for every CPU PHI2 cycle in the capture
       window. On healthy hardware/network at 1 MHz with 6510-only
       mode, delivery ratio is ≈ 1.0 (probed at 1.029 here on a fresh
       boot) and the marker parse hits every JSR/STA pair. After
       sustained workload (e.g. a ~10 min adjacent test agent), the
       same setup degrades to 30-90% delivery, sequence gaps run into
       the thousands, and marker detection fails with a RuntimeError.
       For benchmarking workloads where reliability matters more than
       avoiding 6502 CIA programming, the in-RAM CIA-timer wrapper
       used by ``tools/benchmark_chacha20_poly1305.py`` is the
       fall-back: it shares the same wrapper code with the VICE path
       and is cycle-exact (no UDP / FPGA rate path involved).

    Strategy:

    * Sets debug stream mode to ``"6510 Only"`` so every captured entry is
      one PHI2 CPU cycle with the address bus reflecting the current
      access. VIC cycles are filtered at the FPGA source.
    * Sets CPU turbo to 1 MHz for the capture window — the only setting
      where DebugCapture delivers a near-complete trace (the FPGA's UDP
      emit cap is ~864k entries/sec, comfortably above 1 MHz).
    * Pre-installs the trampoline (one warm-up SYS) BEFORE starting
      capture. This keeps BASIC's SYS-handler activity out of the trace.
    * Runs *samples* re-arms under capture; each re-arm fires exactly one
      JSR through the trampoline.
    * Parses the trace to find marker pairs: the JSR opcode fetch at
      ``trampoline_addr`` (start) and the STA $0351 opcode fetch at
      ``trampoline_addr + 3`` (end). Each pair brackets one routine
      execution.
    * Reports cycle count = (CPU cycles between markers) - 12, matching
      the VICE CIA-timer wrapper convention (which subtracts a JSR + RTS
      calibration baseline = 12 cy).

    The 12-cycle subtraction breaks down as: 6 cy for the JSR opcode
    itself (included in the marker window) + 6 cy for the routine's
    final RTS (included in the routine body). VICE's wrapper measures
    ``JSR target + body + ... + STA $0351`` against ``JSR rts_stub
    + RTS + ... + STA $0351``, so the diff (and our cycle count - 12)
    is the routine body excluding its final RTS.

    :param target: TestTarget with ``backend == "u64"``.
    :param client: Connected ``Ultimate64Client`` (NOT exposed on
        ``TestTarget`` — caller must obtain via ``target.transport._client``
        or by constructing one separately. See module docstring.)
    :param addr: Routine entry-point address.
    :param samples: Number of cycle samples to collect.
    :param mhz: Must be 1 (DebugCapture is cycle-accurate only at 1 MHz).
    :param capture_port: UDP port for the U64 to stream debug entries to.
    :param capture_settle_seconds: Wait between turbo set and capture
        start (FPGA settle time). Also used after stream_debug_start.
    :param capture_drain_seconds: Wait after stream_debug_stop before
        cap.stop() so trailing UDP packets reach us.
    :param per_iteration_timeout: Per-sample sentinel-poll timeout.
    :return: List of *samples* cycle counts.
    """
    backend = getattr(target, "backend", None)
    if backend != "u64":
        raise RuntimeError(f"measure_cycles requires u64 backend, got {backend!r}")
    if client is None:
        raise ValueError("client is required for measure_cycles on u64")

    from c64_test_harness import set_turbo_mhz
    from c64_test_harness.backends.u64_debug_capture import DebugCapture
    from c64_test_harness.backends.ultimate64_helpers import (
        DEBUG_MODE_6510,
        get_debug_stream_mode,
        set_debug_stream_mode,
    )

    if mhz != 1:
        raise ValueError("DebugCapture is only cycle-accurate at 1 MHz")
    if samples < 1:
        raise ValueError("samples must be >= 1")

    # Configure FPGA: 6510-only stream mode (clean CPU traces) + 1 MHz CPU.
    orig_debug_mode = get_debug_stream_mode(client)
    set_debug_stream_mode(client, DEBUG_MODE_6510)
    set_turbo_mhz(client, mhz)
    time.sleep(capture_settle_seconds)

    # Warm-up: pre-install trampoline (or re-arm with new addr) BEFORE
    # capture starts so BASIC SYS-handler noise stays out of the trace.
    # run_subroutine() runs the routine once and parks at the BEQ loop.
    run_subroutine(
        target,
        addr,
        client=client,
        timeout=per_iteration_timeout,
        sentinel_addr=sentinel_addr,
        status_addr=status_addr,
        trampoline_addr=trampoline_addr,
        rearm_addr=rearm_addr,
    )

    local = _local_ip_for(client.host)
    # 8 MiB recv buffer (kern.ipc.maxsockbuf cap on macOS-26) — at 1 MHz
    # with 6510-only mode the FPGA emits at the CPU rate (~4 MB/s of bus
    # cycle entries). The bench interleaves REST calls with capture, and
    # GIL-contended pauses during HTTP round-trips would otherwise overflow
    # the socket buffer (visible as massive
    # ``netstat -s -p udp | grep "full socket buffers"`` deltas). 8 MiB
    # gives ~2 s of headroom which spans the longest single-routine
    # capture window (aead_encrypt n=1024 ≈ 1.7 s wall clock at 1 MHz).
    cap = DebugCapture(port=capture_port, recv_buf_size=8 * 1024 * 1024)
    cap.start()
    started = False
    try:
        client.stream_debug_start(f"{local}:{capture_port}")
        started = True
        # Brief settle so the stream is steady when the first re-arm fires.
        time.sleep(capture_settle_seconds)
        transport = target.transport
        for _ in range(samples):
            # Fast inline re-arm: minimum REST round-trips during the
            # capture window. _u64_rearm does 4 REST calls (zero
            # sentinel + zero status + flush-read + write rearm); we
            # skip status zero (unread by measure) and the flush-read
            # (the FIFO ordering of writes is sufficient on the U64
            # REST API).
            write_bytes(transport, sentinel_addr, bytes([0x00]))
            write_bytes(transport, rearm_addr, bytes([_REARM_FIRE]))
            # Poll sentinel — sleep coarsely so the recv thread gets the
            # GIL during routine execution and drains the UDP buffer.
            deadline = time.monotonic() + per_iteration_timeout
            while time.monotonic() < deadline:
                if read_bytes(transport, sentinel_addr, 1)[0] == _SENTINEL_DONE:
                    break
                time.sleep(0.05)
            else:
                raise TimeoutError(
                    f"U64 trampoline did not complete within "
                    f"{per_iteration_timeout}s at sentinel "
                    f"${sentinel_addr:04X}"
                )
    finally:
        if started:
            try:
                client.stream_debug_stop()
            except Exception:
                pass
        time.sleep(capture_drain_seconds)
        result = cap.stop()
        # Best-effort restore of the original debug stream mode.
        try:
            set_debug_stream_mode(client, orig_debug_mode)
        except Exception:
            pass

    return _parse_marker_pairs(
        result.trace,
        jsr_addr=trampoline_addr,
        sta_addr=trampoline_addr + 3,
        expected_pairs=samples,
        packets_dropped=result.packets_dropped,
    )


def _parse_marker_pairs(
    trace: list,
    *,
    jsr_addr: int,
    sta_addr: int,
    expected_pairs: int,
    packets_dropped: int,
) -> list[int]:
    """Extract per-sample CPU-cycle counts from a 6510-only trace.

    Each iteration is bracketed by two markers on the address bus:

    * ``jsr_addr`` — the JSR opcode fetch (start of one routine call).
    * ``sta_addr`` — the STA $0351 opcode fetch immediately after the
      routine returns.

    Walks the trace finding the first ``jsr_addr`` cycle, then the next
    ``sta_addr`` cycle, and counts entries between them (inclusive of
    the JSR fetch, exclusive of the STA fetch). Subtracts 12 to drop
    the JSR overhead (6 cy) and the routine's final RTS (6 cy), so the
    returned number is the routine body excluding its final RTS — the
    same convention the VICE CIA-timer wrapper reports.

    :param trace: ``list[BusCycle]`` from ``DebugCaptureResult.trace``.
    :param jsr_addr: Address of the trampoline JSR opcode (e.g. $0360).
    :param sta_addr: Address of the trampoline STA $0351 opcode
        (typically ``jsr_addr + 3``).
    :param expected_pairs: Number of (jsr, sta) pairs we expect.
    :param packets_dropped: Sequence-number gap count from the capture
        (used only for diagnostics on length mismatch).
    :return: List of cycle counts, one per matched pair.
    :raises RuntimeError: If we found fewer pairs than expected and the
        trace shows packet drops or appears truncated.
    """
    cycles: list[int] = []
    n = len(trace)
    i = 0
    while i < n and len(cycles) < expected_pairs:
        # Find next JSR fetch.
        while i < n and trace[i].address != jsr_addr:
            i += 1
        if i >= n:
            break
        start = i
        # Find the matching STA fetch (must come AFTER the JSR fetch).
        j = i + 1
        while j < n and trace[j].address != sta_addr:
            j += 1
        if j >= n:
            break
        # Cycles in [start, j): includes JSR (6 cy) + body (with final RTS).
        # VICE convention subtracts 12 (JSR + RTS) to report body work.
        count = j - start - 12
        if count < 0:
            # Defensive — would only happen if the trampoline was malformed.
            count = 0
        cycles.append(count)
        # Advance past this pair to avoid re-matching.
        i = j + 1

    if len(cycles) < expected_pairs:
        raise RuntimeError(
            f"DebugCapture marker parse found {len(cycles)} of "
            f"{expected_pairs} expected JSR/STA pairs at "
            f"jsr=${jsr_addr:04X}/sta=${sta_addr:04X} "
            f"(trace length={n}, packets_dropped={packets_dropped}). "
            "Likely capture truncation or trampoline mis-alignment."
        )
    return cycles
