"""High-level wrapper to authenticate *received* parameters before executing a function.

This matches the paper’s intended deployment model:
  - Some upstream stage produces/forwards parameters that carry embedded hints.
  - The protected program receives parameters, reconstructs the watermark, and verifies authenticity.

Usage:
    from watermarking.wrap import protect, prepare

    KEY  = b"secret"
    ZETA = 123456789
    ETA  = 32

    # client-side
    watermarked = prepare([1,2,3,4,...], key=KEY, zeta=ZETA, eta=ETA)

    # server-side
    @protect(key=KEY, zeta=ZETA, eta=ETA)
    def f(params: list[int]) -> int:
        ...

    f(watermarked)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, TypeVar, Optional, cast

from .encoder import prepare_parameters, build_watermark_graph, restore_params_from_pairs
from .controller import controller_verify, VerificationResult

R = TypeVar("R")


def prepare(params: List[int], *, key: bytes, zeta: int, eta: int) -> List[int]:
    """Client-side helper: return a watermarked parameter list."""
    return prepare_parameters(params, key=key, zeta=zeta, eta=eta).watermarked_params


@dataclass
class ProtectionConfig:
    key: bytes
    zeta: int
    eta: int
    on_tamper: str = "raise"  # "raise" | "return_none" | "call_anyway"


def protect(*, key: bytes, zeta: int, eta: int, on_tamper: str = "raise") -> Callable[[Callable[[List[int]], R]], Callable[[List[int]], R]]:
    """Decorator that authenticates *incoming* params before calling f(params)."""

    cfg = ProtectionConfig(key=key, zeta=zeta, eta=eta, on_tamper=on_tamper)

    def decorator(func: Callable[[List[int]], R]) -> Callable[[List[int]], R]:
        def wrapped(received_params: List[int]) -> R:
            # 1) Build heap watermark graph from received params (no embedding here).
            build = build_watermark_graph(received_params, key=cfg.key, eta=cfg.eta)

            # 2) Controller verifies authenticity by comparing decoded ζ̂ to expected ζ.
            vr: VerificationResult = controller_verify(build.graph_head, cfg.zeta)

            if vr.is_authentic:
                restored = restore_params_from_pairs(received_params, build.permutation)
                return func(restored)

            # Tamper / mismatch path (F^φ)
            if cfg.on_tamper == "call_anyway":
                return func(received_params)
            if cfg.on_tamper == "return_none":
                return cast(R, None)
            raise ValueError(f"Parameter authentication failed: {vr.error or 'code mismatch'}")

        wrapped.__name__ = getattr(func, "__name__", "wrapped")
        wrapped.__doc__ = getattr(func, "__doc__", None)
        return wrapped
    return decorator
