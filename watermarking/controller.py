"""Controller procedure (Algorithm 6).

The Controller compares an expected secret code ζ (decimal) to the one decoded from
a heap watermark graph that should only be constructible when inputs are authentic.

In the original architecture, the Controller is external and reads process memory.
Here we provide an equivalent in-process procedure for reproducible experimentation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from .base_convert import int_to_digits, digits_to_int
from .graph import Node, decode_watermark


@dataclass
class VerificationResult:
    is_authentic: bool
    recovered_zeta: Optional[int]
    recovered_zeta6: Optional[list[int]]
    error: Optional[str] = None


def controller_verify(graph_head: Node, expected_zeta: int) -> VerificationResult:
    """Verify authenticity by decoding watermark and comparing codes (Algorithm 6)."""
    if expected_zeta < 0:
        raise ValueError("expected_zeta must be non-negative")

    # Convert ζ -> ζ6 to obtain μ.
    expected_zeta6 = int_to_digits(expected_zeta, 6)
    mu = len(expected_zeta6)

    try:
        recovered_zeta6 = decode_watermark(graph_head, mu)
        recovered_zeta = digits_to_int(recovered_zeta6, 6)
    except Exception as e:
        return VerificationResult(
            is_authentic=False,
            recovered_zeta=None,
            recovered_zeta6=None,
            error=str(e),
        )

    return VerificationResult(
        is_authentic=(recovered_zeta == expected_zeta),
        recovered_zeta=recovered_zeta,
        recovered_zeta6=recovered_zeta6,
        error=None,
    )
