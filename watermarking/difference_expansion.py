"""Reversible difference expansion embedding for integer pairs.

The paper uses DE-based bit extraction:
    bp <- (x - y) mod 2   (Algorithm 2, line 5)

This aligns with classical reversible difference expansion (DE):
  d  = x - y
  a  = floor((x + y)/2)
  d' = 2*d + b
  x' = a + ceil(d'/2)
  y' = a - floor(d'/2)

Extraction & restoration:
  d' = x' - y'
  b  = d' mod 2
  d  = floor(d'/2)
  a  = floor((x' + y')/2)   (same as original a)
  x  = a + ceil(d/2)
  y  = a - floor(d/2)

We work with unbounded Python integers (no overflow concerns).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class EmbeddedPair:
    x_embedded: int
    y_embedded: int


def _floor_div2(n: int) -> int:
    # Python's // is floor division already.
    return n // 2


def _ceil_div2(n: int) -> int:
    return -((-n) // 2)


def embed_bit(x: int, y: int, bit: int) -> EmbeddedPair:
    """Embed bit into (x, y) via DE and return modified values."""
    if bit not in (0, 1):
        raise ValueError("bit must be 0 or 1")
    d = x - y
    a = _floor_div2(x + y)
    d_prime = 2 * d + bit
    x_prime = a + _ceil_div2(d_prime)
    y_prime = a - _floor_div2(d_prime)
    return EmbeddedPair(x_prime, y_prime)


def extract_bit_and_restore(x_prime: int, y_prime: int) -> Tuple[int, Tuple[int, int]]:
    """Extract embedded bit from (x', y') and restore original (x, y)."""
    d_prime = x_prime - y_prime
    bit = int(d_prime % 2)
    d = _floor_div2(d_prime)
    a = _floor_div2(x_prime + y_prime)
    x = a + _ceil_div2(d)
    y = a - _floor_div2(d)
    return bit, (x, y)
