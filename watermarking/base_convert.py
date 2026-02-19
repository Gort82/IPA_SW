"""Base conversion helpers.

The paper uses:
  - ζ (decimal integer secret code)
  - ζ₂ (binary representation as a bit array of length η)
  - ζ₆ (base-6 representation as a digit array of length μ)

This module provides conversions between:
  int <-> list[int] digits in arbitrary base (2 or 6 here).
"""

from __future__ import annotations

from typing import List, Tuple


def int_to_digits(n: int, base: int) -> List[int]:
    """Convert non-negative integer n to big-endian digits in the given base."""
    if base < 2:
        raise ValueError("base must be >= 2")
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return [0]
    digits: List[int] = []
    while n > 0:
        digits.append(int(n % base))
        n //= base
    return list(reversed(digits))


def digits_to_int(digits: List[int], base: int) -> int:
    """Convert big-endian digits in the given base to an integer."""
    if base < 2:
        raise ValueError("base must be >= 2")
    if not digits:
        raise ValueError("digits must be non-empty")
    n = 0
    for d in digits:
        if d < 0 or d >= base:
            raise ValueError(f"digit {d} out of range for base {base}")
        n = n * base + d
    return n


def bits_from_int(n: int, eta: int) -> List[int]:
    """Convert integer to a fixed-length bit array (big-endian)."""
    if eta <= 0:
        raise ValueError("eta must be > 0")
    bits = int_to_digits(n, 2)
    if len(bits) > eta:
        raise ValueError("eta too small to represent n")
    return [0] * (eta - len(bits)) + bits


def int_from_bits(bits: List[int]) -> int:
    return digits_to_int(bits, 2)


def base_convert_digits(digits: List[int], base_from: int, base_to: int) -> List[int]:
    """Convert a digit array between bases via integer intermediate."""
    n = digits_to_int(digits, base_from)
    return int_to_digits(n, base_to)
