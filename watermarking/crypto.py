"""Keyed helper primitives (Algorithms 7–9 + PRNG seed).

This module implements the key-based routines described in:
Pérez Gort, M. L. (2025). Input parameters authentication through dynamic software watermarking.
Frontiers in Computer Science, 7, 1643075.

- KEYED_PERMUTATION (Algorithm 7): deterministic Fisher–Yates shuffle driven by HMAC-SHA256 with rejection sampling.
- KEYED_INDEX (Algorithm 8): uniform index mapping using HMAC-SHA256 with rejection sampling.
- KEYED_BIT (Algorithm 9): deterministic bit from HMAC-SHA256.
- PRNG(k): deterministic seed material derived from HMAC-SHA256 (implementation detail).
"""

from __future__ import annotations

import hmac
import hashlib
from typing import List, Optional


def _hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def prng_seed(key: bytes, label: str = "PRNG|v1") -> bytes:
    """Deterministically derive a seed from a secret key.

    The paper abstracts this as PRNG(k). We model it as HMAC-SHA256(k, label).
    The resulting bytes can be used as the 'seed' input to KEYED_PERMUTATION.
    """
    return _hmac_sha256(key, label.encode("utf-8"))


def keyed_bit(key: bytes, label: str) -> int:
    """KEYED_BIT(k, label) -> {0,1}. (Algorithm 9)"""
    msg = label.encode("utf-8")
    dig = _hmac_sha256(key, msg)
    r = int.from_bytes(dig[:8], byteorder="big", signed=False)
    return int(r % 2)


def keyed_index(p: int, eta: int, key: bytes, *, bi_lab: str = "KInd|v1") -> int:
    """KEYED_INDEX(p, η, k) -> idx in [0,η). (Algorithm 8)

    Uses rejection sampling to avoid modulo bias when reducing a 64-bit value.
    """
    if eta <= 0:
        raise ValueError("eta must be > 0")
    limit = (1 << 64) - ((1 << 64) % eta)
    c = 0
    while True:
        msg = f"{bi_lab}—{p}—{c}".encode("utf-8")
        dig = _hmac_sha256(key, msg)
        r = int.from_bytes(dig[:8], byteorder="big", signed=False)
        c += 1
        if r < limit:
            return int(r % eta)


def keyed_permutation(seed: bytes, n: int, ctx: str = "KPerm|v1") -> List[int]:
    """KEYED_PERMUTATION(seed, n, ctx) -> permutation of [0..n-1]. (Algorithm 7)

    Deterministic Fisher–Yates shuffle with rejection sampling for unbiased selection.
    """
    if n < 0:
        raise ValueError("n must be >= 0")
    P = list(range(n))
    c = 0
    for i in range(n - 1):
        m = i + 1
        L = (1 << 64) - ((1 << 64) % m)
        while True:
            label = f"perm|{ctx}|i={i}|c={c}".encode("utf-8")
            dig = _hmac_sha256(seed, label)
            r = int.from_bytes(dig[:8], byteorder="big", signed=False)
            c += 1
            if r < L:
                j = int(r % m)
                P[i], P[j] = P[j], P[i]
                break
    return P
