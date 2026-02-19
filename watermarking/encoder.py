"""Watermark hint embedding (client-side) and authentication (server-side).

This module mirrors the paper’s split:
  - **Watermark hint embedding**: prepare an input parameter list I that carries hidden hints.
  - **Runtime authentication**: from received I, extract hints, rebuild ζ₂, build watermark graph,
    and let the Controller verify ζ.

Algorithms implemented:
  - Algorithm 2: HINTS_DETECTION(I, P)
  - Algorithm 3: CODE_BUILDER(Γ, η, k, P)
  - Algorithm 4: ENCODE_WATERMARK(ζ₆)
  - Algorithm 7–9: key-based routines (in watermarking.crypto)

Embedding mechanism:
  - Reversible Difference Expansion (DE) on integer pairs.
  - Extracted bit equals (x - y) mod 2, as in Algorithm 2.

IMPORTANT PRACTICAL NOTE
------------------------
For CODE_BUILDER to reconstruct an arbitrary expected ζ₂ (rather than filling missing positions
via KEYED_BIT “keyed chaos”), every bit position j in [0, η) must receive at least one vote through
KEYED_INDEX(p, η, k) over the available pair indices p. In practice, this requires a sufficiently
large number of parameter pairs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple, Set

from .crypto import keyed_index, keyed_bit, keyed_permutation, prng_seed
from .difference_expansion import embed_bit, extract_bit_and_restore
from .base_convert import bits_from_int, base_convert_digits
from .graph import encode_watermark, Node


@dataclass
class PreparedInput:
    """Client-side output: a parameter list carrying embedded hints."""
    watermarked_params: List[int]
    permutation: List[int]
    eta: int


@dataclass
class AuthenticationBuild:
    """Server-side build output: heap graph + permutation used."""
    graph_head: Node
    permutation: List[int]
    eta: int


def _compute_permutation(params_len: int, *, key: bytes, eta: int) -> List[int]:
    if params_len < 2:
        raise ValueError("Need at least 2 parameters (one pair).")
    seed = prng_seed(key)
    n_pairs = params_len // 2
    if n_pairs < eta:
        raise ValueError(
            f"Not enough parameter pairs to support eta={eta}: need at least {eta} pairs, got {n_pairs}. "
            "Increase the number of input integers or reduce eta."
        )
    P = keyed_permutation(seed, n_pairs)
    covered = {keyed_index(p, eta, key) for p in P}
    if len(covered) < eta:
        raise ValueError(
            f"Insufficient KEYED_INDEX coverage: only {len(covered)}/{eta} bit positions receive votes. "
            "Increase the number of input integers (more pairs) or reduce eta."
        )
    return P


# -------------------------
# Algorithm 2: hints detect
# -------------------------

def hints_detection(I: List[int], P: List[int]) -> List[int]:
    """HINTS_DETECTION(I, P) -> Γ (Algorithm 2)."""
    n_pairs = len(I) // 2
    gamma = [0] * n_pairs
    for p in P:
        x = I[2 * p]
        y = I[2 * p + 1]
        gamma[p] = int((x - y) % 2)
    return gamma


# -------------------------
# Algorithm 3: code builder
# -------------------------

def code_builder(gamma: List[int], eta: int, key: bytes, P: List[int]) -> List[int]:
    """CODE_BUILDER(Γ, η, k, P) -> ζ₂ (Algorithm 3)."""
    zeta2 = [0] * eta
    ones = [0] * eta
    zeros = [0] * eta
    bi_lab = "KBit|v1"

    for p in P:
        j = keyed_index(p, eta, key)
        if gamma[p] == 1:
            ones[j] += 1
        else:
            zeros[j] += 1

    for j in range(eta):
        o = ones[j]
        z = zeros[j]
        if (o > 0) and (z == 0):
            zeta2[j] = 1
        elif (z > 0) and (o == 0):
            zeta2[j] = 0
        else:
            msg = f"{bi_lab}|chaos|j={j}|o={o}|z={z}"
            zeta2[j] = keyed_bit(key, msg)

    return zeta2


# -------------------------
# Client-side embedding
# -------------------------

def prepare_parameters(params: List[int], *, key: bytes, zeta: int, eta: int) -> PreparedInput:
    """Embed watermark hints into `params` to produce a watermarked carrier list.

    This is the *sending* side (or pre-processing stage) that produces the 'fake' carrier values
    described in the paper.
    """
    if zeta < 0:
        raise ValueError("zeta must be non-negative")
    P = _compute_permutation(len(params), key=key, eta=eta)

    # ζ₂ is fixed-length.
    zeta2 = bits_from_int(zeta, eta)

    # Scatter ζ₂ into Γ via KEYED_INDEX(p,η,k) (inverse of Algorithm 3 voting).
    n_pairs = len(params) // 2
    gamma = [0] * n_pairs
    for p in P:
        j = keyed_index(p, eta, key)
        gamma[p] = int(zeta2[j])

    # Embed Γ bits into adjacent pairs using DE.
    I = list(params)
    for p in P:
        x = I[2 * p]
        y = I[2 * p + 1]
        emb = embed_bit(x, y, gamma[p])
        I[2 * p] = emb.x_embedded
        I[2 * p + 1] = emb.y_embedded

    return PreparedInput(watermarked_params=I, permutation=P, eta=eta)


# -------------------------
# Server-side authentication build
# -------------------------

def build_watermark_graph(received_params: List[int], *, key: bytes, eta: int) -> AuthenticationBuild:
    """From received parameters, extract hints and build the heap watermark graph.

    This corresponds to the in-program watermark reconstruction path (Algorithm 1 composition).
    """
    P = _compute_permutation(len(received_params), key=key, eta=eta)

    gamma_detected = hints_detection(received_params, P)
    zeta2_hat = code_builder(gamma_detected, eta, key, P)
    zeta6_hat = base_convert_digits(zeta2_hat, 2, 6)
    head = encode_watermark(zeta6_hat)

    return AuthenticationBuild(graph_head=head, permutation=P, eta=eta)


def restore_params_from_pairs(watermarked_params: List[int], P: List[int]) -> List[int]:
    """Restore original parameter values by reversing DE for every pair in P."""
    I = list(watermarked_params)
    for p in P:
        x_p = I[2 * p]
        y_p = I[2 * p + 1]
        _, (x, y) = extract_bit_and_restore(x_p, y_p)
        I[2 * p] = x
        I[2 * p + 1] = y
    return I
