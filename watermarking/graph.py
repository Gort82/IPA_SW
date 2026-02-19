"""Heap-based watermark graph construction (Algorithms 4–5).

Graph model (Collberg & Thomborson base-6 graph):
  - Create a ring of μ nodes N0..N_{μ-1} with 'next' pointers.
  - Each node also has a 'digit' pointer:
      if ζ6[r] == 0: digit = None
      else: digit = N_{(r + ζ6[r] - 1) mod μ}

Encoding: builds the graph from ζ6 and returns head node N0.
Decoding: recovers ζ6 from any assumed head node by local traversal.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Node:
    next: Optional["Node"] = None
    digit: Optional["Node"] = None


def encode_watermark(zeta6: List[int]) -> Node:
    """ENCODE_WATERMARK(ζ6) -> N0 (Algorithm 4)."""
    mu = len(zeta6)
    if mu <= 0:
        raise ValueError("ζ6 must be non-empty")
    nodes = [Node() for _ in range(mu)]
    for r in range(mu):
        nodes[r].next = nodes[(r + 1) % mu]
    for r in range(mu):
        d = zeta6[r]
        if d == 0:
            nodes[r].digit = None
        else:
            t = (r + d - 1) % mu
            nodes[r].digit = nodes[t]
    return nodes[0]


def decode_watermark(head: Node, mu: int) -> List[int]:
    """DECODE_WATERMARK(N0', μ) -> ζ6 (Algorithm 5).

    Raises ValueError if the structure is invalid (broken ring/unreachable digit).
    """
    if mu <= 0:
        raise ValueError("mu must be > 0")

    # Collect ring nodes in order from assumed head.
    nodes: List[Node] = [head]
    cur = head
    for _ in range(1, mu):
        if cur.next is None:
            raise ValueError("invalid structure (broken ring)")
        cur = cur.next
        nodes.append(cur)

    zeta6 = [0] * mu
    for r in range(mu):
        nr = nodes[r]
        if nr.digit is None:
            zeta6[r] = 0
            continue

        # Count steps along 'next' from nr until reaching nr.digit.
        s = 0
        probe = nr
        while probe is not nr.digit:
            probe = probe.next
            s += 1
            if probe is None:
                raise ValueError("invalid structure (broken ring)")
            if s > mu:
                raise ValueError("invalid structure (unreachable digit)")

        # By construction, ζ6[r] == s + 1 (since s=0 corresponds to digit=self).
        zeta6[r] = s + 1

    return zeta6
