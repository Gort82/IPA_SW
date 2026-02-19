"""Demo: input-parameter authentication via dynamic watermarking.

Run:
    python demo.py

Flow:
  1) Client prepares (watermarks) the parameter list.
  2) Server receives parameters and authenticates them before executing logic.
  3) Tampering with any parameter should be detected.

Note:
  To avoid reliance on KEYED_BIT “keyed chaos”, the number of pairs must be sufficient
  for KEYED_INDEX to cover all η bit positions. This demo uses 512 integers (256 pairs)
  with ETA=32.
"""

from __future__ import annotations

from watermarking.wrap import protect, prepare


KEY = b"demo-key-32bytes-minimum---ok"
ZETA = 123456789  # expected secret code ζ (decimal)
ETA = 32          # length of ζ₂ (bits)


@protect(key=KEY, zeta=ZETA, eta=ETA, on_tamper="raise")
def sum_even_indexed(params: list[int]) -> int:
    """Toy workload: sum values at even indices."""
    return sum(params[::2])


def main() -> None:
    original = list(range(1, 513))  # 512 integers = 256 pairs
    watermarked = prepare(original, key=KEY, zeta=ZETA, eta=ETA)

    print("Original params length:", len(original))
    print("Calling protected function with *authentic watermarked* params...")
    print("Result:", sum_even_indexed(watermarked))

    tampered = watermarked.copy()
    tampered[33] ^= 1  # flip one bit in one parameter
    print("\nCalling protected function with *tampered* params (index 33 flipped)...")
    try:
        print("Result:", sum_even_indexed(tampered))
    except Exception as e:
        print("Tamper detected:", e)


if __name__ == "__main__":
    main()
