# Input Parameters Authentication through Dynamic Software Watermarking


This repository is a reference implementation of the solution described in:

> Pérez Gort, M. L. (2025). *Input parameters authentication through dynamic software watermarking.*  
> Frontiers in Computer Science, 7, 1643075.  
> https://www.frontiersin.org/journals/computer-science/articles/10.3389/fcomp.2025.1643075/full

The goal is to demonstrate, end-to-end, how input parameters can be authenticated using a **dynamic,
heap-based watermark graph** that is only reconstructible when the correct parameter values are provided.

## What this code implements

- **Keyed hint synchronization**:
  - `KEYED_PERMUTATION` (Algorithm 7)
  - `KEYED_INDEX` (Algorithm 8)
  - `KEYED_BIT` (Algorithm 9)

- **Hints extraction and code reconstruction**:
  - `HINTS_DETECTION` (Algorithm 2)
  - `CODE_BUILDER` (Algorithm 3)

- **Heap watermark graph** (Collberg & Thomborson base-6 graph):
  - `ENCODE_WATERMARK` (Algorithm 4)
  - `DECODE_WATERMARK` (Algorithm 5)

- **Controller verification**:
  - Controller procedure (Algorithm 6)

- **Reversible hint embedding** (implementation choice aligned with the paper):
  - Difference Expansion (DE) reversible data hiding on integer pairs.
  - The embedded bit is extracted as `(x - y) mod 2`, matching Algorithm 2.

## Project layout

```
.
├─ watermarking/
│  ├─ crypto.py                # Algorithms 7–9 + deterministic PRNG seed
│  ├─ difference_expansion.py   # reversible DE embedding/extraction for integer pairs
│  ├─ base_convert.py           # int <-> digits conversions (binary/base-6)
│  ├─ graph.py                  # Algorithms 4–5 (heap watermark graph)
│  ├─ encoder.py                # Algorithms 1–3 + embedding orchestration
│  ├─ controller.py             # Algorithm 6
│  └─ wrap.py                   # high-level decorator to protect a function
├─ demo.py
└─ tests/
   └─ test_watermarking.py
```

## Quick start

Requires Python 3.10+.

### Run the demo

```bash
python demo.py
```

You should see:
- an **authentic** call that passes verification and returns a normal result
- a **tampered** call (one parameter changed) that triggers detection

### Run tests

```bash
python -m unittest discover -q
```

## Using the decorator on your own function

Your protected function should accept a `list[int]` (this repo’s “carrier” type).
You can adapt the same pattern for other types once you define how to embed/extract hints.

```python
from watermarking.wrap import protect

KEY  = b"your-secret-key"
ZETA = 123456789     # expected secret code
ETA  = 64            # bit-length for ζ₂

@protect(key=KEY, zeta=ZETA, eta=ETA, on_tamper="raise")
def my_service_logic(params: list[int]) -> int:
    return sum(params)

print(my_service_logic([1,2,3,4]))
```

`on_tamper` controls the alternative flow (the paper’s `F^φ` idea):
- `"raise"` (default): raise an exception
- `"return_none"`: return `None`
- `"call_anyway"`: call the function even if authentication fails (for experimentation only)

## Notes / assumptions

- The paper’s architecture places the Controller externally and assumes it can read runtime memory.
  Here we keep everything in-process but preserve the same logical steps for reproducibility.
- The paper discusses inserting “fake values” into `I`. In this implementation, *DE-embedded values* are
  the modified (“fake”) carrier values, and extraction restores the originals before the protected function runs.
- Integers are treated as unbounded (Python `int`), so we do not include overflow/range checks.

## Citation

If you use or extend this code, please cite the paper:

Pérez Gort, M. L. (2025). *Input parameters authentication through dynamic software watermarking.*  
Frontiers in Computer Science, 7, 1643075.
