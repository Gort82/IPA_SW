import unittest

from watermarking.wrap import prepare, protect
from watermarking.encoder import build_watermark_graph, restore_params_from_pairs
from watermarking.controller import controller_verify


class WatermarkingTests(unittest.TestCase):
    def test_round_trip_authentic(self):
        key = b"unit-test-key"
        zeta = 424242
        eta = 20
        original = list(range(1, 1025))  # 1024 ints = 512 pairs (high coverage)

        watermarked = prepare(original, key=key, zeta=zeta, eta=eta)
        build = build_watermark_graph(watermarked, key=key, eta=eta)
        vr = controller_verify(build.graph_head, zeta)
        self.assertTrue(vr.is_authentic)

        restored = restore_params_from_pairs(watermarked, build.permutation)
        self.assertEqual(restored, original)

    def test_detect_tampering(self):
        key = b"unit-test-key"
        zeta = 424242
        eta = 20
        original = list(range(10, 1034))  # 1024 ints

        watermarked = prepare(original, key=key, zeta=zeta, eta=eta)
        tampered = watermarked.copy()
        # Tamper multiple embedded values to avoid chance agreement in keyed tie-breaks
        for idx in range(0, 100, 2):
            tampered[idx] += 1

        build = build_watermark_graph(tampered, key=key, eta=eta)
        vr = controller_verify(build.graph_head, zeta)
        self.assertFalse(vr.is_authentic)

    def test_decorator(self):
        key = b"unit-test-key"
        zeta = 9999
        eta = 16
        original = list(range(1, 2049))  # lots of pairs

        @protect(key=key, zeta=zeta, eta=eta, on_tamper="raise")
        def f(params):
            return sum(params)

        watermarked = prepare(original, key=key, zeta=zeta, eta=eta)
        self.assertEqual(f(watermarked), sum(original))

        tampered = watermarked.copy()
        tampered[77] ^= 1
        with self.assertRaises(ValueError):
            f(tampered)


if __name__ == "__main__":
    unittest.main()
