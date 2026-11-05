"""Offline tests of the hash formats. The agreement with m1_ctl.batch_hash()
in MySQL is checked live on every verification (integrity step)."""

import hashlib
import struct
import unittest

from m1 import hashing


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class HashingTest(unittest.TestCase):
    def test_vector_bytes_are_float32_little_endian(self):
        self.assertEqual(struct.pack("<2f", 1.0, -2.5).hex().upper(), "0000803F000020C0")

    def test_row_hash_format(self):
        emb = struct.pack("<2f", 1.0, -2.5)
        expected = sha("1|supplier:1|" + "Café".encode("utf-8").hex().upper() + "|0000803F000020C0")
        self.assertEqual(hashing.row_hash(1, "supplier:1", "Café", emb), expected)

    def test_empty_batch_is_the_domain_hash(self):
        self.assertEqual(hashing.batch_hash([]), sha("m1-batch-v1"))

    def test_batch_hash_chains_in_chunk_order(self):
        emb = struct.pack("<f", 0.5)
        c1, c2 = (1, "k1", "a", emb), (2, "k2", "b", emb)
        h = sha("m1-batch-v1")
        for no, key, content, e in (c1, c2):
            h = sha(h + hashing.row_hash(no, key, content, e))
        self.assertEqual(hashing.batch_hash([c2, c1]), h)
        self.assertNotEqual(hashing.batch_hash([c1, (2, "k2", "b", struct.pack("<f", 0.25))]), h)

    def test_canonical_ignores_key_order(self):
        self.assertEqual(hashing.canonical({"b": 1, "a": [1, 2]}), hashing.canonical({"a": [1, 2], "b": 1}))

    def test_verifier_sources_cover_pipeline_sources(self):
        self.assertTrue(set(hashing.PIPELINE_SOURCES) <= set(hashing.VERIFIER_SOURCES))
        for name in hashing.VERIFIER_SOURCES:
            self.assertTrue((hashing.PACKAGE_DIR / name).is_file(), name)


if __name__ == "__main__":
    unittest.main()
