"""Ranking of the agent's semantic search on hand-made unit vectors."""

import math
import struct
import unittest

from m1 import agent


def vec(*xs):
    norm = math.sqrt(sum(x * x for x in xs))
    return struct.pack(f"<{len(xs)}f", *(x / norm for x in xs))


class RankTest(unittest.TestCase):
    def setUp(self):
        self.chunks = [(1, "supplier:1", "east", vec(1, 0, 0)), (2, "supplier:2", "north", vec(0, 1, 0)),
                       (3, "supplier:3", "north-east", vec(1, 1, 0)), (4, "supplier:4", "up", vec(0, 0, 1))]

    def test_orders_by_cosine_and_cuts_at_k(self):
        top = agent.rank(vec(1, 0.2, 0), self.chunks, 2)
        self.assertEqual([r["doc_key"] for r in top], ["supplier:1", "supplier:3"])
        self.assertGreater(top[0]["score"], top[1]["score"])

    def test_ties_keep_chunk_order(self):
        top = agent.rank(vec(0, 0, 1), self.chunks, 4)
        self.assertEqual(top[0]["doc_key"], "supplier:4")
        self.assertEqual([r["doc_key"] for r in top[1:]], ["supplier:1", "supplier:2", "supplier:3"])

    def test_empty_knowledge_base(self):
        self.assertEqual(agent.rank(vec(1, 0, 0), [], 5), [])


if __name__ == "__main__":
    unittest.main()
