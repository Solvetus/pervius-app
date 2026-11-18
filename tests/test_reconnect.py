from __future__ import annotations

import unittest

from pervius.reconnect import DEFAULT_DELAYS, ReconnectPolicy


class ReconnectPolicyTests(unittest.TestCase):
    def test_default_schedule(self):
        policy = ReconnectPolicy()
        self.assertEqual(policy.max_attempts, 6)
        self.assertEqual(
            [policy.delay(attempt) for attempt in range(1, 7)],
            list(DEFAULT_DELAYS),
        )
        self.assertIsNone(policy.delay(7))

    def test_out_of_range_attempts(self):
        policy = ReconnectPolicy((3, 9))
        self.assertIsNone(policy.delay(0))
        self.assertIsNone(policy.delay(-1))
        self.assertEqual(policy.delay(1), 3)
        self.assertEqual(policy.delay(2), 9)

    def test_invalid_policies_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "at least one"):
            ReconnectPolicy(())
        with self.assertRaisesRegex(ValueError, "positive"):
            ReconnectPolicy((1, 0))
        with self.assertRaisesRegex(ValueError, "positive"):
            ReconnectPolicy((-1, 5))


if __name__ == "__main__":
    unittest.main()
