import unittest

from capysicum import _wrapper as W


class CapRightsManipulationTests(unittest.TestCase):
    # NB: These functions never return failure; instead, they
    # terminate the program!

    REVERSE_RIGHTS = {v: k for k, v in W.RIGHTS.items()}

    def setUp(self):
        self.cap_rights = W.new_cap_rights()

    def test_cap_rights_init(self):
        W.cap_rights_init(self.cap_rights)

        for right, name in self.REVERSE_RIGHTS.items():
            self.assertFalse(W.cap_rights_is_set(self.cap_rights, right), name)

    def test_cap_rights_init_with_args(self):
        W.cap_rights_init(self.cap_rights, *self.REVERSE_RIGHTS)

        for right, name in self.REVERSE_RIGHTS.items():
            self.assertTrue(W.cap_rights_is_set(self.cap_rights, right), name)

    def test_cap_rights_set(self):
        so_far, remaining = set(), set(self.REVERSE_RIGHTS)
        W.cap_rights_init(self.cap_rights)

        while remaining:
            self.assertFalse(W.cap_rights_is_set(self.cap_rights, *remaining))

            right = remaining.pop()
            so_far.add(right)
            name = self.REVERSE_RIGHTS[right]

            W.cap_rights_set(self.cap_rights, right)

            self.assertTrue(W.cap_rights_is_set(self.cap_rights, right),
                            name)
            self.assertTrue(W.cap_rights_is_set(self.cap_rights, *so_far),
                            name)

            W.cap_rights_set(self.cap_rights, *so_far)

            self.assertTrue(W.cap_rights_is_set(self.cap_rights, *so_far),
                            name)

    def test_cap_rights_clear(self):
        W.cap_rights_init(self.cap_rights)
        W.cap_rights_set(self.cap_rights, *self.REVERSE_RIGHTS)

        remaining = set(self.REVERSE_RIGHTS)
        while remaining:
            right = remaining.pop()
            name = self.REVERSE_RIGHTS[right]
            W.cap_rights_clear(self.cap_rights, right)
            self.assertFalse(W.cap_rights_is_set(self.cap_rights, right),
                             name)
            self.assertTrue(W.cap_rights_is_set(self.cap_rights, *remaining),
                            name)
