import os
import errno
import tempfile
import unittest

from capysicum import _wrapper as W

NAMES = {W.lib.CAP_WRITE: 'CAP_WRITE',
         W.lib.CAP_IOCTL: 'CAP_IOCTL',
         W.lib.CAP_LOOKUP: 'CAP_LOOKUP',
         W.lib.CAP_BINDAT: 'CAP_BINDAT',
         W.lib.CAP_FCHMOD: 'CAP_FCHMOD'}


class CapEnterTest(unittest.TestCase):

    def test_cap_enter_and_getmode(self):
        self.assertFalse(W.cap_getmode())

        if os.fork():
            _, status = os.wait()
            self.assertFalse(status, "test process failed")
            return

        W.cap_enter()

        self.assertTrue(W.cap_getmode(), "cap_getmode failed")

        os._exit(0)


class SimpleRightsTests(unittest.TestCase):
    # NB: These functions never return failure; instead, they
    # terminate the program!

    SIMPLE_RIGHTS = (W.lib.CAP_WRITE, W.lib.CAP_IOCTL, W.lib.CAP_LOOKUP)

    def setUp(self):
        self.cap_rights = W.new_cap_rights()

    def test_cap_rights_init(self):
        W.cap_rights_init(self.cap_rights)

        for right in self.SIMPLE_RIGHTS:
            self.assertFalse(W.cap_rights_is_set(self.cap_rights, right),
                             NAMES[right])

    def test_cap_rights_init_with_args(self):
        W.cap_rights_init(self.cap_rights, *self.SIMPLE_RIGHTS)

        for right in self.SIMPLE_RIGHTS:
            self.assertTrue(W.cap_rights_is_set(self.cap_rights, right),
                            NAMES[right])

    def test_cap_rights_set(self):
        so_far = set()
        remaining = set(self.SIMPLE_RIGHTS)

        W.cap_rights_init(self.cap_rights)

        while remaining:
            self.assertFalse(W.cap_rights_is_set(self.cap_rights, *remaining))

            right = remaining.pop()
            so_far.add(right)

            W.cap_rights_set(self.cap_rights, right)

            self.assertTrue(W.cap_rights_is_set(self.cap_rights, right),
                            NAMES[right])
            self.assertTrue(W.cap_rights_is_set(self.cap_rights, *so_far),
                            NAMES[right])

            W.cap_rights_set(self.cap_rights, *so_far)

            self.assertTrue(W.cap_rights_is_set(self.cap_rights, *so_far),
                            NAMES[right])

    def test_cap_rights_clear(self):
        W.cap_rights_init(self.cap_rights)

        W.cap_rights_set(self.cap_rights, *self.SIMPLE_RIGHTS)

        remaining = set(self.SIMPLE_RIGHTS)
        while remaining:
            right = remaining.pop()
            W.cap_rights_clear(self.cap_rights, right)
            self.assertFalse(W.cap_rights_is_set(self.cap_rights, right),
                             NAMES[right])
            self.assertTrue(W.cap_rights_is_set(self.cap_rights, *remaining),
                            NAMES[right])

    def test_cap_rights_is_valid(self):
        self.assertFalse(W.cap_rights_is_valid(self.cap_rights))
        W.cap_rights_init(self.cap_rights)
        self.assertTrue(W.cap_rights_is_valid(self.cap_rights))

    def test_cap_rights_merge(self):
        src = self.cap_rights
        dst = W.new_cap_rights()

        W.cap_rights_init(src, *self.SIMPLE_RIGHTS)
        W.cap_rights_init(dst)

        W.cap_rights_merge(dst, src)

        for right in self.SIMPLE_RIGHTS:
            self.assertTrue(W.cap_rights_is_set(dst, right),
                            NAMES[right])

    def test_cap_rights_remove(self):
        src = self.cap_rights
        dst = W.new_cap_rights()

        W.cap_rights_init(src, *self.SIMPLE_RIGHTS)
        W.cap_rights_init(dst, *self.SIMPLE_RIGHTS)

        W.cap_rights_remove(dst, src)

        for right in self.SIMPLE_RIGHTS:
            self.assertFalse(W.cap_rights_is_set(dst, right),
                             NAMES[right])

    def test_cap_rights_contains(self):
        big = self.cap_rights
        little = W.new_cap_rights()

        W.cap_rights_init(big, *self.SIMPLE_RIGHTS)
        W.cap_rights_init(little, self.SIMPLE_RIGHTS[0])

        self.assertTrue(W.cap_rights_contains(big, little))
        self.assertFalse(W.cap_rights_contains(little, big))


class DependentRightsTestCase(unittest.TestCase):
    DEPENDENT_RIGHTS = {W.lib.CAP_FCHMOD: W.lib.CAP_LOOKUP}


class InclusliveRightsTestCase(unittest.TestCase):
    INCLUSLIVE_RIGHTS = {W.lib.CAP_BINDAT: W.lib.CAP_LOOKUP}


class ErrnoMixin(unittest.TestCase):

    def _test_errno(self, args_errnos, func):
        for args, err in args_errnos:
            with self.assertRaises(W.CapysicumError) as caught_ce:
                W.cap_rights_limit(*args)

            self.assertTrue(caught_ce.exception.errno, err)


class TestLimitAndGetd(ErrnoMixin, unittest.TestCase):

    def setUp(self):
        self.f = tempfile.TemporaryFile('w+',
                                        prefix="capysicum_TestLimitFD_tmp")

    def tearDown(self):
        self.f.close()

    def test_cap_rights_limit_and_get(self):
        self.f.write("foobar")
        self.f.flush()
        self.f.seek(0)

        rights = W.cap_rights_init(W.new_cap_rights(), W.lib.CAP_READ)

        W.cap_rights_limit(self.f.fileno(), rights)

        self.assertEquals(self.f.read(), 'foobar')

        with self.assertRaises(IOError) as caught_ioe:
            self.f.write('fails')
            self.f.flush()

        self.assertTrue(caught_ioe.exception.errno, 93)

        fd_rights = W.new_cap_rights()
        W.cap_rights_get(self.f.fileno(), fd_rights)

        self.assertTrue(W.cap_rights_contains(rights, fd_rights))
        self.assertTrue(W.cap_rights_contains(fd_rights, rights))

    def test_cap_rights_limit_fails(self):
        good_rights = W.cap_rights_init(W.new_cap_rights())

        args_errnos = [((self.f.fileno(), W.new_cap_rights()), errno.EINVAL),
                       ((-1, good_rights), errno.EBADF)]

        self._test_errno(args_errnos, W.cap_rights_limit)

    def test_cap_rights_get_fails(self):
        good_rights = W.cap_rights_init(W.new_cap_rights())

        args_errnos = [((self.f.fileno(), W.ffi.cast('cap_rights_t *',
                                                     W.ffi.NULL)),
                        errno.EFAULT),
                       ((-1, good_rights), errno.EBADF)]

        self._test_errno(args_errnos, W.cap_rights_get)
