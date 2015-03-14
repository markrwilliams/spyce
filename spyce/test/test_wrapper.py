import os
import errno
import unittest
import operator
import fcntl
import termios

from spyce import _wrapper as W
from spyce._compat import reduce

from .support import ErrnoMixin, TemporaryFDMixin


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


class SimpleRightsTests(ErrnoMixin, unittest.TestCase):
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


class TestFcntlLimits(ErrnoMixin, TemporaryFDMixin, unittest.TestCase):

    def test_cap_fcntls_get(self):
        allFcntlRights = reduce(operator.or_,
                                [W.lib.CAP_FCNTL_GETFL,
                                 W.lib.CAP_FCNTL_SETFL,
                                 W.lib.CAP_FCNTL_GETOWN,
                                 W.lib.CAP_FCNTL_SETOWN])
        fileno = self.f.fileno()
        self.assertEqual(W.cap_fcntls_get(fileno),
                         allFcntlRights)

        self.f.close()

        with self.assertRaises(W.SpyceError):
            W.cap_fcntls_get(fileno)

    def test_cap_fcntls_limit(self):
        W.cap_fcntls_limit(self.pipeReadFD,
                           W.lib.CAP_FCNTL_GETFL | W.lib.CAP_FCNTL_GETOWN)

        flags = fcntl.fcntl(self.pipeReadFD, fcntl.F_GETFL)
        flags |= os.O_NONBLOCK

        with self.assertRaisesWithErrno(IOError, W.ENOTCAPABLE):
            fcntl.fcntl(self.pipeReadFD, fcntl.F_SETFL, flags)

        fcntl.fcntl(self.pipeReadFD, fcntl.F_GETOWN)

        with self.assertRaisesWithErrno(IOError, W.ENOTCAPABLE):
            fcntl.fcntl(self.pipeReadFD, fcntl.F_SETOWN, os.getpid())

        with self.assertRaisesWithErrno(W.SpyceError, errno.EBADF):
            W.cap_fcntls_limit(-1, W.lib.CAP_FCNTL_GETFL)


class TestIoctlLimits(ErrnoMixin, TemporaryFDMixin, unittest.TestCase):

    def test_cap_ioctls_get_all(self):
        tenZeros = [0] * 10
        for fd in (self.f.fileno(), self.pipeReadFD, self.pipeWriteFD):
            ioctlRights = W.new_ioctl_rights(*tenZeros)
            self.assertEqual(W.cap_ioctls_get(fd, ioctlRights),
                             W.CAP_IOCTLS_ALL)
            self.assertFalse(any(ioctlRights))

        with self.assertRaisesWithErrno(W.SpyceError, errno.EBADF):
            W.cap_ioctls_get(-1, W.new_ioctl_rights())

    def test_cap_ioctls_set_and_get(self):
        ioctlRights = W.new_ioctl_rights(termios.FIOCLEX)
        W.cap_ioctls_limit(self.pipeReadFD, ioctlRights)

        checkNumOfRights = W.cap_ioctls_get(self.pipeReadFD,
                                            W.new_ioctl_rights())

        self.assertEqual(checkNumOfRights, 1)

        fcntl.ioctl(self.pipeReadFD, termios.FIOCLEX)

        W.cap_ioctls_limit(self.pipeWriteFD, W.new_ioctl_rights())

        with self.assertRaisesWithErrno(IOError, W.ENOTCAPABLE):
            fcntl.ioctl(self.pipeWriteFD, termios.FIOCLEX)

        with self.assertRaisesWithErrno(W.SpyceError, W.ENOTCAPABLE):
            W.cap_ioctls_limit(self.pipeWriteFD, ioctlRights)


class TestLimitAndGetFD(ErrnoMixin, TemporaryFDMixin, unittest.TestCase):

    def test_cap_rights_limit_and_get(self):
        self.f.write(b'foobar')
        self.f.flush()
        self.f.seek(0)

        rights = W.cap_rights_init(W.new_cap_rights(), W.lib.CAP_READ)

        W.cap_rights_limit(self.f.fileno(), rights)

        self.assertEqual(self.f.read(), b'foobar')

        with self.assertRaisesWithErrno(IOError, W.ENOTCAPABLE):
            self.f.write(b'fails')
            self.f.flush()

        fdRights = W.new_cap_rights()
        W.cap_rights_get(self.f.fileno(), fdRights)

        self.assertTrue(W.cap_rights_contains(rights, fdRights))
        self.assertTrue(W.cap_rights_contains(fdRights, rights))

    def test_cap_rights_limit_fails(self):
        goodRights = W.cap_rights_init(W.new_cap_rights())

        with self.assertRaisesWithErrno(W.SpyceError, errno.EINVAL):
            W.cap_rights_limit(self.f.fileno(), W.new_cap_rights())

        with self.assertRaisesWithErrno(W.SpyceError, errno.EBADF):
            W.cap_rights_limit(-1, goodRights)

        # can't increase the rights on a file
        W.cap_rights_limit(self.f.fileno(), goodRights)

        W.cap_rights_set(goodRights, W.lib.CAP_WRITE)

        with self.assertRaisesWithErrno(W.SpyceError, W.ENOTCAPABLE):
            W.cap_rights_limit(self.f.fileno(), goodRights)

    def test_cap_rights_get_fails(self):
        goodRights = W.cap_rights_init(W.new_cap_rights())

        with self.assertRaisesWithErrno(W.SpyceError, errno.EFAULT):
            W.cap_rights_get(self.f.fileno(),
                             W.ffi.cast('cap_rights_t *', W.ffi.NULL))

        with self.assertRaisesWithErrno(W.SpyceError, errno.EBADF):
            W.cap_rights_get(-1, goodRights)
