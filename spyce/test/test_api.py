import array
import unittest
import tempfile
import socket
import fcntl
import termios

import spyce._api as A

from .support import ErrnoMixin, TemporaryFDMixin


def normalizeRights(rights):
    return {int(r) for r in rights}


class TestInternalFunctions(unittest.TestCase):

    def setUp(self):
        self.cap_rights = A.new_cap_rights()

    def test_ensureValid(self):
        with self.assertRaises(RuntimeError):
            A._ensureValid(self.cap_rights)

        A._ensureValid(A.cap_rights_init(self.cap_rights))

    def test_rightsFromCapRights(self):
        A.cap_rights_init(self.cap_rights, A.lib.CAP_ACCEPT)
        self.assertEqual(A._rightsFromCapRights(self.cap_rights),
                         {A.CAP_ACCEPT})

    def test_fdFor(self):
        self.assertEqual(A.fdFor(1), 1)

        with tempfile.TemporaryFile() as f:
            self.assertEqual(A.fdFor(f), f.fileno())

        no_fileno = "nope!"

        with self.assertRaises(A.SpyceError):
            A.fdFor(no_fileno)


class TestRight(unittest.TestCase):

    def setUp(self):
        self.value = -1
        self.right = A.Right('CAP_FAKE', self.value)

    def test_repr(self):
        repr(self.right)

    def test_int(self):
        self.assertEqual(int(self.right), self.value)

    def test_notIterable(self):
        with self.assertRaises(NotImplementedError):
            iter(self.right)


class TestRights(ErrnoMixin, TemporaryFDMixin, unittest.TestCase):

    def setUp(self):
        super(TestRights, self).setUp()
        self.rights = A.Rights([A.CAP_READ])

    def test_repr(self):
        repr(self.rights)

    def assertRightsSetEqual(self, expected, actual):
        # some code goes through a fast path enabled by the C API and requires
        # that we reach behind our api to ensure things stayed consistent.
        new_rights = A._rightsFromCapRights(actual._cap_rights)
        self.assertEqual(normalizeRights(expected._rights),
                         normalizeRights(new_rights))

    def test_init_with_bad_rights(self):
        with self.assertRaises(A.SpyceError):
            A.Rights([1])

    def test_add(self):
        self.rights.add(A.CAP_WRITE)
        self.assertEqual(self.rights, {A.CAP_READ, A.CAP_WRITE})

        lenBefore = len(self.rights)

        with self.assertRaises(A.SpyceError):
            self.rights.add(1)

        self.assertNotIn(1, self.rights)
        self.assertEqual(lenBefore, len(self.rights))

    def test_discard(self):
        self.rights.add(A.CAP_WRITE)
        self.rights.discard(A.CAP_WRITE)
        self.assertEqual(self.rights, {A.CAP_READ})

        lenBefore = len(self.rights)

        with self.assertRaises(A.SpyceError):
            self.rights.discard(1)

        self.assertEqual(lenBefore, len(self.rights))

    def test_contains(self):
        self.assertIn(A.CAP_READ, self.rights)
        self.assertNotIn(A.CAP_WRITE, self.rights)

    def test_len(self):
        self.assertEqual(len(self.rights), 1)
        self.rights.add(A.CAP_WRITE)
        self.assertEqual(len(self.rights), 2)

    def test_iter(self):
        self.assertEqual(list(self.rights), [A.CAP_READ])

    def test_le(self):
        self.assertLess(A.Rights(()), self.rights)
        self.assertLess(self.rights, set([A.CAP_READ, A.CAP_WRITE]))

    def test_ge(self):
        self.assertGreater(self.rights, A.Rights(()))
        self.assertGreater(self.rights, set([]))

    def test_ior(self):
        prev = set(self.rights)

        for to_ior, func in [
                (A.Rights([A.CAP_READ, A.CAP_WRITE, A.CAP_BIND]),
                 lambda prev: prev | {A.CAP_WRITE, A.CAP_BIND}),
                (A.Rights([A.CAP_ACCEPT]),
                 lambda prev: prev | {A.CAP_ACCEPT}),
                ([A.CAP_EVENT],
                 lambda prev: prev | {A.CAP_EVENT})]:
            self.rights |= to_ior

            expected = prev = func(prev)
            expected = A.Rights(expected)

            self.assertEqual(expected, self.rights)
            self.assertRightsSetEqual(expected, self.rights)

    def test_isub(self):
        self.rights.add(A.CAP_ACCEPT)
        self.rights.add(A.CAP_BIND)

        for to_sub, expected in [
                (A.Rights([A.CAP_WRITE]), set(self.rights)),
                (A.Rights([A.CAP_BIND, A.CAP_ACCEPT]), set([A.CAP_READ])),
                ([A.CAP_READ], set([]))]:
            self.rights -= to_sub

            expected_rights = A.Rights(expected)
            self.assertEqual(expected_rights, self.rights)
            self.assertRightsSetEqual(expected_rights, self.rights)

    def test_isdisjoint(self):
        self.assertTrue(self.rights.isdisjoint(A.Rights([A.CAP_WRITE])))
        self.assertTrue(self.rights.isdisjoint(A.Rights([])))
        self.assertTrue(self.rights.isdisjoint(set([])))

        self.assertFalse(self.rights.isdisjoint(A.Rights([A.CAP_READ])))
        self.assertFalse(self.rights.isdisjoint(A.Rights([A.CAP_READ,
                                                          A.CAP_WRITE])))

    def test_limitTempFile(self):
        data = b'ok'

        # TODO: this is a synonym of CAP_READ.  handle this!
        self.rights.add(A.CAP_RECV)

        self.f.write(data)
        self.f.flush()
        self.f.seek(0)

        self.rights.limitFile(self.f)

        self.assertEqual(self.f.read(), data)

        with self.assertRaisesWithErrno(IOError, A.ENOTCAPABLE):
            self.f.write(b'this fails')
            self.f.flush()

        self.assertEqual(self.rights, A.getFileRights(self.f))

        self.rights.add(A.CAP_WRITE)
        with self.assertRaisesWithErrno(A.SpyceError, A.ENOTCAPABLE):
            self.rights.limitFile(self.f)

    def test_limitSocketPair(self):
        data = b'ok'

        sendRights = A.Rights([A.CAP_SEND])
        recvRights = A.Rights([A.CAP_RECV])

        sendRights.limitFile(self.socketSideA)
        recvRights.limitFile(self.socketSideB)

        # cross your fingers
        with self.assertRaisesWithErrno(socket.error, A.ENOTCAPABLE):
            self.socketSideB.sendall(data)

        with self.assertRaisesWithErrno(socket.error, A.ENOTCAPABLE):
            self.socketSideA.recv(1024)

        self.socketSideA.sendall(data)
        self.assertEqual(data, self.socketSideB.recv(len(data)))


class TestFcntlRights(ErrnoMixin, TemporaryFDMixin, unittest.TestCase):

    def setUp(self):
        super(TestFcntlRights, self).setUp()
        self.fcntlRights = A.FcntlRights([A.CAP_FCNTL_GETFL])

    def test_init_with_bad_fcntl_rights(self):
        with self.assertRaises(A.SpyceError):
            A.FcntlRights([1])

    def test_add(self):
        self.fcntlRights.add(A.CAP_FCNTL_SETFL)
        self.assertEqual(self.fcntlRights, {A.CAP_FCNTL_GETFL,
                                            A.CAP_FCNTL_SETFL})

        lenBefore = len(self.fcntlRights)

        with self.assertRaises(A.SpyceError):
            self.fcntlRights.add(1)

        self.assertNotIn(1, self.fcntlRights)
        self.assertEqual(lenBefore, len(self.fcntlRights))

    def test_discard(self):
        self.fcntlRights.add(A.CAP_FCNTL_SETFL)
        self.fcntlRights.discard(A.CAP_FCNTL_GETFL)
        self.assertEqual(self.fcntlRights, {A.CAP_FCNTL_SETFL})

        lenBefore = len(self.fcntlRights)

        with self.assertRaises(A.SpyceError):
            self.fcntlRights.discard(1)

        self.assertEqual(lenBefore, len(self.fcntlRights))

    def test_contains(self):
        self.assertIn(A.CAP_FCNTL_GETFL, self.fcntlRights)
        self.assertNotIn(A.CAP_FCNTL_SETFL, self.fcntlRights)

    def test_len(self):
        self.assertEqual(len(self.fcntlRights), 1)
        self.fcntlRights.add(A.CAP_FCNTL_GETOWN)
        self.assertEqual(len(self.fcntlRights), 2)

    def test_iter(self):
        self.assertEqual(list(self.fcntlRights), [A.CAP_FCNTL_GETFL])

    def test_limitFile(self):
        self.fcntlRights.limitFile(self.f)

        with self.assertRaisesWithErrno(IOError, A.ENOTCAPABLE):
            fcntl.fcntl(self.f, fcntl.F_SETFL, 0)

        self.assertEqual(A.getFileFcntlRights(self.f), self.fcntlRights)

        self.fcntlRights.add(A.CAP_FCNTL_SETFL)
        with self.assertRaisesWithErrno(A.SpyceError, A.ENOTCAPABLE):
            self.fcntlRights.limitFile(self.f)


class TestIoctlRights(ErrnoMixin, TemporaryFDMixin, unittest.TestCase):

    def setUp(self):
        super(TestIoctlRights, self).setUp()
        self.ioctlRights = A.IoctlRights([termios.FIOCLEX])

    def test_allIoctls(self):
        self.assertFalse(self.ioctlRights.allIoctls)

        ioctlRights = A.IoctlRights([A.CAP_IOCTLS_ALL])
        self.assertTrue(ioctlRights.allIoctls)

        ioctlRights.add(termios.FIOCLEX)
        self.assertFalse(ioctlRights.allIoctls)

    def test_init_with_bad_fcntl_rights(self):
        with self.assertRaises(A.SpyceError):
            A.IoctlRights([None])

    def test_add(self):
        self.ioctlRights.add(termios.FIONREAD)
        self.assertEqual(self.ioctlRights, {termios.FIOCLEX,
                                            termios.FIONREAD})

        lenBefore = len(self.ioctlRights)

        with self.assertRaises(A.SpyceError):
            self.ioctlRights.add(None)

        self.assertNotIn(None, self.ioctlRights)
        self.assertEqual(lenBefore, len(self.ioctlRights))

    def test_discard(self):
        self.ioctlRights.add(termios.FIONREAD)
        self.ioctlRights.discard(termios.FIOCLEX)
        self.assertEqual(self.ioctlRights, {termios.FIONREAD})

        lenBefore = len(self.ioctlRights)

        with self.assertRaises(A.SpyceError):
            self.ioctlRights.discard(None)

        self.assertEqual(lenBefore, len(self.ioctlRights))

    def test_contains(self):
        self.assertIn(termios.FIOCLEX, self.ioctlRights)
        self.assertNotIn(termios.FIONREAD, self.ioctlRights)

    def test_len(self):
        self.assertEqual(len(self.ioctlRights), 1)
        self.ioctlRights.add(termios.FIOASYNC)
        self.assertEqual(len(self.ioctlRights), 2)

    def test_iter(self):
        self.assertEqual(list(self.ioctlRights), [termios.FIOCLEX])

    def test_limitFile_all_ioctls(self):
        ioctlRights = A.getFileIoctlRights(self.pipeReadFD)
        self.assertTrue(ioctlRights.allIoctls)

        ioctlRights.limitFile(self.pipeReadFD)

        self.assertTrue(A.getFileIoctlRights(self.pipeReadFD).allIoctls)

    def test_limitFile(self):
        self.ioctlRights.limitFile(self.f)

        with self.assertRaisesWithErrno(IOError, A.ENOTCAPABLE):
            buf = array.array('I', [0])
            fcntl.ioctl(self.f, termios.FIONREAD, buf, 1)

        self.assertEqual(A.getFileIoctlRights(self.f), self.ioctlRights)

        self.ioctlRights.add(termios.FIONREAD)
        with self.assertRaisesWithErrno(A.SpyceError, A.ENOTCAPABLE):
            self.ioctlRights.limitFile(self.f)
