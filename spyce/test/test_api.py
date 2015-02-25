import unittest
import StringIO
import tempfile
import socket

import spyce._wrapper as W
import spyce._api as A


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

        no_fileno = StringIO.StringIO("nope!")

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


class TestRights(unittest.TestCase):

    def setUp(self):
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
        self.assertTrue(A.CAP_READ in self.rights)

    def test_len(self):
        self.assertEqual(len(self.rights), 1)
        self.rights.add(A.CAP_WRITE)
        self.assertEqual(len(self.rights), 2)

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

    def verifyErrno(self, cm, err=W.ENOTCAPABLE):
        the_exception = cm.exception
        self.assertEquals(the_exception.errno, err)

    def test_limitTempFile(self):
        data = 'ok'

        # TODO: this is a synonym of CAP_READ.  handle this!
        self.rights.add(A.CAP_RECV)

        with tempfile.TemporaryFile(mode='w+') as f:
            f.write(data)
            f.seek(0)

            self.rights.limitFile(f)

            self.assertEqual(f.read(), data)

            with self.assertRaises(IOError) as cm:
                f.write('this fails')
                f.flush()
            self.verifyErrno(cm)

            self.assertEquals(self.rights, A.getFileRights(f))

    def test_limitSocketPair(self):
        data = 'ok'

        a, b = socket.socketpair()

        sendRights = A.Rights([A.CAP_SEND])
        recvRights = A.Rights([A.CAP_RECV])

        try:
            sendRights.limitFile(a)
            recvRights.limitFile(b)

            # cross your fingers
            with self.assertRaises(socket.error) as cm:
                b.sendall(data)
            self.verifyErrno(cm)

            with self.assertRaises(socket.error) as cm:
                a.recv(1024)
            self.verifyErrno(cm)

            a.sendall(data)
            self.assertEqual(data, b.recv(len(data)))

        finally:
            a.close()
            b.close()
