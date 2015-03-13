import contextlib
import tempfile
import unittest
import socket
import errno
import os


class ErrnoMixin(unittest.TestCase):

    @contextlib.contextmanager
    def assertRaisesWithErrno(self, exc, errno):
        with self.assertRaises(exc) as caught_ce:
            yield

        self.assertTrue(caught_ce.exception.errno, errno)


class TemporaryFDMixin(unittest.TestCase):

    def setUp(self):
        cn = self.__class__.__name__
        self.f = tempfile.TemporaryFile('w+',
                                        prefix="spyce_test_{}_tmp".format(cn))
        self.pipeReadFD, self.pipeWriteFD = self.pipeFDs = os.pipe()
        self.socketSideA, self.socketSideB = self.sockets = socket.socketpair()

    def tearDown(self):
        self.f.close()

        for s in self.sockets:
            s.close()

        for fd in self.pipeFDs:
            try:
                os.close(fd)
            except OSError as e:
                if e.errno != errno.EBADF:
                    raise
