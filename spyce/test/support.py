import contextlib
import tempfile
import unittest
import socket
import errno
import sys
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

        kwargs = {}
        if sys.version_info.major > 2:
            # Python 3 will use a buffered io object that *always*
            # gets flushed on close, even if the buffer is empty.
            # Disable buffering to avoid ENOTCAPABLE on self.f.close()
            # TODO: write tests to exercise "normal" (i.e., unicode
            # and buffered) Python 3 files.
            kwargs['buffering'] = 0

        self.f = tempfile.TemporaryFile('wb+',
                                        prefix="spyce_test_{}_tmp".format(cn),
                                        **kwargs)
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
