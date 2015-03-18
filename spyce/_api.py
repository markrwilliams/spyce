import operator
from collections import namedtuple, MutableSet
from ._wrapper import (lib,
                       cap_enter, cap_getmode,
                       new_cap_rights, cap_rights_init,
                       cap_rights_set, cap_rights_get,
                       cap_rights_clear, cap_rights_is_set,
                       cap_rights_merge, cap_rights_remove,
                       cap_rights_contains, cap_rights_is_valid,
                       cap_rights_limit,
                       cap_fcntls_get, cap_fcntls_limit,
                       new_ioctl_rights, cap_ioctls_get, cap_ioctls_limit,
                       extended_errorcode,
                       SpyceError,
                       CAP_IOCTLS_ALL,
                       MAX_IOCTL_CMDS,
                       ENOTCAPABLE,
                       ECAPMODE,
                       ENOTRECOVERABLE,
                       EOWNERDEAD)
from ._compat import reduce, long


class Right(namedtuple('Right', 'name value')):

    def __int__(self):
        return self.value

    def __iter__(self):
        raise NotImplementedError

    def __repr__(self):
        cn = self.__class__.__name__
        return '{}({})'.format(cn, self.name)


RIGHTS = set()


def _add_right(r, s=RIGHTS):
    s.add(r)
    return r


CAP_ACCEPT = _add_right(Right("CAP_ACCEPT", lib.CAP_ACCEPT))
CAP_ACL_CHECK = _add_right(Right('CAP_ACL_CHECK', lib.CAP_ACL_CHECK))
CAP_ACL_DELETE = _add_right(Right('CAP_ACL_DELETE', lib.CAP_ACL_DELETE))
CAP_ACL_GET = _add_right(Right('CAP_ACL_GET', lib.CAP_ACL_GET))
CAP_ACL_SET = _add_right(Right('CAP_ACL_SET', lib.CAP_ACL_SET))
CAP_BIND = _add_right(Right('CAP_BIND', lib.CAP_BIND))
CAP_BINDAT = _add_right(Right('CAP_BINDAT', lib.CAP_BINDAT))
CAP_CHFLAGSAT = _add_right(Right('CAP_CHFLAGSAT', lib.CAP_CHFLAGSAT))
CAP_CONNECT = _add_right(Right('CAP_CONNECT', lib.CAP_CONNECT))
CAP_CONNECTAT = _add_right(Right('CAP_CONNECTAT', lib.CAP_CONNECTAT))
CAP_CREATE = _add_right(Right('CAP_CREATE', lib.CAP_CREATE))
CAP_EVENT = _add_right(Right('CAP_EVENT', lib.CAP_EVENT))
CAP_EXTATTR_DELETE = _add_right(Right('CAP_EXTATTR_DELETE',
                                      lib.CAP_EXTATTR_DELETE))
CAP_EXTATTR_GET = _add_right(Right('CAP_EXTATTR_GET', lib.CAP_EXTATTR_GET))
CAP_EXTATTR_LIST = _add_right(Right('CAP_EXTATTR_LIST', lib.CAP_EXTATTR_LIST))
CAP_EXTATTR_SET = _add_right(Right('CAP_EXTATTR_SET', lib.CAP_EXTATTR_SET))
CAP_FCHDIR = _add_right(Right('CAP_FCHDIR', lib.CAP_FCHDIR))
CAP_FCHFLAGS = _add_right(Right('CAP_FCHFLAGS', lib.CAP_FCHFLAGS))
CAP_FCHMOD = _add_right(Right('CAP_FCHMOD', lib.CAP_FCHMOD))
CAP_FCHMODAT = _add_right(Right('CAP_FCHMODAT', lib.CAP_FCHMODAT))
CAP_FCHOWN = _add_right(Right('CAP_FCHOWN', lib.CAP_FCHOWN))
CAP_FCHOWNAT = _add_right(Right('CAP_FCHOWNAT', lib.CAP_FCHOWNAT))
CAP_FCNTL = _add_right(Right('CAP_FCNTL', lib.CAP_FCNTL))
CAP_FEXECVE = _add_right(Right('CAP_FEXECVE', lib.CAP_FEXECVE))
CAP_FLOCK = _add_right(Right('CAP_FLOCK', lib.CAP_FLOCK))
CAP_FPATHCONF = _add_right(Right('CAP_FPATHCONF', lib.CAP_FPATHCONF))
CAP_FSCK = _add_right(Right('CAP_FSCK', lib.CAP_FSCK))
CAP_FSTAT = _add_right(Right('CAP_FSTAT', lib.CAP_FSTAT))
CAP_FSTATAT = _add_right(Right('CAP_FSTATAT', lib.CAP_FSTATAT))
CAP_FSTATFS = _add_right(Right('CAP_FSTATFS', lib.CAP_FSTATFS))
CAP_FSYNC = _add_right(Right('CAP_FSYNC', lib.CAP_FSYNC))
CAP_FTRUNCATE = _add_right(Right('CAP_FTRUNCATE', lib.CAP_FTRUNCATE))
CAP_FUTIMES = _add_right(Right('CAP_FUTIMES', lib.CAP_FUTIMES))
CAP_FUTIMESAT = _add_right(Right('CAP_FUTIMESAT', lib.CAP_FUTIMESAT))
CAP_GETPEERNAME = _add_right(Right('CAP_GETPEERNAME', lib.CAP_GETPEERNAME))
CAP_GETSOCKNAME = _add_right(Right('CAP_GETSOCKNAME', lib.CAP_GETSOCKNAME))
CAP_GETSOCKOPT = _add_right(Right('CAP_GETSOCKOPT', lib.CAP_GETSOCKOPT))
CAP_IOCTL = _add_right(Right('CAP_IOCTL', lib.CAP_IOCTL))
CAP_KQUEUE = _add_right(Right('CAP_KQUEUE', lib.CAP_KQUEUE))
CAP_KQUEUE_CHANGE = _add_right(Right('CAP_KQUEUE_CHANGE',
                                     lib.CAP_KQUEUE_CHANGE))
CAP_KQUEUE_EVENT = _add_right(Right('CAP_KQUEUE_EVENT', lib.CAP_KQUEUE_EVENT))
CAP_LINKAT = _add_right(Right('CAP_LINKAT', lib.CAP_LINKAT))
CAP_LISTEN = _add_right(Right('CAP_LISTEN', lib.CAP_LISTEN))
CAP_LOOKUP = _add_right(Right('CAP_LOOKUP', lib.CAP_LOOKUP))
CAP_MAC_GET = _add_right(Right('CAP_MAC_GET', lib.CAP_MAC_GET))
CAP_MAC_SET = _add_right(Right('CAP_MAC_SET', lib.CAP_MAC_SET))
CAP_MKDIRAT = _add_right(Right('CAP_MKDIRAT', lib.CAP_MKDIRAT))
CAP_MKFIFOAT = _add_right(Right('CAP_MKFIFOAT', lib.CAP_MKFIFOAT))
CAP_MKNODAT = _add_right(Right('CAP_MKNODAT', lib.CAP_MKNODAT))
CAP_MMAP = _add_right(Right('CAP_MMAP', lib.CAP_MMAP))
CAP_MMAP_R = _add_right(Right('CAP_MMAP_R', lib.CAP_MMAP_R))
CAP_MMAP_RW = _add_right(Right('CAP_MMAP_RW', lib.CAP_MMAP_RW))
CAP_MMAP_RWX = _add_right(Right('CAP_MMAP_RWX', lib.CAP_MMAP_RWX))
CAP_MMAP_RX = _add_right(Right('CAP_MMAP_RX', lib.CAP_MMAP_RX))
CAP_MMAP_W = _add_right(Right('CAP_MMAP_W', lib.CAP_MMAP_W))
CAP_MMAP_WX = _add_right(Right('CAP_MMAP_WX', lib.CAP_MMAP_WX))
CAP_MMAP_X = _add_right(Right('CAP_MMAP_X', lib.CAP_MMAP_X))
CAP_PDGETPID = _add_right(Right('CAP_PDGETPID', lib.CAP_PDGETPID))
CAP_PDKILL = _add_right(Right('CAP_PDKILL', lib.CAP_PDKILL))
CAP_PDWAIT = _add_right(Right('CAP_PDWAIT', lib.CAP_PDWAIT))
CAP_PEELOFF = _add_right(Right('CAP_PEELOFF', lib.CAP_PEELOFF))
CAP_PREAD = _add_right(Right('CAP_PREAD', lib.CAP_PREAD))
CAP_PWRITE = _add_right(Right('CAP_PWRITE', lib.CAP_PWRITE))
CAP_READ = _add_right(Right('CAP_READ', lib.CAP_READ))
CAP_RECV = _add_right(Right('CAP_RECV', lib.CAP_RECV))
CAP_RENAMEAT = _add_right(Right('CAP_RENAMEAT', lib.CAP_RENAMEAT))
CAP_SEEK = _add_right(Right('CAP_SEEK', lib.CAP_SEEK))
CAP_SEM_GETVALUE = _add_right(Right('CAP_SEM_GETVALUE', lib.CAP_SEM_GETVALUE))
CAP_SEM_POST = _add_right(Right('CAP_SEM_POST', lib.CAP_SEM_POST))
CAP_SEM_WAIT = _add_right(Right('CAP_SEM_WAIT', lib.CAP_SEM_WAIT))
CAP_SEND = _add_right(Right('CAP_SEND', lib.CAP_SEND))
CAP_SETSOCKOPT = _add_right(Right('CAP_SETSOCKOPT', lib.CAP_SETSOCKOPT))
CAP_SHUTDOWN = _add_right(Right('CAP_SHUTDOWN', lib.CAP_SHUTDOWN))
CAP_SYMLINKAT = _add_right(Right('CAP_SYMLINKAT', lib.CAP_SYMLINKAT))
CAP_TTYHOOK = _add_right(Right('CAP_TTYHOOK', lib.CAP_TTYHOOK))
CAP_UNLINKAT = _add_right(Right('CAP_UNLINKAT', lib.CAP_UNLINKAT))
CAP_WRITE = _add_right(Right('CAP_WRITE', lib.CAP_WRITE))


RIGHTS = frozenset(RIGHTS)


class FcntlRight(Right):
    pass


FCNTL_RIGHTS = set()

CAP_FCNTL_GETFL = _add_right(FcntlRight('CAP_FCNTL_GETFL',
                                        lib.CAP_FCNTL_GETFL),
                             FCNTL_RIGHTS)
CAP_FCNTL_SETFL = _add_right(FcntlRight('CAP_FCNTL_SETFL',
                                        lib.CAP_FCNTL_SETFL),
                             FCNTL_RIGHTS)
CAP_FCNTL_GETOWN = _add_right(FcntlRight('CAP_FCNTL_GETOWN',
                                         lib.CAP_FCNTL_GETOWN),
                              FCNTL_RIGHTS)
CAP_FCNTL_SETOWN = _add_right(FcntlRight('CAP_FCNTL_SETOWN',
                                         lib.CAP_FCNTL_SETOWN),
                              FCNTL_RIGHTS)


FCNTL_RIGHTS = frozenset(FCNTL_RIGHTS)


__all__ = (['Right',
            'Rights', 'FcntlRights', 'IoctlRights',
            'getFileRights', 'getFileFcntlRights', 'getFileIoctlRights',
            'inCapabilityMode', 'enterCapabilityMode',
            'CAP_IOCTLS_ALL',
            'ENOTRECOVERABLE',
            'ECAPMODE',
            'ENOTRECOVERABLE',
            'EOWNERDEAD',
            'extended_errorcode']
           + [r.name for r in RIGHTS]
           + [r.name for r in FCNTL_RIGHTS])


def fdFor(thing):
    if isinstance(thing, int):
        return thing
    elif callable(getattr(thing, 'fileno', None)):
        return thing.fileno()
    raise SpyceError("{!r} lacks a fileno", thing)


def _ensureValid(cap_rights):
    if not cap_rights_is_valid(cap_rights):
        raise RuntimeError('Invalid underlying cap_rights object!  '
                           'Please file a bug')


def _rightsFromCapRights(cap_rights):
    return {right for right in RIGHTS
            if cap_rights_is_set(cap_rights, int(right))}


_NO_CAP_RIGHTS = object()


class BaseRights(MutableSet):

    def __init__(self, rights):
        self._rights = rights

    def add(self, thing):
        self._rights.add(thing)

    def discard(self, thing):
        self._rights.discard(thing)

    def __iter__(self):
        return iter(self._rights)

    def __contains__(self, value):
        return value in self._rights

    def __len__(self):
        return len(self._rights)

    def __le__(self, other):
        if not isinstance(other, BaseRights):
            super(BaseRights, self).__le__(other)

        return self._rights <= getattr(other, '_rights', other)

    def __ge__(self, other):
        if not isinstance(other, BaseRights):
            super(BaseRights, self).__ge__(other)

        return self._rights >= getattr(other, '_rights', other)

    def __repr__(self):
        cn = self.__class__.__name__
        rights = ', '.join('{!r}'.format(r) for r in self._rights)
        return '{}([{}])'.format(cn, rights)


class Rights(BaseRights):

    def __init__(self, iterable):
        if iterable is _NO_CAP_RIGHTS:
            return

        rights = set(iterable)
        bad = rights - RIGHTS
        if bad:
            raise SpyceError('Invalid rights: {}'.format(tuple(bad)))

        self._cap_rights = new_cap_rights()
        cap_rights_init(self._cap_rights, *map(int, rights))
        _ensureValid(self._cap_rights)

        self._rights = rights

    @classmethod
    def _from_cap_rights(cls, cap_rights):
        _ensureValid(cap_rights)
        rights = cls(_NO_CAP_RIGHTS)
        rights._rights = _rightsFromCapRights(cap_rights)
        rights._cap_rights = cap_rights
        return rights

    def add(self, right):
        if right not in RIGHTS:
            raise SpyceError('Invalid right {!r}'.format(right))

        _ensureValid(self._cap_rights)
        cap_rights_set(self._cap_rights, int(right))
        super(Rights, self).add(right)

    def discard(self, right):
        if right not in RIGHTS:
            raise SpyceError('Invalid right {!r}'.format(right))

        _ensureValid(self._cap_rights)
        cap_rights_clear(self._cap_rights, int(right))
        super(Rights, self).discard(right)

    def __ior__(self, other):
        cls = self.__class__
        if not isinstance(other, cls):
            return super(cls, self).__ior__(other)

        self_cap_rights = self._cap_rights
        cap_rights_merge(self_cap_rights, other._cap_rights)
        _ensureValid(self_cap_rights)

        self._rights |= other._rights
        return self

    def __isub__(self, other):
        cls = self.__class__
        if not isinstance(other, cls):
            return super(cls, self).__isub__(other)

        self_cap_rights = self._cap_rights
        cap_rights_remove(self_cap_rights, other._cap_rights)
        _ensureValid(self_cap_rights)

        self._rights -= other._rights
        return self

    def isdisjoint(self, other):
        cls = self.__class__
        if not isinstance(other, cls):
            return super(cls, self).isdisjoint(other)

        if not other:
            return True

        _ensureValid(other._cap_rights)
        return (self._rights.isdisjoint(other)
                and not cap_rights_contains(self._cap_rights,
                                            other._cap_rights))

    def limitFile(self, fileobj):
        cap_rights_limit(fdFor(fileobj), self._cap_rights)


class FcntlRights(BaseRights):

    def __init__(self, iterable):
        rights = set(iterable)
        bad = rights - FCNTL_RIGHTS
        if bad:
            raise SpyceError('Invalid fcntl rights: {}'.format(tuple(bad)))

        self._rights = rights

    @classmethod
    def _from_intRights(cls, intRights):
        return cls(right for right in FCNTL_RIGHTS if intRights & int(right))

    def add(self, right):
        if right not in FCNTL_RIGHTS:
            raise SpyceError('Invalid fcntl right {!r}'.format(right))
        super(FcntlRights, self).add(right)

    def discard(self, right):
        if right not in FCNTL_RIGHTS:
            raise SpyceError('Invalid fcntl right {!r}'.format(right))
        super(FcntlRights, self).discard(right)

    def limitFile(self, fileobj):
        fd = fdFor(fileobj)
        rights = reduce(operator.or_, map(int, self._rights))
        cap_fcntls_limit(fd, rights)


ALL_IOCTLS = frozenset([CAP_IOCTLS_ALL])


class IoctlRights(BaseRights):
    allIoctls = False

    def __init__(self, iterable):
        rights = set(iterable)
        bad = {r for r in rights if not isinstance(r, (int, long))}
        if bad:
            raise SpyceError('Invald ioctls {!r}'.format(tuple(bad)))
        if rights == ALL_IOCTLS:
            self.allIoctls = True
        self._rights = rights

    def add(self, right):
        if not isinstance(right, (int, long)):
            raise SpyceError('Invalid ioctl {!r}'.format(right))
        self.allIoctls = False
        super(IoctlRights, self).add(right)

    def discard(self, right):
        if not isinstance(right, (int, long)):
            raise SpyceError('Invalid ioctl {!r}'.format(right))
        super(IoctlRights, self).discard(right)

    def limitFile(self, fileobj):
        if self.allIoctls:
            return
        fd = fdFor(fileobj)
        rights = list(self._rights)
        while rights:
            toApply, rights = rights[:MAX_IOCTL_CMDS], rights[MAX_IOCTL_CMDS:]
            buf = new_ioctl_rights(*toApply)
            cap_ioctls_limit(fd, buf)


def getFileRights(fileobj):
    fd = fdFor(fileobj)
    cap_rights = new_cap_rights()
    cap_rights_get(fd, cap_rights)
    return Rights._from_cap_rights(cap_rights)


def getFileFcntlRights(fileobj):
    fd = fdFor(fileobj)
    intRights = cap_fcntls_get(fd)
    return FcntlRights._from_intRights(intRights)


def getFileIoctlRights(fileobj, upTo=MAX_IOCTL_CMDS):
    buf = new_ioctl_rights(*[0] * upTo)
    fd = fdFor(fileobj)
    numIoctls = cap_ioctls_get(fd, buf)
    if numIoctls == CAP_IOCTLS_ALL:
        return IoctlRights(ALL_IOCTLS)
    return IoctlRights(buf[0:numIoctls])


def inCapabilityMode():
    return cap_getmode()


def enterCapabilityMode():
    # TODO: close fds, set resource limits, what else?
    cap_enter()
