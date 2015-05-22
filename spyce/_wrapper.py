import errno
import os

from ._binding import ffi, lib

CAP_IOCTLS_ALL = lib.CAP_IOCTLS_ALL

ENOTCAPABLE = lib.ENOTCAPABLE
ECAPMODE = lib.ECAPMODE
ENOTRECOVERABLE = lib.ENOTRECOVERABLE
EOWNERDEAD = lib.EOWNERDEAD

extended_errorcode = errno.errorcode.copy()
extended_errorcode[ENOTCAPABLE] = 'ENOTCAPABLE'
extended_errorcode[ECAPMODE] = 'ECAPMODE'
extended_errorcode[ENOTRECOVERABLE] = 'ENOTRECOVERABLE'
extended_errorcode[EOWNERDEAD] = 'EOWNERDEAD'

MAX_IOCTL_CMDS = 256


def _errno_to_str(errno):
    return '[Errno {} ()] {}'.format(errno,
                                     extended_errorcode[errno],
                                     os.strerror(errno))


class SpyceError(Exception):

    def __init__(self, msg=None, errno=None):
        if msg is None and errno is not None:
            msg = _errno_to_str(errno)
        super(SpyceError, self).__init__(msg)
        self.errno = errno


def cap_getmode():
    in_cap_mode = ffi.new('unsigned int *', 0)
    if lib.cap_getmode(in_cap_mode) < 0:  # pragma: no cover
        raise SpyceError(ffi.errno)
    return bool(in_cap_mode[0])


def cap_enter():                # pragma: no cover
    if lib.cap_enter() < 0:
        raise SpyceError(ffi.errno)


def new_cap_rights():
    return ffi.new('cap_rights_t*')


def prep_rights(rights):
    args = [ffi.cast('unsigned long long', right) for right in rights]
    args.append(ffi.NULL)
    return args


def cap_rights_init(cap_rights, *rights):
    lib.__cap_rights_init(lib.CAP_RIGHTS_VERSION,
                          cap_rights,
                          *prep_rights(rights))
    return cap_rights


def cap_rights_set(cap_rights, *rights):
    lib.__cap_rights_set(cap_rights, *prep_rights(rights))
    return cap_rights


def cap_rights_clear(cap_rights, *rights):
    lib.__cap_rights_clear(cap_rights, *prep_rights(rights))
    return cap_rights


def cap_rights_is_set(cap_rights, *rights):
    return lib.__cap_rights_is_set(cap_rights, *prep_rights(rights))


def cap_rights_is_valid(cap_rights):
    return bool(lib.cap_rights_is_valid(cap_rights))


def cap_rights_merge(dst, src):
    lib.cap_rights_merge(dst, src)
    return dst


def cap_rights_remove(dst, src):
    lib.cap_rights_remove(dst, src)
    return dst


def cap_rights_contains(big, little):
    return bool(lib.cap_rights_contains(big, little))


def cap_rights_limit(fd, rights):
    if lib.cap_rights_limit(fd, rights) < 0:
        raise SpyceError(errno=ffi.errno)


def cap_rights_get(fd, rights):
    if lib.cap_rights_get(fd, rights) < 0:
        raise SpyceError(errno=ffi.errno)


def cap_fcntls_get(fd):
    fcntlrights = ffi.new('uint32_t *')
    if lib.cap_fcntls_get(fd, fcntlrights) < 0:
        raise SpyceError(errno=ffi.errno)
    return fcntlrights[0]


def cap_fcntls_limit(fd, fcntlrights):
    if lib.cap_fcntls_limit(fd, fcntlrights) < 0:
        raise SpyceError(errno=ffi.errno)


def new_ioctl_rights(*commands):
    return ffi.new('unsigned long[]', commands)


def cap_ioctls_get(fd, cmds):
    total_commands = lib.cap_ioctls_get(fd, cmds, len(cmds))
    if total_commands < 0:
        raise SpyceError(errno=ffi.errno)
    return total_commands


def cap_ioctls_limit(fd, cmds):
    if lib.cap_ioctls_limit(fd, cmds, len(cmds)) < 0:
        raise SpyceError(errno=ffi.errno)


if __name__ == '__main__':
    ffi.compile()
