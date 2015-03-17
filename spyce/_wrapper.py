import errno
import os

import cffi

ffi = cffi.FFI()

ffi.cdef('''
typedef unsigned int u_int;

struct cap_rights {
    ...;
};

typedef	struct cap_rights cap_rights_t;


#define ENOTCAPABLE ...
#define ECAPMODE ...
#define ENOTRECOVERABLE ...
#define EOWNERDEAD ...

/* internal use, so that we can call __cap_rights_init */
#define CAP_RIGHTS_VERSION ...

#define CAP_ACCEPT ...
#define CAP_ACL_CHECK ...
#define CAP_ACL_DELETE ...
#define CAP_ACL_GET ...
#define CAP_ACL_SET ...
#define CAP_BIND ...
#define CAP_BINDAT ...
#define CAP_CHFLAGSAT ...
#define CAP_CONNECT ...
#define CAP_CONNECTAT ...
#define CAP_CREATE ...
#define CAP_EVENT ...
#define CAP_EXTATTR_DELETE ...
#define CAP_EXTATTR_GET ...
#define CAP_EXTATTR_LIST ...
#define CAP_EXTATTR_SET ...
#define CAP_FCHDIR ...
#define CAP_FCHFLAGS ...
#define CAP_FCHMOD ...
#define CAP_FCHMODAT ...
#define CAP_FCHOWN ...
#define CAP_FCHOWNAT ...
#define CAP_FCNTL ...
#define CAP_FEXECVE ...
#define CAP_FLOCK ...
#define CAP_FPATHCONF ...
#define CAP_FSCK ...
#define CAP_FSTAT ...
#define CAP_FSTATAT ...
#define CAP_FSTATFS ...
#define CAP_FSYNC ...
#define CAP_FTRUNCATE ...
#define CAP_FUTIMES ...
#define CAP_FUTIMESAT ...
#define CAP_GETPEERNAME ...
#define CAP_GETSOCKNAME ...
#define CAP_GETSOCKOPT ...
#define CAP_IOCTL ...
#define CAP_KQUEUE ...
#define CAP_KQUEUE_CHANGE ...
#define CAP_KQUEUE_EVENT ...
#define CAP_LINKAT ...
#define CAP_LISTEN ...
#define CAP_LOOKUP ...
#define CAP_MAC_GET ...
#define CAP_MAC_SET ...
#define CAP_MKDIRAT ...
#define CAP_MKFIFOAT ...
#define CAP_MKNODAT ...
#define CAP_MMAP ...
#define CAP_MMAP_R ...
#define CAP_MMAP_RW ...
#define CAP_MMAP_RWX ...
#define CAP_MMAP_RX ...
#define CAP_MMAP_W ...
#define CAP_MMAP_WX ...
#define CAP_MMAP_X ...
#define CAP_PDGETPID ...
#define CAP_PDKILL ...
#define CAP_PDWAIT ...
#define CAP_PEELOFF ...
#define CAP_PREAD ...
#define CAP_PWRITE ...
#define CAP_READ ...
#define CAP_RECV ...
#define CAP_RENAMEAT ...
#define CAP_SEEK ...
#define CAP_SEM_GETVALUE ...
#define CAP_SEM_POST ...
#define CAP_SEM_WAIT ...
#define CAP_SEND ...
#define CAP_SETSOCKOPT ...
#define CAP_SHUTDOWN ...
#define CAP_SYMLINKAT ...
#define CAP_TTYHOOK ...
#define CAP_UNLINKAT ...
#define CAP_WRITE ...

int
cap_enter(void);

int
cap_getmode(u_int *modep);

cap_rights_t *
__cap_rights_init(int version, cap_rights_t *rights, ...);

cap_rights_t *
__cap_rights_set(cap_rights_t *rights, ...);

cap_rights_t
*__cap_rights_clear(cap_rights_t *rights, ...);

bool
__cap_rights_is_set(const cap_rights_t *rights, ...);

bool
cap_rights_is_valid(const cap_rights_t *rights);

cap_rights_t *
cap_rights_merge(cap_rights_t *dst, const cap_rights_t *src);

cap_rights_t *
cap_rights_remove(cap_rights_t *dst, const cap_rights_t *src);

bool
cap_rights_contains(const cap_rights_t *big, const cap_rights_t *little);

int
cap_rights_limit(int fd, const cap_rights_t *rights);

int
cap_rights_get(int fd, cap_rights_t *rights);

static const int CAP_FCNTL_GETFL;
static const int CAP_FCNTL_SETFL;
static const int CAP_FCNTL_GETOWN;
static const int CAP_FCNTL_SETOWN;

int
cap_fcntls_get(int fd, uint32_t *fcntlrights);

int
cap_fcntls_limit(int fd, uint32_t fcntlights);

static const long CAP_IOCTLS_ALL;

int
cap_ioctls_limit(int fd, const unsigned long *cmds, size_t cmds);

ssize_t
cap_ioctls_get(int fd, unsigned long *cmds, size_t maxcmds);
''')

lib = ffi.verify('''
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/capability.h>
''', ext_package='spyce')


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
