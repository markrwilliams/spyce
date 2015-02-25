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


static const int _M_ENOTCAPABLE;
static const int _M_ECAPMODE;
static const int _M_ENOTRECOVERABLE;
static const int _M_EOWNERDEAD;

/* internal use, so that we can call __cap_rights_init */
static const int _M_CAP_RIGHTS_VERSION;

static const unsigned long long CAP_ACCEPT;
static const unsigned long long CAP_ACL_CHECK;
static const unsigned long long CAP_ACL_DELETE;
static const unsigned long long CAP_ACL_GET;
static const unsigned long long CAP_ACL_SET;
static const unsigned long long CAP_BIND;
static const unsigned long long CAP_BINDAT;
static const unsigned long long CAP_CHFLAGSAT;
static const unsigned long long CAP_CONNECT;
static const unsigned long long CAP_CONNECTAT;
static const unsigned long long CAP_CREATE;
static const unsigned long long CAP_EVENT;
static const unsigned long long CAP_EXTATTR_DELETE;
static const unsigned long long CAP_EXTATTR_GET;
static const unsigned long long CAP_EXTATTR_LIST;
static const unsigned long long CAP_EXTATTR_SET;
static const unsigned long long CAP_FCHDIR;
static const unsigned long long CAP_FCHFLAGS;
static const unsigned long long CAP_FCHMOD;
static const unsigned long long CAP_FCHMODAT;
static const unsigned long long CAP_FCHOWN;
static const unsigned long long CAP_FCHOWNAT;
static const unsigned long long CAP_FCNTL;
static const unsigned long long CAP_FEXECVE;
static const unsigned long long CAP_FLOCK;
static const unsigned long long CAP_FPATHCONF;
static const unsigned long long CAP_FSCK;
static const unsigned long long CAP_FSTAT;
static const unsigned long long CAP_FSTATAT;
static const unsigned long long CAP_FSTATFS;
static const unsigned long long CAP_FSYNC;
static const unsigned long long CAP_FTRUNCATE;
static const unsigned long long CAP_FUTIMES;
static const unsigned long long CAP_FUTIMESAT;
static const unsigned long long CAP_GETPEERNAME;
static const unsigned long long CAP_GETSOCKNAME;
static const unsigned long long CAP_GETSOCKOPT;
static const unsigned long long CAP_IOCTL;
static const unsigned long long CAP_KQUEUE;
static const unsigned long long CAP_KQUEUE_CHANGE;
static const unsigned long long CAP_KQUEUE_EVENT;
static const unsigned long long CAP_LINKAT;
static const unsigned long long CAP_LISTEN;
static const unsigned long long CAP_LOOKUP;
static const unsigned long long CAP_MAC_GET;
static const unsigned long long CAP_MAC_SET;
static const unsigned long long CAP_MKDIRAT;
static const unsigned long long CAP_MKFIFOAT;
static const unsigned long long CAP_MKNODAT;
static const unsigned long long CAP_MMAP;
static const unsigned long long CAP_MMAP_R;
static const unsigned long long CAP_MMAP_RW;
static const unsigned long long CAP_MMAP_RWX;
static const unsigned long long CAP_MMAP_RX;
static const unsigned long long CAP_MMAP_W;
static const unsigned long long CAP_MMAP_WX;
static const unsigned long long CAP_MMAP_X;
static const unsigned long long CAP_PDGETPID;
static const unsigned long long CAP_PDKILL;
static const unsigned long long CAP_PDWAIT;
static const unsigned long long CAP_PEELOFF;
static const unsigned long long CAP_PREAD;
static const unsigned long long CAP_PWRITE;
static const unsigned long long CAP_READ;
static const unsigned long long CAP_RECV;
static const unsigned long long CAP_RENAMEAT;
static const unsigned long long CAP_SEEK;
static const unsigned long long CAP_SEM_GETVALUE;
static const unsigned long long CAP_SEM_POST;
static const unsigned long long CAP_SEM_WAIT;
static const unsigned long long CAP_SEND;
static const unsigned long long CAP_SETSOCKOPT;
static const unsigned long long CAP_SHUTDOWN;
static const unsigned long long CAP_SYMLINKAT;
static const unsigned long long CAP_TTYHOOK;
static const unsigned long long CAP_UNLINKAT;
static const unsigned long long CAP_WRITE;

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

''')

lib = ffi.verify('''
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/capability.h>

static const int _M_ENOTCAPABLE = ENOTCAPABLE;
static const int _M_ECAPMODE = ECAPMODE;
static const int _M_ENOTRECOVERABLE = ENOTRECOVERABLE;
static const int _M_EOWNERDEAD = EOWNERDEAD;

static const int _M_CAP_RIGHTS_VERSION = CAP_RIGHTS_VERSION;

''', ext_package='spyce')

ENOTCAPABLE = lib._M_ENOTCAPABLE
ECAPMODE = lib._M_ECAPMODE
ENOTRECOVERABLE = lib._M_ENOTRECOVERABLE
EOWNERDEAD = lib._M_EOWNERDEAD

extended_errorcode = errno.errorcode.copy()
extended_errorcode[ENOTCAPABLE] = 'ENOTCAPABLE'
extended_errorcode[ECAPMODE] = 'ECAPMODE'
extended_errorcode[ENOTRECOVERABLE] = 'ENOTRECOVERABLE'
extended_errorcode[EOWNERDEAD] = 'EOWNERDEAD'


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
    if lib.cap_getmode(in_cap_mode) < 0:
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
    lib.__cap_rights_init(lib._M_CAP_RIGHTS_VERSION,
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
