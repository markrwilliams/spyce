# spyce

## What it is

`spyce` provides Python bindings for FreeBSD's [Capsicum](http://www.cl.cam.ac.uk/research/security/capsicum/freebsd.html) sandboxing framework.

It uses [`cffi`](https://cffi.readthedocs.org/en/latest/), so it works with CPython 2 & 3 as well as PyPy.

### NB: This has only been tested against against FreeBSD 10.1-RELEASE

## What it does

`spyce` currently provides the following:

* [`cap_rights_limit(2)`/`cap_rights_get(3)`](https://www.freebsd.org/cgi/man.cgi?query=cap_rights_limit&apropos=0&sektion=2&manpath=FreeBSD+10.1-RELEASE&arch=default&format=html), and all of [`rights(4)`](https://www.freebsd.org/cgi/man.cgi?query=cap_rights_limit&apropos=0&sektion=2&manpath=FreeBSD+10.1-RELEASE&arch=default&format=html):
````python
        from spyce import Rights, getFileRights, CAP_READ, CAP_SEEK
        with open('somefile', 'rb') as f:
            originalRights = getFileRights(f)
            assert originalRights & {CAP_READ, CAP_SEEK}
            Rights([CAP_READ, CAP_SEEK]).limitFile(f)
            # do some stuff!
````
* [`cap_fcntls_limit(2)`/`cap_fcntls_get(2)`](https://www.freebsd.org/cgi/man.cgi?query=cap_fcntls_limit&apropos=0&sektion=2&manpath=FreeBSD+10.1-RELEASE&arch=default&format=html):
````python
        from spyce import FcntlRights, getFileFcntlRights, CAP_FCNTL_GETFL
        with open('somefile', 'rb') as f:
            originalFcntlRights = getFileFcntlRights(f)
            assert CAP_FCNTL_GETFL in originalRights
            FcntlRights([CAP_FCNTL_GETFL]).limitFile(f)
            # do some stuff!
````
* [`cap_ioctls_limit(2)`/`cap_ioctls_get(2)`](https://www.freebsd.org/cgi/man.cgi?query=cap_ioctls_limit&apropos=0&sektion=2&manpath=FreeBSD+10.1-RELEASE&arch=default&format=html):
````python
        from spyce import IoctlRights, getFileIoctlRights, CAP_IOCTLS_ALL
        from termios import FIOCLEX
        with open('somefile', 'rb') as f:
            originalIoctlRights = getFileIoctlRights(f)
            assert originalIoctlRights.allIoctls
            IoctlRights([FIOCLEX]).limitFile(f)
            # do some stuff!
````

All `limitFile` methods work on objects with `.fileno()` methods or integers.

### Docs are coming soon!