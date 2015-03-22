"""
    Spyce
    ~~~~~~~

    Python CFFI bindings for FreeBSD's Capsicum sandboxing framework.


    :copyright: (c) 2015 by Mark Williams
    :license: BSD, see LICENSE for more details.

"""

__author__ = 'Mark Williams'
__contact__ = 'markrwilliams@gmail.com'
__url__ = 'https://github.com/markrwilliams/spyce'
__license__ = 'BSD'
desc = ('A functional Python web framework that streamlines'
        ' explicit development practices while eliminating'
        ' global state.')

try:
    import vcversioner
    __version__ = vcversioner.find_version().version
except:
    import traceback
    traceback.print_exc()

    __version__ = '0.0.0'



if __name__ == '__main__':
    from setuptools import setup, find_packages
    from spyce._wrapper import ffi

    setup(name='spyce',
          version=__version__,
          description=desc,
          long_description=__doc__,
          author=__author__,
          author_email=__contact__,
          zip_safe=False,
          packages=find_packages(),
          ext_package='spyce',
          ext_modules=[ffi.verifier.get_extension()])
