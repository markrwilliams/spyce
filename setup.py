"""
    Spyce
    ~~~~~~~

    CFFI bindings for FreeBSD's Capsicum sandboxing framework.


    :copyright: (c) 2015 by Mark Williams
    :license: BSD, see LICENSE for more details.

"""

__author__ = 'Mark Williams'
__version__ = '0.0.1'
__contact__ = 'markrwilliams@gmail.com'
__url__ = 'https://github.com/markrwilliams/spyce'
__license__ = 'BSD'
desc = ('A functional Python web framework that streamlines'
        ' explicit development practices while eliminating'
        ' global state.')


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
          setup_requires=['vcversioner'],
          vcversioner={
              'version_module_paths': ['spyce/_version.py']
          },
          ext_package='spyce',
          ext_modules=[ffi.verifier.get_extension()])
