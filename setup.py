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
desc = "Python CFFI bindings for FreeBSD's Capsicum sandboxing framework."

if __name__ == '__main__':
    from setuptools import setup, find_packages

    setup(name='spyce',
          description=desc,
          long_description=__doc__,
          author=__author__,
          author_email=__contact__,
          zip_safe=False,
          packages=find_packages(),
          setup_requires=['vcversioner', 'cffi>=1.0.1'],
          cffi_modules=['spyce/_binding_build.py:ffi'],
          install_requires=['cffi>=1.0.1'],
          include_package_data=True,
          vcversioner={})
