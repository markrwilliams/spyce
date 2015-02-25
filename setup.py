if __name__ == '__main__':
    from setuptools import setup, find_packages
    from spyce._wrapper import ffi

    setup(name='spyce',
          version='0.0.0',
          zip_safe=False,
          packages=find_packages(),
          ext_package='spyce',
          ext_modules=[ffi.verifier.get_extension()])
