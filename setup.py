if __name__ == '__main__':
    from setuptools import setup
    from spyce._wrapper import ffi

    setup(name='spyce',
          version='0.0.0',
          zip_safe=False,
          ext_package='spyce',
          ext_modules=[ffi.verifier.get_extension()])
