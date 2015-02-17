if __name__ == '__main__':
    from setuptools import setup
    from capysicum._wrapper import ffi

    setup(name='capysicum',
          version='0.0.0',
          zip_safe=False,
          ext_package='capysicum',
          ext_modules=[ffi.verifier.get_extension()])
