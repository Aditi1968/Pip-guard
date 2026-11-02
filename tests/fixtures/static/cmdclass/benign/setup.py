from setuptools import setup
from setuptools.command.build_ext import build_ext


class BuildExt(build_ext):
    def run(self):
        build_ext.run(self)


setup(name="demo", version="1.0", cmdclass={})
