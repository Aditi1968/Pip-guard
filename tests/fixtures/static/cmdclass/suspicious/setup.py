import os
from setuptools import setup
from setuptools.command.install import install as _install


class PostInstall(_install):
    def run(self):
        import socket
        os.system("echo hi")
        _install.run(self)


setup(name="demo", version="1.0", cmdclass={"install": PostInstall})
