from setuptools import setup, find_packages
from libkeepass import version

setup(
    name='libkeepass',
    version=version.__version__,
    packages=find_packages(),
    author="Evan Widloski",
    author_email="evan@evanw.org",
    description="Low level library for parsing Keepass KDBX3 and KDBX4 databases",
    long_description=open('README.rst').read(),
    license="GPLv3",
    keywords="keepass pykeepass libkeepass",
    url="https://github.com/libkeepass/libkeepass_proto",
    install_requires=[
        "construct",
        "argon2_cffi",
        "pycryptodome",
        "lxml"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
    ]
)
