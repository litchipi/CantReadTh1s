#!/usr/bin/env python3

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
     name='cantreadth1s',
     version='0.2',
     author="Litchi Pi",
     author_email="litchi.pi@protonmail.com",
     description="A simple tool to store securely files, in CLI or inside a script",
     long_description=long_description,
     long_description_content_type="text/markdown",
     url="https://github.com/litchipi/CantReadTh1s",
     packages=['cantreadth1s'],
     license="GPLv3",
     classifiers=[
         "Programming Language :: Python :: 3",
     ],
 )
