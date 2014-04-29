#!/usr/bin/env python
from setuptools import setup


setup(
    name='xstream',
    version='0.0.1',
    packages=['xstream'],
    package_data={
        '': ['README.md'],
    },
    install_requires=['ssloop>=0.0.5'],
    author='snower',
    author_email='sujian199@gmail.com',
    url='http://github.com/snower/ssloop',
    license='MIT',
    description='xstream is a simple spdy  protocol',
    long_description='xstream is a simple spdy  protocol'
)
