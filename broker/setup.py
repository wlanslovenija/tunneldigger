#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os

from setuptools import find_packages, setup

VERSION = '0.2.0'

setup(
    name='tunneldigger-broker',
    version=VERSION,
    description="Tunneldigger broker.",
    long_description=open(os.path.join(os.path.dirname(__file__), '..', 'README.rst')).read(),
    author='wlan slovenija',
    author_email='open@wlan-si.net',
    url='https://github.com/wlanslovenija/tunneldigger',
    license='AGPLv3',
    packages=find_packages(exclude=('*.tests', '*.tests.*', 'tests.*', 'tests')),
    package_data={},
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Programming Language :: Python',
    ],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'netfilter>=0.6.2',
        'six>=1.10.0',
    ],
    extras_require={},
)
