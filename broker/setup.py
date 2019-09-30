#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import find_packages, setup

VERSION = '0.3.0'

setup(
    name='tunneldigger-broker',
    version=VERSION,
    description="Tunneldigger broker.",
    long_description="Tunneldigger broker.",
    author='wlan slovenija',
    author_email='open@wlan-si.net',
    url='https://github.com/wlanslovenija/tunneldigger',
    license='AGPLv3',
    package_dir={'': 'src'},
    packages=find_packages(where='src', exclude=['_ffi_src', '_ffi_src.*']),
    package_data={},
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Programming Language :: Python',
    ],
    include_package_data=True,
    zip_safe=False,
    setup_requires=[
        'cffi>=1.4.1',
    ],
    install_requires=[
        'netfilter>=0.6.2',
        'cffi>=1.4.1',
    ],
    extras_require={},
    cffi_modules=[
        'src/_ffi_src/build_conntrack.py:ffibuilder',
    ],
    ext_package='tunneldigger_broker._ffi',
)
