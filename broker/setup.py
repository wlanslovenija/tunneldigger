#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import find_packages, setup

VERSION = '0.4.0'

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
    packages=find_packages(where='src'),
    package_data={},
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU Affero General Public License v3',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3 :: Only',
    ],
    include_package_data=True,
    zip_safe=False,
    extras_require={},
)
