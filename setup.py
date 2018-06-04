#!/usr/bin/env python
import os
import sys
from setuptools import setup, find_packages
from pkg_resources import resource_filename

# depending on your execution context the version file
# may be located in a different place!
vsn_path = resource_filename(__name__, 'hvac/version')
if not os.path.exists(vsn_path):
    vsn_path = resource_filename(__name__, 'version')
    if not os.path.exists(vsn_path):
        print("%s is missing" % vsn_path)
        sys.exit(1)

setup(
    name='async-hvac',
    version=open(vsn_path, 'r').read(),
    description='HashiCorp Vault API client',
    author='Lionel Zerbib',
    author_email='lionel@alooma.io',
    url='https://github.com/Aloomaio/async-hvac',
    keywords=['hashicorp', 'vault'],
    classifiers=['License :: OSI Approved :: Apache Software License'],
    packages=find_packages(),
    install_requires=[
        'aiohttp==3.2.0',
    ],
    include_package_data=True,
    package_data={'hvac':['version']},
    extras_require={
        'parser': ['pyhcl>=0.2.1,<0.3.0']
    }
)
