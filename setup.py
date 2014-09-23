#! /usr/bin/env python
# -*- coding: utf-8 -*-


# Plastic-Auth -- Accounts & authentication API
# By: Emmanuel Raviart <emmanuel@raviart.com>
#
# Copyright (C) 2014 Emmanuel Raviart
# https://github.com/plastic-data/plastic-auth-api
#
# This file is part of Plastic-Auth.
#
# Plastic-Auth is free software; you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# Plastic-Auth is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


"""Web API for Plastic-Auth -- Accounts & authentication API"""


from setuptools import setup, find_packages


classifiers = """\
Development Status :: 2 - Pre-Alpha
Environment :: Web Environment
License :: OSI Approved :: GNU Affero General Public License v3
Operating System :: POSIX
Programming Language :: Python
Topic :: Scientific/Engineering :: Information Analysis
Topic :: Internet :: WWW/HTTP :: WSGI :: Server
"""

doc_lines = __doc__.split('\n')


setup(
    name = 'Plastic-Auth-API',
    version = '0.1dev',

    author = 'Emmanuel Raviart',
    author_email = 'emmanuel@raviart.com',
    classifiers = [classifier for classifier in classifiers.split('\n') if classifier],
    description = doc_lines[0],
    keywords = 'api data personal server store web',
    license = 'http://www.fsf.org/licensing/licenses/agpl-3.0.html',
    long_description = '\n'.join(doc_lines[2:]),
    url = 'https://github.com/plastic-data/plastic-auth-api/plastic-auth-api',

    data_files = [
        ('share/locale/fr/LC_MESSAGES', ['plastic_auth_api/i18n/fr/LC_MESSAGES/plastic-auth-api.mo']),
        ],
    entry_points = {
        'paste.app_factory': 'main = plastic_auth_api.application:make_app',
        },
    include_package_data = True,
    install_requires = [
        'Babel >= 0.9.4',
        'Biryani1 >= 0.9dev',
#        'pymongo >= 2.2',
        'pyzmq >= 14.3',
        'Suq1 >= 0.1dev',
        'WebError >= 0.10',
        'WebOb >= 1.1',
        'ws4py >= 0.3.2',
        ],
    message_extractors = {'plastic_auth_api': [
        ('**.py', 'python', None),
        ]},
#    package_data = {'plastic_auth_api': ['i18n/*/LC_MESSAGES/*.mo']},
    packages = find_packages(),
    zip_safe = False,
    )
