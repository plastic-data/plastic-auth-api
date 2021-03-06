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


"""Environment configuration"""


import logging
import os
import sys

from biryani1 import strings
import pymongo

import plastic_auth_api
from . import contexts, conv, model


app_dir = os.path.dirname(os.path.abspath(__file__))


def load_environment(global_conf, app_conf):
    """Configure the application environment."""
    conf = plastic_auth_api.conf  # Empty dictionary
    conf.update(strings.deep_decode(global_conf))
    conf.update(strings.deep_decode(app_conf))
    conf.update(conv.check(conv.struct(
        {
            'app_conf': conv.set_value(app_conf),
            'app_dir': conv.set_value(app_dir),
            'cache_dir': conv.default(os.path.join(os.path.dirname(app_dir), 'cache')),
            'database': conv.default('plastic_auth_api'),
            'debug': conv.pipe(conv.guess_bool, conv.default(False)),
            'global_conf': conv.set_value(global_conf),
            'i18n_dir': conv.default(os.path.join(app_dir, 'i18n')),
            'log_level': conv.pipe(
                conv.default('WARNING'),
                conv.function(lambda log_level: getattr(logging, log_level.upper())),
                ),
            'mongodb_address': conv.default('localhost'),
            'mongodb_port': conv.pipe(
                conv.input_to_int,
                conv.default(27017),
                ),
            'package_name': conv.default(u'plastic-auth-api'),
            'realm': conv.default(u'Plastic-Auth API'),
            'plastic_auth_ui.name': conv.default(u'Plastic-Auth-UI'),
            'zmq_push_socket': conv.not_none,
            'zmq_sub_socket': conv.not_none,
            },
        default = 'drop',
        ))(conf))

    # Configure logging.
    logging.basicConfig(level = conf['log_level'], stream = sys.stderr)

    errorware = conf.setdefault('errorware', {})
    errorware['debug'] = conf['debug']
    if not errorware['debug']:
        errorware['error_email'] = conf['email_to']
        errorware['error_log'] = conf.get('error_log', None)
        errorware['error_message'] = conf.get('error_message', 'An internal server error occurred')
        errorware['error_subject_prefix'] = conf.get('error_subject_prefix', 'Plastic-Auth Web API Error: ')
        errorware['from_address'] = conf['from_address']
        errorware['smtp_server'] = conf.get('smtp_server', 'localhost')

    components = dict(
        conf = conf,
        contexts = contexts,
        conv = conv,
        db = pymongo.Connection(conf['mongodb_address'], conf['mongodb_port'])[conf['database']],
        model = model,
        )
    model.init(components)


def setup_environment(drop_indexes = False):
    """Setup the application environment (after it has been loaded)."""

    # Setup MongoDB database.
    model.setup(drop_indexes = drop_indexes)
