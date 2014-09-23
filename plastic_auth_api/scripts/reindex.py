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


"""Reindex objects."""


import argparse
import collections
import logging
import os
import sys

import paste.deploy

from plastic_auth_api import contexts, environment, model


app_name = os.path.splitext(os.path.basename(__file__))[0]
log = logging.getLogger(app_name)


def main():
    parser = argparse.ArgumentParser(description = __doc__)
    parser.add_argument('config', help = "CKAN-of-Worms configuration file")
    parser.add_argument('-a', '--all', action = 'store_true', default = False, help = "reindex everything")
    parser.add_argument('-c', '--client', action = 'store_true', default = False, help = "reindex clients")
    parser.add_argument('-s', '--section', default = 'main',
        help = "Name of configuration section in configuration file")
    parser.add_argument('-u', '--user', action = 'store_true', default = False, help = "reindex accounts")
    parser.add_argument('-v', '--verbose', action = 'store_true', default = False, help = "increase output verbosity")
    args = parser.parse_args()
    logging.basicConfig(level = logging.DEBUG if args.verbose else logging.WARNING, stream = sys.stdout)
    site_conf = paste.deploy.appconfig('config:{0}#{1}'.format(os.path.abspath(args.config), args.section))
    environment.load_environment(site_conf.global_conf, site_conf.local_conf)

    ctx = contexts.null_ctx

    if args.all or args.client:
        for client in model.Client.find(as_class = collections.OrderedDict):
            client.compute_attributes()
            if client.save(ctx, safe = False):
                log.info(u'Updated client: {} - {}'.format(client._id, client.name))

    if args.all or args.user:
        for account in model.Account.find(as_class = collections.OrderedDict):
            account.compute_attributes()
            if account.save(ctx, safe = False):
                log.info(u'Updated account: {} - {} <{}>'.format(account._id, account.full_name, account.email))

    return 0


if __name__ == "__main__":
    sys.exit(main())
