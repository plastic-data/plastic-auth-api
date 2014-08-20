#! /usr/bin/env python
# -*- coding: utf-8 -*-


# Weotu -- Accounts & authentication API
# By: Emmanuel Raviart <emmanuel@raviart.com>
#
# Copyright (C) 2014 Emmanuel Raviart
# https://gitorious.org/weotu
#
# This file is part of Weotu.
#
# Weotu is free software; you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# Weotu is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


"""Remove token from clients and create an access with this token for this client."""


import argparse
import collections
import logging
import os
import sys

import paste.deploy

from weotu_api import contexts, environment, model


app_name = os.path.splitext(os.path.basename(__file__))[0]
log = logging.getLogger(app_name)


def main():
    parser = argparse.ArgumentParser(description = __doc__)
    parser.add_argument('config', help = "CKAN-of-Worms configuration file")
    parser.add_argument('-s', '--section', default = 'main',
        help = "Name of configuration section in configuration file")
    parser.add_argument('-v', '--verbose', action = 'store_true', default = False, help = "increase output verbosity")
    args = parser.parse_args()
    logging.basicConfig(level = logging.DEBUG if args.verbose else logging.WARNING, stream = sys.stdout)
    site_conf = paste.deploy.appconfig('config:{0}#{1}'.format(os.path.abspath(args.config), args.section))
    environment.load_environment(site_conf.global_conf, site_conf.local_conf)

    status = model.Status.find_one()
    if status is None:
        status = model.Status()
    upgrade(status)

    return 0


def upgrade(status):
    ctx = contexts.null_ctx

    for index_name in ('token_1',):
        if index_name in model.Client.index_information():
            model.Client.drop_index(index_name)

    for client in model.Client.find(dict(token = {'$exists': True}), as_class = collections.OrderedDict):
        access = model.Access.find_one(dict(token = client.token), as_class = collections.OrderedDict)
        if access is None:
            access = model.Access(
                client_id = client._id,
                token = client.token,
                )
            access.save(ctx, safe = True)
        else:
            assert access.client_id == client._id

        del client.token
        client.compute_attributes()
        client.save(ctx, safe = True)
        log.info(u'Extracted access from client {0} ({1}). Access token: {2}'.format(client.name, client.symbol,
            access.token))

    if status.last_upgrade_name is None or status.last_upgrade_name < app_name:
        status.last_upgrade_name = app_name
        status.save()


if __name__ == "__main__":
    sys.exit(main())

