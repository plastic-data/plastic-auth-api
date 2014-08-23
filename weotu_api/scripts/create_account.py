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


"""Create a user account."""


import argparse
import datetime
import hashlib
import logging
import os
import sys
import uuid

import paste.deploy

from weotu_api import contexts, conv, environment, model


app_name = os.path.splitext(os.path.basename(__file__))[0]
log = logging.getLogger(app_name)


def main():
    parser = argparse.ArgumentParser(description = __doc__)
    parser.add_argument('config', help = "path of Weotu-API configuration file")
    parser.add_argument('-b', '--block', action = 'store_true', default = False, help = "block account")
    parser.add_argument('-e', '--email', help = "account email")
    parser.add_argument('-f', '--full-name', help = "account full name")
#    parser.add_argument('-g', '--group', action = 'append', help = "title or id of group")
    parser.add_argument('-o', '--email-verified', action = 'store_true',
        default = False, help = "Mark email as valid (verified)")
    parser.add_argument('-p', '--password', help = "account password", required = True)
    parser.add_argument('-s', '--section', default = 'main',
        help = "Name of configuration section in configuration file")
    parser.add_argument('-v', '--verbose', action = 'store_true', default = False, help = "increase output verbosity")
    args = parser.parse_args()
    logging.basicConfig(level = logging.DEBUG if args.verbose else logging.WARNING, stream = sys.stdout)
    site_conf = paste.deploy.appconfig('config:{0}#{1}'.format(os.path.abspath(args.config), args.section))
    environment.load_environment(site_conf.global_conf, site_conf.local_conf)

    ctx = contexts.null_ctx
    email = conv.check(conv.input_to_email)(args.email, state = ctx)
    full_name = conv.check(conv.cleanup_line)(args.full_name, state = ctx)
#    groups = conv.check(conv.pipe(
#        conv.uniform_sequence(
#            conv.pipe(
#                conv.cleanup_line,
#                model.Group.str_to_instance,
#                ),
#            drop_none_items = True,
#            ),
#        conv.empty_to_none,
#        ))(args.group, state = ctx)
    password = conv.check(conv.pipe(
        conv.cleanup_line,
        conv.not_none,
        ))(args.password, state = ctx)
    url_name = conv.check(conv.input_to_url_name)(full_name, state = ctx)
    assert email is not None or url_name is not None, 'An account must have an email and/or a full name'
    if email is not None:
        existing_account = model.Account.find_one(dict(email = email))
        assert existing_account is None, u'An account with email "{}" already exists'.format(email).encode('utf-8')
    if url_name is not None:
        existing_account = model.Account.find_one(dict(url_name = url_name))
        assert existing_account is None, u'An account with name "{}" already exists'.format(url_name).encode('utf-8')

    salt = conv.check(conv.make_bytes_to_base64url(remove_padding = True))(uuid.uuid4().bytes,
        state = ctx)
    hash_object = hashlib.sha256(salt.encode('utf-8'))
    hash_object.update(password.encode('utf-8'))
    account = model.Account(
        blocked = args.block,
        email = email,
        email_verified = datetime.datetime.utcnow() if email is not None and args.email_verified else None,
        full_name = full_name,
#        groups_id = [
#            group._id
#            for group in groups
#            ] if groups is not None else None,
        password_hexdigest = hash_object.hexdigest(),
        salt = salt,
        url_name = url_name,
        )
    account.compute_attributes()
    account.save(ctx, safe = True)

    access = model.Access(
        account_id = account._id,
        client_id = None,  # => client = Weotu-API
        token = unicode(uuid.uuid4()),
        )
    access.save(ctx, safe = True)
    print u'Account {0} main access token: {1}'.format(account.email, access.token).encode('utf-8')
    return 0


if __name__ == "__main__":
    sys.exit(main())
