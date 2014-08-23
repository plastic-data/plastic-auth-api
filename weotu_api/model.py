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


"""The application's model objects"""


import hashlib

from suq1 import accesses, setups
import zmq.green as zmq

from . import conf, conv


zmq_context = zmq.Context()
zmq_sender = None


class Access(accesses.Access):
    pass


class Account(accesses.Account):
    admin = False
    password_hexdigest = None
    # Random string prepended to password before computing digest, to ensure that 2 users with the same password don't
    # have the same digest.
    salt = None

    @classmethod
    def ensure_indexes(cls):
        super(Account, cls).ensure_indexes()
        cls.ensure_index('admin', sparse = True)

    @classmethod
    def make_basic_authorization_to_instance(cls):
        def basic_authorization_to_instance(value, state = None):
            if value is None:
                return value, None
            if state is None:
                state = conv.default_state
            username_and_password, error = conv.pipe(
                conv.base64_to_bytes,
                conv.decode_str(encoding = 'utf-8'),
                conv.not_none,
                )(value, state = state)
            if error is not None:
                return username_and_password, error
            username_password_couple = username_and_password.split(u':', 1)
            if len(username_password_couple) < 2:
                return username_password_couple, state._(u"Missing username and/or password")
            self, error = conv.pipe(
                conv.cleanup_line,
                cls.str_to_instance,
                conv.not_none,
                )(username_password_couple[0], state = state)
            if error is not None:
                return self, error
            password, error = conv.pipe(
                conv.cleanup_line,
                conv.not_none,
                )(username_password_couple[1], state = state)
            if error is not None:
                return password, state._(u"Password error: {}").format(error)
            hash_object = hashlib.sha256(self.salt.encode('utf-8'))
            hash_object.update(password.encode('utf-8'))
            if self.password_hexdigest != hash_object.hexdigest():
                return self, state._(u"Wrong password")
            return self, None

        return basic_authorization_to_instance

    def turn_to_json_attributes(self, state):
        value, error = super(Account, self).turn_to_json_attributes(state)
        if error is not None:
            return value, error
        value.pop('password_hexdigest', None)
        value.pop('salt', None)
        return value, None


class Client(accesses.Client):
    can_authenticate = False  # Only clients managed by admins can authenticate users.


def configure(ctx):
    setups.configure(ctx)


def init(components):
    setups.init(components)

    global zmq_sender
    zmq_sender = zmq_context.socket(zmq.PUSH)
    zmq_sender.connect(conf['zmq_push_socket'])


def setup(drop_indexes = False):
    """Setup MongoDb database."""
    import os

    from . import conf, contexts, upgrades

    setups.setup(drop_indexes = drop_indexes, upgrades_dir = os.path.dirname(upgrades.__file__))

    Access.ensure_indexes()
    Account.ensure_indexes()
    Client.ensure_indexes()

    ctx = contexts.null_ctx

    # Upsert UI client.
    access = Client.upsert_with_access(ctx, conf['weotu_ui.name'], u'weotu-ui')
    print u'Client {0} ({1}). Access token: {2}'.format(access.client.name, access.client.symbol, access.token).encode(
        'utf-8')

