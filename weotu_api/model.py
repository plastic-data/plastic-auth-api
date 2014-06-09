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


import collections
import hashlib

import zmq.green as zmq

from . import conf, conv, objects


zmq_context = zmq.Context()
zmq_sender = None


class Account(objects.Initable, objects.JsonMonoClassMapper, objects.Mapper, objects.ActivityStreamWrapper):
    access_tokens = None
#    admin = False
    blocked = False
    collection_name = 'accounts'
    email = None
    email_verified = False
    full_name = None
    password_hexdigest = None
    # Random string prepended to password before computing digest, to ensure that 2 users with the same password don't
    # have the same digest.
    salt = None
    url_name = None

    @classmethod
    def bson_to_json(cls, value, state = None):
        if value is None:
            return value, None
        value = value.copy()
#        value.pop('access_tokens', None)
        if value.get('draft_id') is not None:
            value['draft_id'] = unicode(value['draft_id'])
        id = value.pop('_id', None)
        if id is not None:
            value['id'] = unicode(id)
        return value, None

    def compute_url_name(self):
        url_name = conv.check(conv.input_to_url_name)(self.full_name)
        if url_name is None:
            if self.url_name is not None:
                del self.url_name
        else:
            self.url_name = url_name

    @classmethod
    def make_access_token_to_instance(cls):
        def access_token_to_instance(value, state = None):
            if value is None:
                return value, None
            if state is None:
                state = conv.default_state
            self = cls.find_one(
                dict(
                    access_tokens = value,
                    ),
                as_class = collections.OrderedDict,
                )
            if self is None:
                return value, state._(u"No account with given access token")
            return self, None

        return access_token_to_instance

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
                cls.make_str_to_instance(),
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

    @classmethod
    def make_str_to_instance(cls):
        def str_to_instance(value, state = None):
            if value is None:
                return value, None
            if state is None:
                state = conv.default_state
            id, error = conv.str_to_object_id(value, state = state)
            if id is not None and error is None:
                self = cls.find_one(id, as_class = collections.OrderedDict)
                if self is None:
                    return id, state._(u"No account with given ID")
            else:
                email, error = conv.str_to_email(value, state = state)
                if email is not None and error is None:
                    self = cls.find_one(dict(email = email), as_class = collections.OrderedDict)
                    if self is None:
                        return email, state._(u"No account with given email")
                else:
                    url_name, error = conv.input_to_url_name(value, state = state)
                    if url_name is None or error is not None:
                        return url_name, error
                    self = cls.find_one(dict(url_name = url_name), as_class = collections.OrderedDict)
                    if self is None:
                        return url_name, state._(u"No account with given name")
            return self, None

        return str_to_instance

    def turn_to_json_attributes(self, state):
        value, error = conv.object_to_clean_dict(self, state = state)
        if error is not None:
            return value, error
#        value.pop('access_tokens', None)
        if value.get('draft_id') is not None:
            value['draft_id'] = unicode(value['draft_id'])
        id = value.pop('_id', None)
        if id is not None:
            value['id'] = unicode(id)
        return value, None


class Client(objects.Initable, objects.JsonMonoClassMapper, objects.Mapper, objects.ActivityStreamWrapper):
    access_token = None
    blocked = False
    collection_name = 'clients'
    name = None
    password_hexdigest = None
    # Random string prepended to password before computing digest, to ensure that 2 users with the same password don't
    # have the same digest.
    salt = None
    owner_id = None
    url_name = None

    @classmethod
    def bson_to_json(cls, value, state = None):
        if value is None:
            return value, None
        value = value.copy()
        if value.get('draft_id') is not None:
            value['draft_id'] = unicode(value['draft_id'])
        id = value.pop('_id', None)
        if id is not None:
            value['id'] = unicode(id)
        value['owner_id'] = unicode(value['owner_id'])
        return value, None

    def compute_url_name(self):
        self.url_name = conv.check(conv.pipe(
            conv.input_to_url_name,
            conv.not_none,
            ))(self.name)

    @classmethod
    def make_access_token_to_instance(cls):
        def access_token_to_instance(value, state = None):
            if value is None:
                return value, None
            if state is None:
                state = conv.default_state
            self = cls.find_one(
                dict(
                    access_token = value,
                    ),
                as_class = collections.OrderedDict,
                )
            if self is None:
                return value, state._(u"No client with given access token")
            return self, None

        return access_token_to_instance

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
                cls.make_str_to_instance(),
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

    @classmethod
    def make_str_to_instance(cls):
        def str_to_instance(value, state = None):
            if value is None:
                return value, None
            if state is None:
                state = conv.default_state
            id, error = conv.str_to_object_id(value, state = state)
            if id is not None and error is None:
                self = cls.find_one(id, as_class = collections.OrderedDict)
                if self is None:
                    return id, state._(u"No client with given ID")
            else:
                url_name, error = conv.input_to_url_name(value, state = state)
                if url_name is None or error is not None:
                    return url_name, error
                self = cls.find_one(dict(url_name = url_name), as_class = collections.OrderedDict)
                if self is None:
                    return url_name, state._(u"No client with given name")
            return self, None

        return str_to_instance

    def turn_to_json_attributes(self, state):
        value, error = conv.object_to_clean_dict(self, state = state)
        if error is not None:
            return value, error
        if value.get('draft_id') is not None:
            value['draft_id'] = unicode(value['draft_id'])
        id = value.pop('_id', None)
        if id is not None:
            value['id'] = unicode(id)
        value['owner_id'] = unicode(value['owner_id'])
        return value, None


class Status(objects.Mapper, objects.Wrapper):
    collection_name = 'status'
    last_upgrade_name = None


def configure(ctx):
    pass


def init(db):
    objects.Wrapper.db = db

    global zmq_sender
    zmq_sender = zmq_context.socket(zmq.PUSH)
    zmq_sender.connect(conf['zmq_push_socket'])


def setup():
    """Setup MongoDb database."""
    import imp
    import os
    import uuid

    from . import conf, contexts, upgrades

    upgrades_dir = os.path.dirname(upgrades.__file__)
    upgrades_name = sorted(
        os.path.splitext(upgrade_filename)[0]
        for upgrade_filename in os.listdir(upgrades_dir)
        if upgrade_filename.endswith('.py') and upgrade_filename != '__init__.py'
        )
    status = Status.find_one(as_class = collections.OrderedDict)
    if status is None:
        status = Status()
        if upgrades_name:
            status.last_upgrade_name = upgrades_name[-1]
        status.save()
    else:
        for upgrade_name in upgrades_name:
            if status.last_upgrade_name is None or status.last_upgrade_name < upgrade_name:
                print 'Upgrading "{0}"'.format(upgrade_name)
                upgrade_file, upgrade_file_path, description = imp.find_module(upgrade_name, [upgrades_dir])
                try:
                    upgrade_module = imp.load_module(upgrade_name, upgrade_file, upgrade_file_path, description)
                finally:
                    if upgrade_file:
                        upgrade_file.close()
                upgrade_module.upgrade(status)

    Account.ensure_index('access_tokens', unique = True)
    Account.ensure_index('email', sparse = True, unique = True)
    Account.ensure_index('url_name', sparse = True, unique = True)

    Client.ensure_index('access_token', unique = True)
    Client.ensure_index('url_name', sparse = True, unique = True)
    Client.ensure_index('owner_id')