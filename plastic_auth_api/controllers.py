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


"""Root controllers"""


import calendar
import collections
import datetime
import hashlib
import logging
import json
import uuid

import bson
import pymongo
from suq1 import urls, wsgihelpers
from suq1.controllers import accesses
import webob
import webob.exc
import ws4py.server.wsgiutils
import ws4py.websocket
import zmq.green as zmq

from . import conf, contexts, conv, model


log = logging.getLogger(__name__)
N_ = lambda message: message
router = None


@wsgihelpers.wsgify
def api1_authenticate(req):
    ctx = contexts.Ctx(req)
    headers = wsgihelpers.handle_cross_origin_resource_sharing(ctx)

    assert req.method == 'POST', req.method

    content_type = req.content_type
    if content_type is not None:
        content_type = content_type.split(';', 1)[0].strip()
    if content_type == 'application/json':
        inputs, error = conv.pipe(
            conv.make_input_to_json(object_pairs_hook = collections.OrderedDict),
            conv.test_isinstance(dict),
            )(req.body, state = ctx)
        if error is not None:
            return wsgihelpers.respond_json(ctx,
                collections.OrderedDict(sorted(dict(
                    apiVersion = '1.0',
                    error = collections.OrderedDict(sorted(dict(
                        code = 400,  # Bad Request
                        errors = [error],
                        message = ctx._(u'Invalid JSON in request POST body'),
                        ).iteritems())),
                    method = req.script_name,
                    params = req.body,
                    url = req.url.decode('utf-8'),
                    ).iteritems())),
                headers = headers,
                )
    else:
        # URL-encoded POST.
        inputs = dict(req.POST)

    data, errors = conv.pipe(
        conv.struct(
            dict(
                access_token = conv.pipe(
                    conv.test_isinstance(basestring),
                    conv.input_to_uuid_str,
                    model.Access.make_token_to_instance(accept_client = True),
                    conv.not_none,
                    ),
                context = conv.test_isinstance(basestring),  # For asynchronous calls
                email = conv.pipe(
                    conv.test_isinstance(basestring),
                    conv.input_to_email,
                    conv.not_none,
                    ),
                password = conv.pipe(
                    conv.test_isinstance(basestring),
                    conv.cleanup_line,
                    conv.not_none,
                    ),
                relying_party_id = conv.pipe(
                    conv.test_isinstance(basestring),
                    conv.cleanup_line,
                    model.Client.str_to_instance,
                    conv.not_none,
                    ),
                state = conv.pipe(
                    conv.test_isinstance(basestring),
                    conv.input_to_uuid_str,
                    conv.not_none,
                    ),
                ),
            ),
        conv.rename_item('relying_party_id', 'relying_party'),
        )(inputs, state = ctx)
    if inputs.get('password'):
        # Replace password in inputs to ensure that it will not be sent back to caller.
        inputs['password'] = u'X' * len(inputs['password'])
    if errors is None:
        client = data['access_token'].client
        if not client.can_authenticate:
            return wsgihelpers.respond_json(ctx,
                collections.OrderedDict(sorted(dict(
                    apiVersion = '1.0',
                    context = inputs.get('context'),
                    error = collections.OrderedDict(sorted(dict(
                        code = 403,  # Forbidden
                        message = ctx._(u'Client is not allowed to request user authentication'),
                        ).iteritems())),
                    method = req.script_name,
                    params = inputs,
                    url = req.url.decode('utf-8'),
                    ).iteritems())),
                headers = headers,
                )

        account = model.Account.find_one(dict(email = data['email']), as_class = collections.OrderedDict)
        if account is None:
            errors = dict(
                email = ctx._(u"Unknown email"),
                )
        else:
            hash_object = hashlib.sha256(account.salt.encode('utf-8'))
            hash_object.update(data['password'].encode('utf-8'))
            if hash_object.hexdigest() != account.password_hexdigest:
                errors = dict(
                    password = ctx._('Incorrect password'),
                    )
            elif account.blocked:
                errors = dict(
                    email = ctx._(u"Account is blocked"),
                    )
            elif account.email_verified is None:
                errors = dict(
                    email = ctx._(u"Email has not been verified"),
                    )
    if errors is not None:
        return wsgihelpers.respond_json(ctx,
            collections.OrderedDict(sorted(dict(
                apiVersion = '1.0',
                context = inputs.get('context'),
                error = collections.OrderedDict(sorted(dict(
                    code = 400,  # Bad Request
                    errors = [errors],
                    message = ctx._(u'Bad parameters in request'),
                    ).iteritems())),
                method = req.script_name,
                params = inputs,
                url = req.url.decode('utf-8'),
                ).iteritems())),
            headers = headers,
            )

    access = model.Access.find_one(
        dict(
            account_id = account._id,
            client_id = None,
            ),
        as_class = collections.OrderedDict,
        sort = [('updated', pymongo.DESCENDING)],
        )
    if access is None:
        access = model.Access(
            account_id = account._id,
            client_id = None,  # => client = WeFaqIt-API
            token = unicode(uuid.uuid4()),
            )
        access.save(ctx, safe = True)

    authentication = collections.OrderedDict(
        (key, value)
        for key, value in (
            ('access_token', access.token),
            ('client_id', unicode(data['relying_party']._id)),
            ('email', account.email),
            ('email_verified', int(calendar.timegm(account.email_verified.timetuple()) * 1000)
                if account.email_verified is not None
                else None),
            ('full_name', account.full_name),
            ('issued', int(calendar.timegm(datetime.datetime.utcnow().timetuple()) * 1000)),
            ('state', data['state']),
            )
        if value is not None
        )
    model.zmq_sender.send_multipart([
        'v1/authenticated/',
        unicode(json.dumps(authentication, encoding = 'utf-8', ensure_ascii = False, indent = 2)).encode('utf-8'),
        ])

    return wsgihelpers.respond_json(ctx,
        collections.OrderedDict(sorted(dict(
            authentication = authentication,
            apiVersion = '1.0',
            context = data['context'],
            method = req.script_name,
            params = inputs,
            url = req.url.decode('utf-8'),
            ).iteritems())),
        headers = headers,
        )


@wsgihelpers.wsgify
def api1_new_account(req):
    ctx = contexts.Ctx(req)
    headers = wsgihelpers.handle_cross_origin_resource_sharing(ctx)

    assert req.method == 'POST', req.method

    content_type = req.content_type
    if content_type is not None:
        content_type = content_type.split(';', 1)[0].strip()
    if content_type != 'application/json':
        return wsgihelpers.respond_json(ctx,
            collections.OrderedDict(sorted(dict(
                apiVersion = '1.0',
                error = collections.OrderedDict(sorted(dict(
                    code = 400,  # Bad Request
                    message = ctx._(u'Bad content-type: {}').format(content_type),
                    ).iteritems())),
                method = req.script_name,
                url = req.url.decode('utf-8'),
                ).iteritems())),
            headers = headers,
            )

    inputs, error = conv.pipe(
        conv.make_input_to_json(object_pairs_hook = collections.OrderedDict),
        conv.test_isinstance(dict),
        conv.not_none,
        )(req.body, state = ctx)
    if error is not None:
        return wsgihelpers.respond_json(ctx,
            collections.OrderedDict(sorted(dict(
                apiVersion = '1.0',
                error = collections.OrderedDict(sorted(dict(
                    code = 400,  # Bad Request
                    errors = [error],
                    message = ctx._(u'Invalid JSON in request POST body'),
                    ).iteritems())),
                method = req.script_name,
                params = req.body,
                url = req.url.decode('utf-8'),
                ).iteritems())),
            headers = headers,
            )

    data, errors = conv.struct(
        dict(
            blocked = conv.pipe(
                conv.test_isinstance((bool, int)),
                conv.anything_to_bool,
                conv.default(False),
                ),
            context = conv.test_isinstance(basestring),  # For asynchronous calls
            email = conv.pipe(
                conv.test_isinstance(basestring),
                conv.input_to_email,
                conv.test(lambda email:
                    model.Account.get_collection().find_one(dict(email = email), []) is None,
                    error = N_(u"An account with the same email already exists")),
                conv.not_none,
                ),
            email_verified = conv.pipe(
                conv.test_isinstance((float, int)),
                conv.timestamp_to_datetime,
                ),
            full_name = conv.pipe(
                conv.test_isinstance(basestring),
                conv.cleanup_line,
                conv.test_conv(conv.pipe(
                    conv.input_to_url_name,
                    conv.test(lambda url_name:
                        model.Account.get_collection().find_one(dict(url_name = url_name), []) is None,
                        error = N_(u"An account with the same name already exists")),
                    )),
                ),
            password = conv.pipe(
                conv.test_isinstance(basestring),
                conv.cleanup_line,
                conv.not_none,
                ),
            ),
        )(inputs, state = ctx)
    if errors is not None:
        return wsgihelpers.respond_json(ctx,
            collections.OrderedDict(sorted(dict(
                apiVersion = '1.0',
                context = inputs.get('context'),
                error = collections.OrderedDict(sorted(dict(
                    code = 400,  # Bad Request
                    errors = [errors],
                    message = ctx._(u'Bad parameters in request'),
                    ).iteritems())),
                method = req.script_name,
                params = inputs,
                url = req.url.decode('utf-8'),
                ).iteritems())),
            headers = headers,
            )

    salt = conv.check(conv.make_bytes_to_base64url(remove_padding = True))(uuid.uuid4().bytes, state = ctx)
    hash_object = hashlib.sha256(salt.encode('utf-8'))
    hash_object.update(data['password'].encode('utf-8'))
    account = model.Account(
        blocked = data['blocked'],
        email = data['email'],
        email_verified = data['email'] and data['email_verified'],
        full_name = data['full_name'],
        password_hexdigest = hash_object.hexdigest(),
        salt = salt,
        )
    account.compute_attributes()
    changed = account.save(ctx, safe = True)

    access = model.Access(
        account_id = account._id,
        client_id = None,  # => client = Plastic-Auth-API
        token = unicode(uuid.uuid4()),
        )
    access_changed = access.save(ctx, safe = True)

    account_json = account.to_json()
    if changed:
        model.zmq_sender.send_multipart([
            'v1/new_account/',
            unicode(json.dumps(account_json, encoding = 'utf-8', ensure_ascii = False, indent = 2)).encode('utf-8'),
            ])
    return wsgihelpers.respond_json(ctx,
        collections.OrderedDict(sorted(dict(
            account = account_json,
            apiVersion = '1.0',
            context = data['context'],
            method = req.script_name,
            params = inputs,
            url = req.url.decode('utf-8'),
            ).iteritems())),
        headers = headers,
        )


def make_router():
    """Return a WSGI application that searches requests to controllers """
    global router
    router = urls.make_router(
        ('POST', '^/api/1/authenticate/?$', api1_authenticate),
        ('POST', '^/api/1/access/upsert/?$', accesses.api1_upsert_access),
        ('POST', '^/api/1/account/?$', api1_new_account),
        ('POST', '^/api/1/client/upsert/?$', accesses.api1_upsert_client),
#        ('GET', '^/api/1/login/?$', api1_login),
        (('GET', 'POST'), '^/ws/1/accounts/?$', ws1_accounts),
        (('GET', 'POST'), '^/ws/1/authentications/?$', accesses.ws1_authentications),
        )
    return router


def ws1_accounts(environ, start_response):
    req = webob.Request(environ)
    ctx = contexts.Ctx(req)
    try:
        headers = wsgihelpers.handle_cross_origin_resource_sharing(ctx)
    except webob.exc.HTTPException as response:
        return response(environ, start_response)

    assert req.method == 'GET', req.method

    content_type = req.content_type
    if content_type is not None:
        content_type = content_type.split(';', 1)[0].strip()
    if content_type == 'application/json':
        inputs, error = conv.pipe(
            conv.make_input_to_json(object_pairs_hook = collections.OrderedDict),
            conv.test_isinstance(dict),
            )(req.body, state = ctx)
        if error is not None:
            return wsgihelpers.respond_json(ctx,
                collections.OrderedDict(sorted(dict(
                    apiVersion = '1.0',
                    error = collections.OrderedDict(sorted(dict(
                        code = 400,  # Bad Request
                        errors = [error],
                        message = ctx._(u'Invalid JSON in request POST body'),
                        ).iteritems())),
                    method = req.script_name,
                    params = req.body,
                    url = req.url.decode('utf-8'),
                    ).iteritems())),
                headers = headers,
                )(environ, start_response)
    else:
        # URL-encoded GET or POST.
        inputs = dict(req.params)

    data, errors = conv.struct(
        dict(
            access_token = conv.pipe(
                conv.test_isinstance(basestring),
                conv.input_to_uuid_str,
                model.Access.make_token_to_instance(accept_client = True),
                conv.not_none,
                ),
            ),
        )(inputs, state = ctx)
    if errors is not None:
        return wsgihelpers.respond_json(ctx,
            collections.OrderedDict(sorted(dict(
                apiVersion = '1.0',
                context = inputs.get('context'),
                error = collections.OrderedDict(sorted(dict(
                    code = 400,  # Bad Request
                    errors = [errors],
                    message = ctx._(u'Bad parameters in request'),
                    ).iteritems())),
                method = req.script_name,
                params = inputs,
                url = req.url.decode('utf-8'),
                ).iteritems())),
            headers = headers,
            )(environ, start_response)

    # TODO: Check that client can receive accounts.
    client = data['access_token'].client

    ws1_accounts_emitter_app = ws4py.server.wsgiutils.WebSocketWSGIApplication(
        handler_cls = type(
            'WS1AccountsEmitter{}'.format(client._id),
            (WS1AccountsEmitter,),
            dict(
                client_id = client._id,
                ctx = ctx,
                ),
            ),
        )
    try:
        return ws1_accounts_emitter_app(environ, start_response)
    except ws4py.server.wsgiutils.HandshakeError as error:
        return wsgihelpers.bad_request(ctx, explanation = ctx._(u'WebSocket Handshake Error: {0}').format(error))(
            environ, start_response)


class WS1AccountsEmitter(ws4py.websocket.WebSocket):
    client_id = None
    ctx = None

    def opened(self):
        zmq_subscriber = model.zmq_context.socket(zmq.SUB)
        zmq_subscriber.connect(conf['zmq_sub_socket'])
        zmq_subscriber.setsockopt(zmq.SUBSCRIBE, 'v1/delete_account/')
        zmq_subscriber.setsockopt(zmq.SUBSCRIBE, 'v1/new_account/')
        zmq_subscriber.setsockopt(zmq.SUBSCRIBE, 'v1/update_account/')

        # Now that 0MQ socket is open, first send existing accounts (while queueing 0MQ messages).
        for account in model.Account.find(as_class = collections.OrderedDict):
            if self.terminated:
                break
            access = model.Access.find_one(
                dict(
                    account_id = account._id,
                    client_id = self.client_id,
                    ),
                as_class = collections.OrderedDict,
                sort = [('updated', pymongo.DESCENDING)],
                )
            if access is None:
                access = model.Access(
                    account_id = account._id,
                    client_id = self.client_id,
                    token = unicode(uuid.uuid4()),
                    )
                access.save(self.ctx, safe = True)
            account_json = account.to_json()
            account_json['access_token'] = access.token
            self.send(' '.join([
                'v1/update_account/',
                unicode(json.dumps(account_json, encoding = 'utf-8', ensure_ascii = False, indent = 2)).encode('utf-8'),
                ]))
        self.send(' '.join(['v1/end_existing_accounts/', 'null']))

        while not self.terminated:
            address, content = zmq_subscriber.recv_multipart()
            account_json = json.loads(content)
            account_id = bson.objectid.ObjectId(account_json['id'])
            access = model.Access.find_one(
                dict(
                    account_id = account_id,
                    client_id = self.client_id,
                    ),
                as_class = collections.OrderedDict,
                sort = [('updated', pymongo.DESCENDING)],
                )
            if access is None and address != 'v1/delete_account/':
                access = model.Access(
                    account_id = account_id,
                    client_id = self.client_id,
                    token = unicode(uuid.uuid4()),
                    )
                access.save(self.ctx, safe = True)
            if access is not None:
                account_json['access_token'] = access.token
                content = unicode(json.dumps(account_json, encoding = 'utf-8', ensure_ascii = False,
                    indent = 2)).encode('utf-8')
            self.send(' '.join([address, content]))

