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


"""Root controllers"""


import calendar
import collections
import datetime
import hashlib
import json
import urlparse
import uuid

import webob
import webob.exc
import ws4py.server.wsgiutils
import ws4py.websocket
import zmq.green as zmq

from . import conf, contexts, conv, model, urls, wsgihelpers


N_ = lambda message: message
router = None


@wsgihelpers.wsgify
def api1_authenticate(req):
    ctx = contexts.Ctx(req)
    headers = wsgihelpers.handle_cross_origin_resource_sharing(ctx)

    assert req.method == 'POST', req.method

    inputs_converters = dict(
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
        )

    content_type = req.content_type
    if content_type is not None:
        content_type = content_type.split(';', 1)[0].strip()
    if content_type == 'application/json':
        inputs, error = conv.pipe(
            conv.make_input_to_json(),
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

    data, errors = conv.struct(inputs_converters)(inputs, state = ctx)
    if inputs.get('password'):
        # Replace password in inputs to ensure that it will not be sent back to caller.
        inputs['password'] = u'X' * len(inputs['password'])
    if errors is None:
        account = model.Account.find_one(dict(email = data['email']))
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
            elif not account.email_verified:
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

    issued_at_timestamp = calendar.timegm(datetime.datetime.utcnow().timetuple())
    expire_at_date_time = datetime.datetime.utcnow() + datetime.timedelta(seconds = 3600)  # TODO
    expire_at_timestamp = calendar.timegm(expire_at_date_time.timetuple())
    return wsgihelpers.respond_json(ctx,
        collections.OrderedDict(sorted(dict(
            access_info = collections.OrderedDict([
                # The content of the access token
                # TODO. Cf http://openid.net/specs/openid-connect-core-1_0.html#IDToken
                ('expire_at', expire_at_timestamp),
                ('issued_at', issued_at_timestamp),
                ]),
            apiVersion = '1.0',
            context = data['context'],
            id_info = collections.OrderedDict([
                # The content of the ID token
                ('email', account.email),
                ('email_verified', account.email_verified),
                ('expire_at', expire_at_timestamp),
                ('issued_at', issued_at_timestamp),
                ]),
            method = req.script_name,
#            nonce = TODO,
            params = inputs,
            url = req.url.decode('utf-8'),
            ).iteritems())),
        headers = headers,
        )


#@wsgihelpers.wsgify
#def api1_login(req):
#    ctx = contexts.Ctx(req)
#    headers = wsgihelpers.handle_cross_origin_resource_sharing(ctx)

#    assert req.method == 'GET', req.method
#    params = req.GET
#    inputs = dict(
#        context = params.get('context'),
#        )
#    data, errors = conv.struct(dict(
#        context = conv.noop,  # For asynchronous calls
#        ))(inputs, state = ctx)
#    if errors is not None:
#        return wsgihelpers.respond_json(ctx,
#            collections.OrderedDict(sorted(dict(
#                apiVersion = '1.0',
#                context = inputs.get('context'),
#                error = collections.OrderedDict(sorted(dict(
#                    code = 400,  # Bad Request
#                    errors = [errors],
#                    message = ctx._(u'Bad parameters in request'),
#                    ).iteritems())),
#                method = req.script_name,
#                params = inputs,
#                url = req.url.decode('utf-8'),
#                ).iteritems())),
#            headers = headers,
#            )

#    token = conv.check(conv.make_bytes_to_base64url(remove_padding = True))(uuid.uuid4().bytes, state = ctx)

#    return wsgihelpers.respond_json(ctx,
#        collections.OrderedDict(sorted(dict(
#            apiVersion = '1.0',
#            context = data['context'],
#            method = req.script_name,
#            params = inputs,
#            token = token,
#            url = req.url.decode('utf-8'),
#            ).iteritems())),
#        headers = headers,
#        )


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
                conv.test(lambda email: \
                    model.Account.get_collection().find_one(dict(email = email), []) is None,
                    error = N_(u"An account with the same email already exists")),
                ),
            email_verified = conv.pipe(
                conv.test_isinstance((bool, int)),
                conv.anything_to_bool,
                conv.default(False),
                ),
            full_name = conv.pipe(
                conv.test_isinstance(basestring),
                conv.cleanup_line,
                conv.test_conv(conv.pipe(
                    conv.input_to_url_name,
                    conv.test(lambda url_name: \
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
    if errors is None:
        if data['email'] is None and data['full_name'] is None:
            errors = dict(email = state._(u"An account must have either an email or a full name"))
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
    account.compute_url_name()
    changed = account.save(ctx, safe = True)

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


@wsgihelpers.wsgify
def api1_new_client(req):
    ctx = contexts.Ctx(req)
    headers = wsgihelpers.handle_cross_origin_resource_sharing(ctx)

    assert req.method == 'POST', req.method

    account = handle_account_authorization_header(ctx, headers)

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
            access_token = conv.pipe(
                conv.test_isinstance(basestring),
                conv.input_to_uuid,
                ),
            blocked = conv.pipe(
                conv.test_isinstance((bool, int)),
                conv.anything_to_bool,
                conv.default(False),
                ),
            context = conv.test_isinstance(basestring),  # For asynchronous calls
            name = conv.pipe(
                conv.test_isinstance(basestring),
                conv.cleanup_line,
                conv.test_conv(conv.pipe(
                    conv.input_to_url_name,
                    conv.test(lambda url_name: \
                        model.Client.get_collection().find_one(dict(url_name = url_name), []) is None,
                        error = N_(u"A client with the same name already exists")),
                    )),
                conv.not_none,
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

    account = handle_account_data_access_token(ctx, headers, account, data)

    access_token = unicode(uuid.uuid4())
    salt = conv.check(conv.make_bytes_to_base64url(remove_padding = True))(uuid.uuid4().bytes, state = ctx)
    hash_object = hashlib.sha256(salt.encode('utf-8'))
    hash_object.update(data['password'].encode('utf-8'))
    client = model.Client(
        access_token = access_token,
        blocked = data['blocked'],
        name = data['name'],
        owner_id = account._id,
        password_hexdigest = hash_object.hexdigest(),
        salt = salt,
        )
    client.compute_url_name()
    changed = client.save(ctx, safe = True)

    client_json = client.to_json()
    if changed:
        model.zmq_sender.send_multipart([
            'v1/new_client/',
            unicode(json.dumps(client_json, encoding = 'utf-8', ensure_ascii = False, indent = 2)).encode('utf-8'),
            ])
    return wsgihelpers.respond_json(ctx,
        collections.OrderedDict(sorted(dict(
            apiVersion = '1.0',
            client = client_json,
            context = data['context'],
            method = req.script_name,
            params = inputs,
            url = req.url.decode('utf-8'),
            ).iteritems())),
        headers = headers,
        )


def handle_account_authorization_header(ctx, headers, required = False):
    account = None
    req = ctx.req
    authorization = req.authorization
    if authorization is None:
        if required:
            raise wsgihelpers.respond_json(ctx,
                collections.OrderedDict(sorted(dict(
                    apiVersion = '1.0',
                    error = collections.OrderedDict(sorted(dict(
                        code = 401,  # Unauthorized
                        message = ctx._(u'Missing authorization header'),
                        ).iteritems())),
                    method = req.script_name,
                    url = req.url.decode('utf-8'),
                    ).iteritems())),
                headers = headers,
                )
    elif authorization[0].lower() == 'basic':
        account, error = conv.pipe(
            model.Account.make_basic_authorization_to_instance(),
            conv.not_none,
            )(authorization[1], state = ctx)
        if error is not None:
            raise wsgihelpers.respond_json(ctx,
                collections.OrderedDict(sorted(dict(
                    apiVersion = '1.0',
                    error = collections.OrderedDict(sorted(dict(
                        code = 401,  # Unauthorized
                        message = ctx._(u'Basic authentication error: {}').format(error),
                        ).iteritems())),
                    method = req.script_name,
                    url = req.url.decode('utf-8'),
                    ).iteritems())),
                headers = headers,
                )
    elif authorization[0].lower() == 'bearer':
        account, error = conv.pipe(
            conv.input_to_uuid,
            model.Account.make_access_token_to_instance(),
            conv.not_none,
            )(authorization[1], state = ctx)
        if error is not None:
            raise wsgihelpers.respond_json(ctx,
                collections.OrderedDict(sorted(dict(
                    apiVersion = '1.0',
                    error = collections.OrderedDict(sorted(dict(
                        code = 401,  # Unauthorized
                        message = ctx._(u'Bearer authentication error: {}').format(error),
                        ).iteritems())),
                    method = req.script_name,
                    url = req.url.decode('utf-8'),
                    ).iteritems())),
                headers = headers,
                )
    else:
        raise wsgihelpers.respond_json(ctx,
            collections.OrderedDict(sorted(dict(
                apiVersion = '1.0',
                error = collections.OrderedDict(sorted(dict(
                    code = 401,  # Unauthorized
                    message = ctx._(u'Unknown authorization error: {} {}').format(*authorization),
                    ).iteritems())),
                method = req.script_name,
                url = req.url.decode('utf-8'),
                ).iteritems())),
            headers = headers,
            )

    return account


def handle_account_data_access_token(ctx, headers, authorization_account, data):
    data_account, error = conv.pipe(
        conv.input_to_uuid,
        model.Account.make_access_token_to_instance(),
        conv.not_none if authorization_account is None else conv.test_none(
            error = N_(u"Authentication provided twice (in Authorization HTTP header and in POSTed data)")),
        )(data['access_token'], state = ctx)
    if error is not None:
        raise wsgihelpers.respond_json(ctx,
            collections.OrderedDict(sorted(dict(
                apiVersion = '1.0',
                context = inputs.get('context'),
                error = collections.OrderedDict(sorted(dict(
                    code = 401,  # Unauthorized
                    errors = [dict(access_token = error)],
                    message = ctx._(u'Authentication failed'),
                    ).iteritems())),
                method = req.script_name,
                params = inputs,
                url = req.url.decode('utf-8'),
                ).iteritems())),
            headers = headers,
            )
    return authorization_account or data_account


def handle_client_authorization_header(ctx, headers, required = False):
    client = None
    req = ctx.req
    authorization = req.authorization
    if authorization is None:
        if required:
            raise wsgihelpers.respond_json(ctx,
                collections.OrderedDict(sorted(dict(
                    apiVersion = '1.0',
                    error = collections.OrderedDict(sorted(dict(
                        code = 401,  # Unauthorized
                        message = ctx._(u'Missing authorization header'),
                        ).iteritems())),
                    method = req.script_name,
                    url = req.url.decode('utf-8'),
                    ).iteritems())),
                headers = headers,
                )
    elif authorization[0].lower() == 'basic':
        client, error = conv.pipe(
            model.Client.make_basic_authorization_to_instance(),
            conv.not_none,
            )(authorization[1], state = ctx)
        if error is not None:
            raise wsgihelpers.respond_json(ctx,
                collections.OrderedDict(sorted(dict(
                    apiVersion = '1.0',
                    error = collections.OrderedDict(sorted(dict(
                        code = 401,  # Unauthorized
                        message = ctx._(u'Basic authentication error: {}').format(error),
                        ).iteritems())),
                    method = req.script_name,
                    url = req.url.decode('utf-8'),
                    ).iteritems())),
                headers = headers,
                )
    elif authorization[0].lower() == 'bearer':
        client, error = conv.pipe(
            conv.input_to_uuid,
            model.Client.make_access_token_to_instance(),
            conv.not_none,
            )(authorization[1], state = ctx)
        if error is not None:
            raise wsgihelpers.respond_json(ctx,
                collections.OrderedDict(sorted(dict(
                    apiVersion = '1.0',
                    error = collections.OrderedDict(sorted(dict(
                        code = 401,  # Unauthorized
                        message = ctx._(u'Bearer authentication error: {}').format(error),
                        ).iteritems())),
                    method = req.script_name,
                    url = req.url.decode('utf-8'),
                    ).iteritems())),
                headers = headers,
                )
    else:
        raise wsgihelpers.respond_json(ctx,
            collections.OrderedDict(sorted(dict(
                apiVersion = '1.0',
                error = collections.OrderedDict(sorted(dict(
                    code = 401,  # Unauthorized
                    message = ctx._(u'Unknown authorization error: {} {}').format(*authorization),
                    ).iteritems())),
                method = req.script_name,
                url = req.url.decode('utf-8'),
                ).iteritems())),
            headers = headers,
            )

    return client


def handle_client_data_access_token(ctx, headers, authorization_client, data):
    data_client, error = conv.pipe(
        conv.input_to_uuid,
        model.Client.make_access_token_to_instance(),
        conv.not_none if authorization_client is None else conv.test_none(
            error = N_(u"Authentication provided twice (in Authorization HTTP header and in POSTed data)")),
        )(data['access_token'], state = ctx)
    if error is not None:
        raise wsgihelpers.respond_json(ctx,
            collections.OrderedDict(sorted(dict(
                apiVersion = '1.0',
                context = inputs.get('context'),
                error = collections.OrderedDict(sorted(dict(
                    code = 401,  # Unauthorized
                    errors = [dict(access_token = error)],
                    message = ctx._(u'Authentication failed'),
                    ).iteritems())),
                method = req.script_name,
                params = inputs,
                url = req.url.decode('utf-8'),
                ).iteritems())),
            headers = headers,
            )
    return authorization_client or data_client


def make_router():
    """Return a WSGI application that searches requests to controllers """
    global router
    router = urls.make_router(
        ('POST', '^/api/1/authenticate/?$', api1_authenticate),
        ('POST', '^/api/1/account/?$', api1_new_account),
        ('POST', '^/api/1/client/?$', api1_new_client),
#        ('GET', '^/api/1/login/?$', api1_login),
        ('GET', '^/ws/1/accounts/?$', ws1_accounts),
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

    try:
        client = handle_client_authorization_header(ctx, headers, required = True)
    except webob.exc.HTTPException as response:
        return response(environ, start_response)

    # TODO: Check client.

    try:
        return ws1_accounts_emitter_app(environ, start_response)
    except ws4py.server.wsgiutils.HandshakeError as error:
        return wsgihelpers.bad_request(ctx, explanation = ctx._(u'WebSocket Handshake Error: {0}').format(error))(
            environ, start_response)

class WS1AccountsEmitter(ws4py.websocket.WebSocket):
    def opened(self):
        zmq_subscriber = model.zmq_context.socket(zmq.SUB)
        zmq_subscriber.connect(conf['zmq_sub_socket'])
        zmq_subscriber.setsockopt(zmq.SUBSCRIBE, 'v1/delete_account/')
        zmq_subscriber.setsockopt(zmq.SUBSCRIBE, 'v1/new_account/')
        zmq_subscriber.setsockopt(zmq.SUBSCRIBE, 'v1/update_account/')

        # Now that 0MQ socket is open, first send existing accounts (while queueing 0MQ messages).
        for account in model.Account.find():
            if self.terminated:
                break
            self.send(' '.join([
                'v1/update_account/',
                unicode(json.dumps(account.to_json(), encoding = 'utf-8', ensure_ascii = False, indent = 2)).encode(
                    'utf-8'),
                ]))
        self.send(' '.join(['v1/end_existing_accounts/', 'null']))

        while not self.terminated:
            address, content = zmq_subscriber.recv_multipart()
            self.send(' '.join([address, content]))

ws1_accounts_emitter_app = ws4py.server.wsgiutils.WebSocketWSGIApplication(handler_cls = WS1AccountsEmitter)
