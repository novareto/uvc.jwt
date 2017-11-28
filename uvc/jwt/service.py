# -*- coding: utf-8 -*-

import grok
import json
import uvcsite

from uvc.rest.service import Service
from uvc.rest.components import IRESTNode
from zope.interface import implementer
from zope.pluggableauth.interfaces import IAuthenticatorPlugin
from zope.component import getUtility
from zope.browser.interfaces import IView
from zope.publisher.interfaces import IPublishTraverse
from zope.publisher.interfaces.http import IHTTPPublisher
from zope.publisher.interfaces.browser import IBrowserPublisher

from .handler import JWTHandler
from . import IKey, IVault
from .utils import expiration_date, get_posix_timestamp


handler = JWTHandler()


@implementer(IBrowserPublisher, IRESTNode)
class Endpoint(object):

    def __init__(self, request, context):
        self.context = context
        self.request = request

    def browserDefault(self, request):
        return self, None

    def __resolve__(self, request):
        httpmethod = request.method.upper()
        method = getattr(self, httpmethod, None)
        if method is not None:
            return method
        raise NotImplementedError(
            "`%s` method has no bound resolver." % httpmethod)

    def __call__(self, request):
        method = self.__resolve__(request)
        return method()


class JWTAuth(Endpoint):

    def authenticate(self):
        self.request.response.setHeader('Access-Control-Allow-Origin', '*')
        principals = getUtility(IAuthenticatorPlugin, name='principals')
        principal = principals.authenticateCredentials(
            json.loads(self.request.bodyStream.stream.read()))
        return principal

    def POST(self):
        principal = self.authenticate()
        if principal is None:
            self.request.response.setStatus(403, "Login failed")
            return json.dumps({'error': 'Login failed.'})

        key = IKey(self.context).load()
        vault = IVault(self.context)
        payload = handler.create_payload(**{'userid': principal.id})
        token = handler.create_encrypted_signed_token(key, payload)
        expire = get_posix_timestamp(expiration_date(minutes=60))
        vault.store(payload['userid'], payload['uid'], expire)
        return json.dumps({'jwt': token.serialize()})


class JWTUser(Endpoint):

    def GET(self):
        self.request.response.setHeader('Access-Control-Allow-Origin', '*')
        return json.dumps({'data': {'name':'cklinger', 'pid': '0101010001'}})


class JWTRefresh(Endpoint):

    def POST(self):
        self.request.response.setHeader('Access-Control-Allow-Origin', '*')
        vault = IVault(self.context)
        key = IKey(self.context).load()
        new_date = expiration_date(minutes=1)
        try:
            to_refresh = self.request._auth[7:]
            data = json.loads(handler.decrypt_and_verify(key, to_refresh))
            new_ts = get_posix_timestamp(new_date)
            if vault.refresh(data['userid'], data['uid'], new_ts) is True:
                return json.dumps({
                    'message': ('Token refreshed with success. '
                                'New expiration date set to %s') % new_date})
            return json.dumps(
                {'error': u'The given token could not be refreshed'})
        except Exception as e:
            # be more specific
            return json.dumps(
                {'error': u'An error occured'})



class JWTLogout(Endpoint):

    def POST(self):
        self.request.response.setHeader('Access-Control-Allow-Origin', '*')
        return json.dumps({'status': 'success', 'message': 'Logout'})


class JSONService(Service):
    grok.name('json')

    endpoints = {
        'login': JWTAuth,
        'logout': JWTLogout,
        'auth': JWTAuth,
        'user': JWTUser,
        'refresh': JWTRefresh,
        }
    
    def publishTraverse(self, request, name):
        endpoint = self.endpoints.get(name, None)
        if endpoint is not None:
            return endpoint(self.request, self.context)
            
