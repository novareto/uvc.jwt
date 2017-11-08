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

    def publish(self, request):
        method = self.__resolve__(request)
        return method()


class JWTAuth(Endpoint):

    def authenticate(self):
        principals = getUtility(IAuthenticatorPlugin, name='principals')
        principal = principals.authenticateCredentials(json.loads(self.request.bodyStream.stream.read()))
        return principal

    def POST(self):
        principal = self.authenticate()
        if principal is None:
            return json.dumps({'error': 'Login failed.'})

        key = IKey(self.context).load()
        vault = IVault(self.context)
        payload = handler.create_payload(**{'userid': principal.id})
        token = handler.create_encrypted_signed_token(key, payload)
        expire = get_posix_timestamp(expiration_date(minutes=60))
        vault.store(payload['userid'], payload['uid'], expire)
        self.request.response.setHeader(
                'Access-Control-Allow-Origin', 'http://localhost:8080')
        return json.dumps({'jwt': token.serialize()})


class JWTUser(Endpoint):

    def GET(self):
        #self.request.response.setHeader(
        #    'Access-Control-Allow-Origin', 'http://62.210.125.78:8765')
        self.request.response.setHeader(
                'Access-Control-Allow-Origin', 'http://localhost:8080')
        return json.dumps({'data': {'name':'cklinger', 'pid': '0101010001'}})


class JWTRefresh(Endpoint):

    def POST(self):
        vault = IVault(self.context)
        key = IKey(self.context).load()
    
        new_date = expiration_date(minutes=1)
        to_refresh = json.loads(self.request.bodyStream.stream.read())['old_token']
        payload = json.loads(handler.decrypt_and_verify(key, to_refresh))
        if vault.refresh(payload['userid'], payload['uid'], get_posix_timestamp(new_date)) is True:
            return json.dumps({'message': 'Token refreshed with success. New expiration date set to %s' % new_date})
        return json.dumps({'error': u'The given token could not be refreshed'})


class JSONService(Service):
    grok.name('json')

    endpoints = {
        'login': JWTAuth,
        'auth': JWTAuth,
        'user': JWTUser,
        'refresh': JWTRefresh,
        }
    
    def publishTraverse(self, request, name):
        endpoint = self.endpoints.get(name, None)
        if endpoint is not None:
            return endpoint(self.request, self.context)
            
