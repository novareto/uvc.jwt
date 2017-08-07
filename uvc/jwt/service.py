# -*- coding: utf-8 -*-

import grok
import json
import uvcsite
from .handler import JWTHandler
from . import IKey, IVault
from .utils import expiration_date, get_posix_timestamp
from uvc.services import Service, Endpoint
from zope.pluggableauth.interfaces import IAuthenticatorPlugin
from zope.component import getUtility
from zope.browser.interfaces import IView
from zope.publisher.interfaces import IPublishTraverse
from zope.publisher.interfaces.http import IHTTPPublisher

handler = JWTHandler()


class JWTAuth(Endpoint):
        
    def authenticate(self):
        principals = getUtility(IAuthenticatorPlugin, name='principals')
        principal = principals.authenticateCredentials(json.loads(self.request.bodyStream.stream.read()))
        return principal

    def OPTIONS(self):
        self.request.response.setHeader(
            'Access-Control-Allow-Origin', 'http://localhost:8082')
        self.request.response.setHeader(
            'Access-Control-Allow-Headers', 'Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With')
        return ""

    def POST(self):
        principal = self.authenticate()
        if principal is None:
            return json.dumps({'error': 'Login failed.'})

        key = IKey(self.context).load()
        vault = IVault(self.context)
        payload = handler.create_payload(**{'userid': principal.id})
        token = handler.create_encrypted_signed_token(key, payload)
        expire = get_posix_timestamp(expiration_date(minutes=1))
        vault.store(payload['userid'], payload['uid'], expire)
        self.request.response.setHeader(
            'Access-Control-Allow-Origin', 'http://localhost:8082')
        return json.dumps({'jwt': token.serialize()})


class JWTUser(Endpoint):
    
    def OPTIONS(self):
        self.request.response.setHeader(
            'Access-Control-Allow-Origin', 'http://localhost:8082')
        self.request.response.setHeader(
            'Access-Control-Allow-Headers', 'Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With')
        return ""

    def GET(self):
        self.request.response.setHeader(
            'Access-Control-Allow-Origin', 'http://localhost:8082')
        return json.dumps({'user': {'name':'cklinger'}})


class JWTRefresh(Endpoint):
    
    def OPTIONS(self):
        self.request.response.setHeader(
            'Access-Control-Allow-Origin', 'http://localhost:8082')
        self.request.response.setHeader(
            'Access-Control-Allow-Headers', 'Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With')
        return ""

    def POST(self):
        vault = IVault(self.context)
        key = IKey(self.context).load()
    
        new_date = expiration_date(minutes=1)
        to_refresh = json.loads(self.request.bodyStream.stream.read())['old_token']
        payload = json.loads(handler.decrypt_and_verify(key, to_refresh))
        if vault.refresh(payload['userid'], payload['uid'], get_posix_timestamp(new_date)) is True:
            return json.dumps({'message': 'Token refreshed with success. New expiration date set to %s' % new_date})
        return json.dumps({'error': u'The given token could not be refreshed'})

    def __call__(self):
        self.update()
        self.request.response.setHeader('Content-Type', 'application/json')
        return self.render()

        
        principal = self.authenticate()
        if principal is None:
            return json.dumps({'error': 'Login failed.'})

        key = IKey(self.context).load()        
        payload = handler.create_payload(**{'userid': principal.id})
        token = handler.create_encrypted_signed_token(key, payload)
        self.request.response.setHeader('Access-Control-Allow-Origin', 'http://localhost:8082')
        return json.dumps({'jwt': token.serialize()})


    

class JSONService(Service):
    grok.name('json')

    endpoints = {
        'login': JWTAuth,
        'user': JWTUser,
        'refresh': JWTRefresh,
        }
    
    def publishTraverse(self, request, name):
        endpoint = self.endpoints.get(name, None)
        if endpoint is not None:
            return endpoint(self.request, self.context)
            
