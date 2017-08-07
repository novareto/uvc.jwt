# -*- coding: utf-8 -*-

import grok
import json
import uvcsite
from .handler import JWTHandler
from . import IKey
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
        self.request.response.setHeader('Access-Control-Allow-Origin', 'http://localhost:8082')
        self.request.response.setHeader('Access-Control-Allow-Headers', 'Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With')
        return ""

    def POST(self):
        principal = self.authenticate()
        if principal is None:
            return json.dumps({'error': 'Login failed.'})

        key = IKey(self.context).load()        
        payload = handler.create_payload(**{'userid': principal.id})
        token = handler.create_encrypted_signed_token(key, payload)
        self.request.response.setHeader('Access-Control-Allow-Origin', 'http://localhost:8082')
        return json.dumps({'jwt': token.serialize()})


class JWTUser(Endpoint):
    
    def OPTIONS(self):
        self.request.response.setHeader('Access-Control-Allow-Origin', 'http://localhost:8082')
        self.request.response.setHeader('Access-Control-Allow-Headers', 'Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With')
        return ""

    def GET(self):
        self.request.response.setHeader('Access-Control-Allow-Origin', 'http://localhost:8082')
        return json.dumps({'user': {'name':'cklinger'}})


class JSONService(Service):
    grok.name('json')

    endpoints = {
        'login': JWTAuth,
        'user': JWTUser,
        }
    
    def publishTraverse(self, request, name):
        print request.__class__
        endpoint = self.endpoints.get(name, None)
        if endpoint is not None:
            return endpoint(self.request, self.context)
            
