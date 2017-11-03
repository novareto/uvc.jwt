# -*- coding: utf-8 -*-
# Copyright (c) 2007-2013 NovaReto GmbH
# cklinger@novareto.de 

import json
import grok
import uvcsite


from . import IKey, IVault
from .handler import JWTHandler
from .utils import expiration_date, get_posix_timestamp


from zope.component import getUtility
from md.rest.components import JsonEndpoint
from zope.pluggableauth.interfaces import IAuthenticatorPlugin
from grokcore import rest


class RESTAuthLayer(rest.IRESTLayer):
    rest.restskin('auth')


handler = JWTHandler()


class AuthService(JsonEndpoint):
    grok.name('auth')
    grok.context(uvcsite.IUVCSite)
    grok.layer(RESTAuthLayer)
    grok.require('zope.Public')

    def authenticate(self, data):
        principals = getUtility(IAuthenticatorPlugin, name='principals')
        principal = principals.authenticateCredentials(data)
        return principal

    @grok.require('zope.Public')
    def OPTIONS(self):
        self.request.response.setHeader(
            'Access-Control-Allow-Origin', 'http://localhost:8082')
        self.request.response.setHeader(
            'Access-Control-Allow-Headers', 'Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With')
        return "TRUE"

    @grok.require('zope.Public')
    def POST(self, data):
        principal = self.authenticate(data)
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
        return {'jwt': token.serialize()}

    @grok.require('zope.View')
    def GET(self):
        self.request.response.setHeader(
            'Access-Control-Allow-Origin', 'http://localhost:8082')
        return {'user': {'name':'cklinger'}}
