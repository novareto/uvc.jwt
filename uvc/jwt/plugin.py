# -*- coding: utf-8 -*-

import grok
import json
import uvcsite
import urllib2
from . import IKey
from .utils import date_from_timestamp
from .handler import JWTHandler
from zope.interface import Interface
from zope.annotation import IAnnotations
from zope.pluggableauth.interfaces import (
    IPrincipalInfo, IAuthenticatorPlugin, ICredentialsPlugin)


class BearerTokenAuthCredentialsPlugin(grok.GlobalUtility):
    grok.name('creds.jwt')
    grok.implements(ICredentialsPlugin)

    def extractCredentials(self, request):
        if request._auth:
            if request._auth.lower().startswith(u'bearer '):
                access_token = request._auth.split()[-1]
            return {'access_token': access_token}
        return None

    def challenge(self, request):
        if not grok.IRESTLayer.providedBy(request):
            return False
        request.response.setStatus(401)
        return True

    def logout(self, request):
        return False


class JWTHolder(object):
    grok.implements(IPrincipalInfo)

    credentialsPlugin = None
    authenticatorPlugin = None

    def __repr__(self):
        return '<AccessTokenHolder "%s">' % self.id

    def __init__(self, token):
        self.id = token['userid']
        self.expiration = date_from_timestamp(float(token['exp']))
        self.title = u'Access token %r' % self.id
        self.description = u'JWT access token'


class AuthenticateBearer(grok.GlobalUtility):
    grok.name('auth.jwt')
    grok.implements(IAuthenticatorPlugin)

    def __init__(self):
        self.jwt = JWTHandler()

    @property
    def key(self):
        app = grok.getApplication()
        return IKey(app).load()

    def verify(self, payload):
        # Here, we need to assert that the expiration time is right.
        # We might do other checks.
        return True
        return self.jwt.verify(self.key, payload) == True

    def authenticateCredentials(self, credentials):
        """Return principal info if credentials can be authenticated
        """      
        if not isinstance(credentials, dict):
            return None
        
        access_token = credentials.get('access_token')
        if access_token is None:
            return None

        payload = self.jwt.decrypt_and_verify(self.key, access_token)
        if not payload:
            return None
        else:
            payload = json.loads(payload)
        print payload
        if self.verify(payload) == True:
            return JWTHolder(payload)
        return None

    def principalInfo(self, id):
        return None
