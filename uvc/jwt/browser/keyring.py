# -*- coding: utf-8 -*-

import uuid
import grok
import uvcsite
import json
import grokcore.view

from dolmen.forms.base import Fields, Actions, Action, SUCCESS
from zope.annotation import IAnnotations
from zope.publisher.interfaces.http import IHTTPRequest
from zope.publisher.browser import BrowserPage
from zope.pluggableauth.interfaces import IAuthenticatorPlugin
from zope.component import getUtility

from ..handler import JWTHandler
from ..utils import expiration_date
from .. import IKey, IVault


grok.templatedir('templates')


class GenerateKeyAction(Action):
    """Update action for any locatable object.
    """

    def __call__(self, form):
        handler = JWTHandler()
        key = handler.generate_key()
        form.key = key.export()

        form.flash(u"Keyring updated with a new key.")
        form.redirect(form.url(form.context))

        return SUCCESS


class PortalJWTKeyring(uvcsite.Form):
    grok.name('jwt.keyring')
    grok.context(uvcsite.IUVCSite)
    grok.require('zope.ManageSite')

    label = u"JWT Keyring"

    ignoreContent = False

    fields = Fields()
    actions = Actions(GenerateKeyAction('Generate'))

    @property
    def key(self):
        return IKey(self.context).read()

    @key.setter
    def key(self, value):
        IKey(self.context).write(value)

    @property
    def jwk(self):
        key = self.key
        if not key:
            return None
        return json.loads(key)


class JWT(uvcsite.View):
    grok.context(uvcsite.IUVCSite)
    grok.require('zope.Public')

    def update(self):
        self.handler = JWTHandler()

    def authenticate(self):
        principals = getUtility(IAuthenticatorPlugin, name='principals')
        principal = principals.authenticateCredentials(self.request.form)
        return principal

    def render(self):
        principal = self.authenticate()
        if principal is None:
            return json.dumps({'error': 'Login failed.'})

        key = IKey(self.context).load()        
        payload = self.handler.create_payload(**{'userid': principal.id})
        token = self.handler.create_encrypted_signed_token(key, payload)
        return json.dumps({'jwt': token.serialize()})

    def __call__(self):
        self.update()
        self.request.response.setHeader('Content-Type', 'application/json')
        return self.render()


class Refresh(uvcsite.View):
    grok.context(uvcsite.IUVCSite)
    grok.require('zope.Public')

    def update(self):
        self.vault = IVault(self.context)
        self.handler = JWTHandler()
        self.key = IKey(self.context).load()
        
    def refresh(self):
        new_date = expiration_date(minutes=1)
        to_refresh = self.request.form.get('old_token')
        payload = self.handler.decrypt_and_verify(self.key, to_refresh)
        return self.vault.refresh(payload['userid'], payload['uid'], new_date)

    def render(self):
        new_token = self.refresh()
        if new_token is not False:
            return json.dumps({'jwt': token.serialize()})
        return json.dumps({'error': u'The given token could not be refreshed'})

    def __call__(self):
        self.update()
        self.request.response.setHeader('Content-Type', 'application/json')
        return self.render()
