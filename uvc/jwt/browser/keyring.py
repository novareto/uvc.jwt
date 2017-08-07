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
from .. import IKey


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
        print "I AM IN"
        import pdb; pdb.set_trace()
        self.update()
        self.request.response.setHeader('Content-Type', 'application/json')
        return self.render()


