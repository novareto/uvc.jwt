# -*- coding: utf-8 -*-

import logging
import grok
import uvcsite
from datetime import datetime
from zope.annotation import IAnnotations
from zope.interface import Interface
from jwcrypto import jwk
from jwcrypto.common import json_decode
from BTrees.OIBTree import OIBTree
from BTrees.OOBTree import OOBTree
from .utils import date_from_timestamp, now

logger = logging.getLogger('uvcsite.uvc.jwt')

def log(message, summary='', severity=logging.DEBUG):
    logger.log(severity, '%s %s', summary, message)


class IKey(Interface):

    def read():
        """Document me
        """

    def write(value):
        """Document me
        """

    def load():
        """Document me
        """


class IVault(Interface):

    def store(user, token, expiration_date):
        pass

    def retrieve(user, token):
        pass

    def refresh(user, token, expiration_date):
        pass


class ApplicationJWTKey(grok.Adapter):
    grok.context(uvcsite.IUVCSite)
    grok.implements(IKey)

    annotation_slot = 'jwt.keyring'

    def load(self):
        key = self.read()
        if key is None:
            raise ValueError('JWT key does not exist')
        k = json_decode(key)
        return jwk.JWK(**k)

    def read(self):
        key = IAnnotations(self.context).get(self.annotation_slot, None)
        return key

    def write(self, value):
        IAnnotations(self.context)[self.annotation_slot] = value


class ApplicationJWTVault(grok.Adapter):
    grok.context(uvcsite.IUVCSite)
    grok.implements(IVault)

    annotation_slot = 'jwt.vault'

    def store(self, user, token_id, expiration_date):
        annotations = IAnnotations(self.context)
        users = annotations.get(self.annotation_slot, None)
        if users is None:
            users = annotations[self.annotation_slot] = OOBTree()
        vault = users.get(user, None)
        if vault is None:
            vault = users[user] = OIBTree()
        vault[token_id] = int(expiration_date)


    def retrieve(self, user, token_id):
        annotations = IAnnotations(self.context)
        users = annotations.get(self.annotation_slot, None)
        if users is not None:
            vault = users.get(user, None)
            if vault is not None:
                return vault.get(token_id, None)
        return None


    def refresh(self, user, token_id, expiration_date):
        annotations = IAnnotations(self.context)
        users = annotations.get(self.annotation_slot, None)
        if users is not None:
            vault = users.get(user, None)
            if vault is not None and token_id in vault:
                 vault[token_id] = int(expiration_date)
                 return True

        return False

    def check_token(self, user, token_id):
        annotations = IAnnotations(self.context)
        users = annotations.get(self.annotation_slot, None)
        if users is not None:
            vault = users.get(user, None)
            if vault is not None and token_id in vault:
                 exp = date_from_timestamp(float(vault[token_id]))
                 return exp >= now()
        return None
