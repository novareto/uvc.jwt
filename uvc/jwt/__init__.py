# -*- coding: utf-8 -*-

import logging
import grok
import uvcsite
from zope.annotation import IAnnotations
from zope.interface import Interface
from jwcrypto import jwk
from jwcrypto.common import json_decode


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
