# -*- coding: utf-8 -*-

import uuid
from .utils import now, get_posix_timestamp, expiration_date, date_from_timestamp
from jwcrypto import jwk, jws, jwt
from jwcrypto.common import json_encode, json_decode


class JWTHandler(object):

    def create_payload(self, **ticket):
        tid = uuid.uuid4()
        exp = get_posix_timestamp(expiration_date(minutes=61))
        payload = {
            'uid': str(tid),
            'exp': int(exp),
        }
        ticket.update(payload)
        return ticket

    def generate_key(self, ktype='oct', size=256):
        return jwk.JWK.generate(kty=ktype, size=size)

    def create_signed_token(self, key, payload, alg="HS256"):
        """Return an unserialized signed token.
        Signed with the given key (JWK object)
        """
        token = jwt.JWT(header={"alg": alg}, claims=payload)
        token.make_signed_token(key)
        return token

    def create_encrypted_signed_token(
            self, key, payload, alg="A256KW", enc="A256CBC-HS512"):
        token = self.create_signed_token(key, payload)
        etoken = jwt.JWT(header={"alg": alg, "enc": enc},
                         claims=token.serialize())
        etoken.make_encrypted_token(key)
        return etoken

    def verify(self, key, serial):
        """Return the claims of a signed token
        """
        ET = jwt.JWT(key=key, jwt=serial)
        return ET.claims

    def decrypt_and_verify(self, key, serial):
        """Return the claims of a signed and encrypted token
        """
        eclaims = self.verify(key, serial)
        ST = jwt.JWT(key=key, jwt=eclaims)
        return ST.claims
