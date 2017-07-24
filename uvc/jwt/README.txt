=======
Doctest
=======

uvc.jwt

:Test-Layer: functional


Let's first create an instance of Uvcsite at the top level:

   >>> from zope.app.testing.functional import getRootFolder
   >>> from uvcsite.app import Uvcsite
   >>> from zope.site.hooks import setSite
   >>> root = getRootFolder()
   >>> uvcsite = Uvcsite()
   >>> root['app'] = uvcsite
   >>> setSite(root['app'])

   >>> from zope.component import getUtility
   >>> from zope.authentication.interfaces import IAuthentication

   >>> auth = getUtility(IAuthentication)
   >>> print auth
   <zope.pluggableauth.authentication.PluggableAuthentication object at ...>

   >>> for plugin in auth.getCredentialsPlugins():
   ...     print plugin
   ('cookies', <dolmen.app.authentication.plugins.cookies.CookiesCredentials object at 0...>)

   >>> for plugin in auth.getAuthenticatorPlugins():
   ...     print plugin
   ('principals', <uvcsite.auth.handler.UVCAuthenticator object at 0...>)

   >>> from zope.component import getMultiAdapter
   >>> from zope.publisher.browser import TestRequest
   >>> request = TestRequest()
   >>> jwt_view = getMultiAdapter((uvcsite, request), name='jwt.keyring')
   >>> jwt_view

   >>> from uvc.jwt.browser.keyring import GenerateKeyAction, IKey
   >>> marker = GenerateKeyAction('gen')(jwt_view)
   >>> marker
   >>> import transaction; transaction.commit()

   >>> IKey(uvcsite).read()
   "BLAB"

   >>> jwt = getMultiAdapter((uvcsite, request), name='jwt')
   >>> jwt
