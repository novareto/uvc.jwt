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
   >>> from uvcsite.tests import startInteraction, endInteraction
   >>> request = startInteraction('mgr')

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
   >>> jwt_view = getMultiAdapter((uvcsite, request), name='jwt.keyring')
   >>> jwt_view
   <uvc.jwt.browser.keyring.PortalJWTKeyring object at 0...>

   >>> from uvc.jwt.browser.keyring import GenerateKeyAction, IKey
   >>> marker = GenerateKeyAction('gen')(jwt_view)
   >>> marker
   <Marker SUCCESS>

   >>> IKey(uvcsite).read()
   '{"k":"...","kty":"oct"}'
   >>> endInteraction()

   >>> request = startInteraction('')
   >>> request.form['data']= "login=0101010001&password=passwort" 
   >>> request.form = {'login': '0101010001', 'password':'passwort'} 
   >>> jwt = getMultiAdapter((uvcsite, request), name='jwt')
   >>> jwt
   <uvc.jwt.browser.keyring.JWT object at 0...>

   >>> jwt()
   '{"jwt": "..."}'
   >>> endInteraction()

   >>> request = startInteraction('')
   >>> request.form = {'login': '0101010001', 'password':'WRONG'} 
   >>> jwt = getMultiAdapter((uvcsite, request), name='jwt')
   >>> jwt
   <uvc.jwt.browser.keyring.JWT object at 0...>

   >>> jwt()
   '{"error": "Login failed."}'

   >>> endInteraction()
