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




SETUP PAU INTERACTIVE DEBUGGER


Welcome to the interactive debug prompt.
The 'root' variable contains the ZODB root folder.
The 'app' variable contains the Debugger, 'app.publish(path)' simulates a request.
>>> from zope.component import getUtility
>>> from zope.component import setSite
Traceback (most recent call last):
  File "<console>", line 1, in <module>
ImportError: cannot import name setSite
>>> from zope.component.hooks import setSite
>>> root['app']
<uvcsite.app.Uvcsite object at 0x1102131b8>
>>> setSite(root['app'])
>>> from zope.authentication.interfaces import IAuthentication
>>> pau = getUtility(IAuthentication)
>>> pau
<zope.pluggableauth.authentication.PluggableAuthentication object at 0x110213758>
>>> dir(pau)
['_BTreeContainer__len', '__class__', '__contains__', '__delattr__', '__delitem__', '__dict__', '__doc__', '__format__', '__getattribute__', '__getitem__', '__getstate__', '__hash__', '__implemented__', '__init__', '__iter__', '__len__', '__module__', '__name__', '__new__', '__parent__', '__providedBy__', '__provides__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__setitem__', '__setstate__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_newContainerData', '_p_activate', '_p_changed', '_p_deactivate', '_p_delattr', '_p_estimated_size', '_p_getattr', '_p_invalidate', '_p_jar', '_p_mtime', '_p_oid', '_p_serial', '_p_setattr', '_p_state', '_p_status', '_p_sticky', '_plugins', '_setitemf', 'authenticate', 'authenticatorPlugins', 'credentialsPlugins', 'get', 'getAuthenticatorPlugins', 'getCredentialsPlugins', 'getPrincipal', 'getQueriables', 'has_key', 'items', 'keys', 'logout', 'unauthenticatedPrincipal', 'unauthorized', 'values']
>>> pau.credentialsPlugins
('cookies', 'Zope Realm Basic-Auth', 'No Challenge if Authenticated')
>>> pau.credentialsPlugins = ('cookies', 'Zope Realm Basic-Auth', 'creds.jwt', 'No Challenge if Authenticated')
>>> pau.authenticatorPlugins
('principals',)
>>> pau.authenticatorPlugins = ('principals', 'auth.jwt')
>>> import transaction; transaction.commit()
>>> exit