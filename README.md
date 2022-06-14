# Django MitID Auth

Module for authenticating against an OpenID backend and against a MitID backend,
with common middleware to intercept requests, check path against a whitelist, 
and delegate to configured handler.

The auth mechanism is a bit different from the standard Django auth system, 
in that we don't leverage the User classes, but instead write relevant data 
directly to the session, which also determines whether a user is logged in. 
This means that we don't collide with standard login mechanisms (e.g. normal 
django username/password), and an admin of staff user that's logged in "the 
normal way" can also be logged in through our session, in essence faking a 
citizen login.

The Saml2 code borrows heavily from https://pypi.org/project/python3-saml-django/
(MIT Licensed). It does so in order to avoid using the default django auth 
system.
