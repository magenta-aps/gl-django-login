import time

from django.conf import settings
from django.contrib.auth.views import redirect_to_login
from django.shortcuts import redirect
from django.utils.module_loading import import_string

"""
The following code is forked from https://github.com/labd/django-session-timeout
We add functionality to allow a callable to be specified in settings.SESSION_EXPIRE_CALLABLE,
that is called when the session expires.
The callable is specified as a string reference to a function
"""

"""
The MIT License (MIT)

Copyright (c) 2017 Michael van Tellingen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
SESSION_TIMEOUT_KEY = "_session_init_timestamp_"


class SessionTimeoutMiddleware:
    def process_request(self, request):
        if not hasattr(request, "session") or request.session.is_empty():
            return

        init_time = request.session.setdefault(SESSION_TIMEOUT_KEY, time.time())

        expire_seconds = getattr(
            settings, "SESSION_EXPIRE_SECONDS", settings.SESSION_COOKIE_AGE
        )

        session_is_expired = time.time() - init_time > expire_seconds

        if session_is_expired:
            request.session.flush()
            # Begin additional functionality
            expire_callable = getattr(settings, "SESSION_EXPIRE_CALLABLE", None)
            if type(expire_callable) is str:
                expire_callable = import_string(expire_callable)
                if callable(expire_callable):
                    return expire_callable(request)
            # End additional functionality
            redirect_url = getattr(settings, "SESSION_TIMEOUT_REDIRECT", None)
            if redirect_url:
                return redirect(redirect_url)
            else:
                return redirect_to_login(next=request.path)

        expire_since_last_activity = getattr(
            settings, "SESSION_EXPIRE_AFTER_LAST_ACTIVITY", False
        )
        grace_period = getattr(
            settings, "SESSION_EXPIRE_AFTER_LAST_ACTIVITY_GRACE_PERIOD", 1
        )

        if expire_since_last_activity and time.time() - init_time > grace_period:
            request.session[SESSION_TIMEOUT_KEY] = time.time()
