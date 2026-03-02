import time

from django.conf import settings
from django.contrib.auth.views import redirect_to_login
from django.shortcuts import redirect
from django.utils.module_loading import import_string

"""
The following code is forked from https://github.com/labd/django-session-timeout

Copyright (c) 2017 Michael van Tellingen

MIT License

We add functionality to allow a callable to be specified in settings.SESSION_EXPIRE_CALLABLE, that is called when the session expires.
The callable is specified as a string reference to a function
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
