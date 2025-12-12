import logging

from django.conf import settings
from django.http import HttpResponseRedirect

logger = logging.getLogger(__name__)


class LoginProvider:
    session_data_key = getattr(settings, "LOGIN_SESSION_DATA_KEY", None) or "user_info"

    @classmethod
    def enabled(cls):
        return settings.LOGIN_PROVIDER_CLASS == cls.__module__ + "." + cls.__qualname__

    @classmethod
    def is_logged_in(cls, request):
        return (
            True
            if request.session.get(cls.session_data_key)
            or (hasattr(request, "user") and request.user.is_authenticated)
            else False
        )

    @classmethod
    def clear_session(cls, session):
        if cls.session_data_key in session:
            del session[cls.session_data_key]
        session.save()

    @classmethod
    def login(cls, request):
        raise NotImplementedError

    @classmethod
    def handle_login_callback(cls, request, success_url):
        return HttpResponseRedirect(success_url)

    @classmethod
    def logout(cls, request):
        cls.clear_session(request.session)
        url = getattr(settings, "LOGIN_MITID_REDIRECT_URL", settings.LOGIN_REDIRECT_URL)
        return HttpResponseRedirect(url)

    @classmethod
    def handle_logout_callback(cls, request):
        url = getattr(settings, "LOGIN_MITID_REDIRECT_URL", settings.LOGIN_REDIRECT_URL)
        return HttpResponseRedirect(url)
