import logging

from django.conf import settings
from django.http import HttpResponseRedirect

from django_mitid_auth.loginprovider import LoginProvider

logger = logging.getLogger(__name__)


class DummyProvider(LoginProvider):
    session_data_key = getattr(settings, "LOGIN_SESSION_DATA_KEY", None) or "user_info"

    @classmethod
    def enabled(cls):
        return (
            True
            if getattr(settings, "DEFAULT_CVR", None)
            or getattr(settings, "DEFAULT_CPR", None)
            else False
        )

    @classmethod
    def login(cls, request):
        request.session[cls.session_data_key] = {
            "CVR": getattr(settings, "DEFAULT_CVR", None),
            "CPR": getattr(settings, "DEFAULT_CPR", None),
        }

    @classmethod
    def handle_login_callback(cls, request, success_url):
        return HttpResponseRedirect(success_url)
