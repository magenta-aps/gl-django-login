import logging
from django.conf import settings
from django.http import HttpResponseRedirect
from django_mitid_auth.loginprovider import LoginProvider

logger = logging.getLogger(__name__)


class DummyProvider(LoginProvider):

    @classmethod
    def enabled(cls):
        return True if settings.DEFAULT_CVR or settings.DEFAULT_CPR else False

    @classmethod
    def login(cls, request):
        request.session['user_info'] = {
            'CVR': settings.DEFAULT_CVR,
            'CPR': settings.DEFAULT_CPR,
        }

    @classmethod
    def handle_login_callback(cls, request, success_url):
        return HttpResponseRedirect(success_url)
