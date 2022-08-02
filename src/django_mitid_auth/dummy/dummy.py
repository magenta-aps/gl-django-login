import logging
from django.conf import settings
from django.http import HttpResponseRedirect

logger = logging.getLogger(__name__)


class DummyProvider:

    @classmethod
    def enabled(cls):
        return True if settings.DEFAULT_CVR or settings.DEFAULT_CPR else False

    @classmethod
    def is_logged_in(cls, request):
        return True if request.session.get('user_info') else False

    @classmethod
    def clear_session(cls, session):
        if 'user_info' in session:
            del session['user_info']
        session.save()

    @classmethod
    def login(cls, request):
        request.session['user_info'] = {
            'CVR': settings.DEFAULT_CVR,
            'CPR': settings.DEFAULT_CPR,
        }

    @classmethod
    def handle_login_callback(cls, request, success_url):
        return HttpResponseRedirect(success_url)

    @classmethod
    def logout(cls, request):
        cls.clear_session(request.session)
        return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)

    @classmethod
    def handle_logout_callback(cls, request):
        return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)
