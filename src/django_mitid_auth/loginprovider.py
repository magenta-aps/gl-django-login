import logging
from django.conf import settings
from django.http import HttpResponseRedirect

logger = logging.getLogger(__name__)


class LoginProvider:

    @classmethod
    def enabled(cls):
        raise NotImplementedError

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
        raise NotImplementedError

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
