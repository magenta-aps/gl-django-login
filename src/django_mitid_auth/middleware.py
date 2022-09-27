from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import redirect
from django.template.loader import get_template
from django.urls import reverse
from django.utils.http import urlencode, urlquote
from django_mitid_auth import login_provider_class


class LoginManager:

    @property
    def enabled(self):
        return settings.LOGIN_PROVIDER_CLASS is not None

    @property
    def can_bypass(self):
        return self.enabled and settings.LOGIN_BYPASS_ENABLED

    white_listed_urls = []

    def __init__(self, get_response):
        self.white_listed_urls = list(settings.LOGIN_WHITELISTED_URLS)
        self.get_response = get_response
        namespace = settings.LOGIN_NAMESPACE
        if self.enabled:
            self.provider = login_provider_class()
            # Urls that should not redirect an anonymous user to login page
            if hasattr(self.provider, 'whitelist'):
                self.white_listed_urls += self.provider.whitelist
            self.white_listed_urls += [
                reverse(f"{namespace}:login"),
                reverse(f"{namespace}:login-callback"),
                reverse(f"{namespace}:logout"),
                reverse(f"{namespace}:logout-callback"),
            ]

    def get_login_redirection_url(self, request):
        backpage = urlquote(request.path)
        if request.GET:
            backpage += "?" + urlencode(request.GET, True)
        login_url = getattr(settings, 'LOGIN_MITID_URL', settings.LOGIN_URL)
        return login_url + "?back=" + backpage

    def redirect_to_login(self, request):
        print("redirecting to login")
        return redirect(self.get_login_redirection_url(request))

    def __call__(self, request):
        if request.path not in self.white_listed_urls \
                and request.path.rstrip('/') not in self.white_listed_urls \
                and not request.path.startswith(settings.STATIC_URL):            # When any non-whitelisted page is loaded, check if we are authenticated
            print(f"{request.path} is not in whitelist; whitelist is {self.white_listed_urls}")
            if self.enabled:
                if self.provider.is_logged_in(request):
                    return self.get_response(request)
                else:
                    if self.can_bypass:
                        if request.GET.get('login_bypass'):
                            # set up dummy session
                            self.set_dummy_session(request)
                        else:
                            # offer bypass page
                            return HttpResponse(
                                get_template('django_mitid_auth/bypass.html').render({
                                    'login_url': self.get_login_redirection_url(request),
                                    'bypass_url': request.path+"?login_bypass=1"
                                })
                            )
                    else:
                        return self.redirect_to_login(request)
            else:
                # Not enabled; fall back to dummy user if available
                self.set_dummy_session(request)

        return self.get_response(request)

    def set_dummy_session(self, request):
        if ('user_info' not in request.session or not request.session['user_info']) and (settings.DEFAULT_CVR or settings.DEFAULT_CPR):
            request.session['user_info'] = {
                'cvr': settings.DEFAULT_CVR,
                'cpr': settings.DEFAULT_CPR,
            }

    @staticmethod
    def get_backpage(request):
        backpage = request.GET.get(
            'back',
            request.session.get('backpage',
                getattr(settings, "LOGIN_MITID_REDIRECT_URL", settings.LOGIN_REDIRECT_URL)
            )
        )
        return backpage

    @staticmethod
    def get_whitelisted_urls():
        return LoginManager(None).white_listed_urls
