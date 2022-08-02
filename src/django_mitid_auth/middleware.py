from django.conf import settings
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.http import urlencode, urlquote
from django_mitid_auth import loginprovider


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
        if self.enabled:
            self.provider = loginprovider()
            # Urls that should not redirect an anonymous user to login page
            if hasattr(self.provider, 'whitelist'):
                self.white_listed_urls += self.provider.whitelist
            namespace = settings.LOGIN_NAMESPACE
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
        return settings.LOGIN_URL + "?back=" + backpage

    def redirect_to_login(self, request):
        return redirect(self.get_login_redirection_url(request))

    def __call__(self, request):
        if self.can_bypass:
            print(request.path)
            if request.path == reverse(f"{settings.LOGIN_NAMESPACE}:bypass") and request.GET.get('login_bypass'):
                # set up dummy session
                self.set_dummy_session(request)
            else:
                # offer bypass page
                return redirect(''.join([
                    reverse(f"{settings.LOGIN_NAMESPACE}:bypass"),
                    "?login="+urlquote(self.get_login_redirection_url(request)),
                    "&bypass="+urlquote(request.path+"?login_bypass=1")
                ]))

        elif self.enabled:
            # When any non-whitelisted page is loaded, check if we are authenticated
            if request.path not in self.white_listed_urls and request.path.rstrip('/') not in self.white_listed_urls and not request.path.startswith(settings.STATIC_URL):
                if not self.provider.is_logged_in(request):
                    return self.redirect_to_login(request)
        else:
            # Not enabled; fall back to dummy user if available
            self.set_dummy_session(request)

        return self.get_response(request)

    def set_dummy_session(self, request):
        if ('user_info' not in request.session or not request.session['user_info']) and (settings.DEFAULT_CVR or settings.DEFAULT_CPR):
            request.session['user_info'] = {
                'CVR': settings.DEFAULT_CVR,
                'CPR': settings.DEFAULT_CPR,
            }

    @staticmethod
    def get_backpage(request):
        backpage = request.GET.get('back', request.session.get('backpage', settings.LOGIN_REDIRECT_URL))
        return backpage
