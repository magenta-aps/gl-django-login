from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.http import urlencode, urlquote
from django_mitid_auth import loginprovider


class LoginManager:

    @property
    def enabled(self):
        return settings.LOGIN_PROVIDER_CLASS is not None

    white_listed_urls = []

    def __init__(self, get_response):
        self.white_listed_urls = list(settings.LOGIN_WHITELISTED_URLS)
        if self.enabled:
            self.provider = loginprovider()
            self.get_response = get_response
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

    def redirect_to_login(self, request):
        backpage = urlquote(request.path)
        if request.GET:
            backpage += "?" + urlencode(request.GET, True)
        return redirect(settings.LOGIN_URL + "?back=" + backpage)

    def __call__(self, request):
        if self.enabled:
            print("enabled")
            # When any non-whitelisted page is loaded, check if we are authenticated
            if request.path not in self.white_listed_urls and request.path.rstrip('/') not in self.white_listed_urls and not request.path.startswith(settings.STATIC_URL):
                if not self.provider.is_logged_in(request):
                    return self.redirect_to_login(request)
        else:
            print("not enabled")
            if 'user_info' not in request.session or not request.session['user_info']:
                request.session['user_info'] = {
                    'CVR': settings.DEFAULT_CVR,
                    'CPR': settings.DEFAULT_CPR,
                }
        # try:
        #     response = self.get_response(request)
        #     if response.status_code == 403:
        #         return self.redirect_to_login(request)
        #     return response
        # except PermissionDenied:
        #     return self.redirect_to_login(request)

    @staticmethod
    def get_backpage(request):
        backpage = request.GET.get('back', request.session.get('backpage', settings.LOGIN_REDIRECT_URL))
        return backpage
