import re
from typing import List
from urllib.parse import quote_plus

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.template.loader import get_template
from django.urls import reverse
from django.utils.http import urlencode

from django_mitid_auth import login_provider_class


class LoginManager:
    session_data_key = getattr(settings, "LOGIN_SESSION_DATA_KEY", None) or "user_info"

    @property
    def enabled(self) -> bool:
        return settings.LOGIN_PROVIDER_CLASS is not None

    @property
    def can_bypass(self) -> bool:
        return self.enabled and settings.LOGIN_BYPASS_ENABLED

    white_listed_urls: List[str] = []

    def __init__(self, get_response):
        self.white_listed_urls = list(settings.LOGIN_WHITELISTED_URLS)
        self.get_response = get_response
        namespace = settings.LOGIN_NAMESPACE
        if self.enabled:
            self.provider = login_provider_class()
            # Urls that should not redirect an anonymous user to login page
            if hasattr(self.provider, "whitelist"):
                self.white_listed_urls += self.provider.whitelist
            self.white_listed_urls += [
                reverse(f"{namespace}:login"),
                reverse(f"{namespace}:login-callback"),
                reverse(f"{namespace}:logout"),
                reverse(f"{namespace}:logout-callback"),
            ]

    def get_login_redirection_url(self, request: HttpRequest) -> str:
        backpage = quote_plus(request.path)
        if request.GET:
            backpage += "?" + urlencode(request.GET, True)
        login_url = str(getattr(settings, "LOGIN_MITID_URL", settings.LOGIN_URL))
        return login_url + "?back=" + backpage

    def redirect_to_login(self, request: HttpRequest) -> HttpResponse:
        return redirect(self.get_login_redirection_url(request))

    def check_whitelist(self, path) -> bool:
        for p in (path, path.rstrip("/")):
            for item in self.white_listed_urls:
                if type(item) is re.Pattern:
                    if item.match(p):
                        return True
                elif p == item:
                    return True
        return False

    def __call__(self, request: HttpRequest):
        if not self.check_whitelist(request.path) and not request.path.startswith(
            settings.STATIC_URL
        ):  # When any non-whitelisted page is loaded, check if we are authenticated
            if self.enabled:
                if self.provider.is_logged_in(request):
                    return self.get_response(request)
                else:
                    if self.can_bypass:
                        if request.GET.get("login_bypass"):
                            # set up dummy session
                            self.set_dummy_session(request)
                        else:
                            # offer bypass page
                            return HttpResponse(
                                get_template("django_mitid_auth/bypass.html").render(
                                    {
                                        "login_url": self.get_login_redirection_url(
                                            request
                                        ),
                                        "bypass_url": request.path + "?login_bypass=1",
                                    }
                                )
                            )
                    else:
                        return self.redirect_to_login(request)
            else:
                # Not enabled; fall back to dummy user if available
                self.set_dummy_session(request)

        return self.get_response(request)

    @classmethod
    def set_dummy_session(cls, request):
        if (
            cls.session_data_key not in request.session
            or not request.session[cls.session_data_key]
        ):
            populate_dummy_session = getattr(settings, "POPULATE_DUMMY_SESSION", False)
            if populate_dummy_session:
                request.session[cls.session_data_key] = populate_dummy_session()
            elif getattr(settings, "DEFAULT_CVR", None) or getattr(
                settings, "DEFAULT_CPR", None
            ):
                request.session[cls.session_data_key] = {
                    "cvr": getattr(settings, "DEFAULT_CVR", None),
                    "cpr": getattr(settings, "DEFAULT_CPR", None),
                }
            request.session["login_bypassed"] = True

    @classmethod
    def clear_dummy_session(cls, request):
        for key in (cls.session_data_key, "login_bypassed"):
            if key in request.session:
                del request.session[key]

    @staticmethod
    def get_backpage(request):
        backpage = request.GET.get(
            "back",
            request.session.get(
                "backpage",
                getattr(
                    settings, "LOGIN_MITID_REDIRECT_URL", settings.LOGIN_REDIRECT_URL
                ),
            ),
        )
        return backpage

    @staticmethod
    def get_whitelisted_urls():
        return LoginManager(None).white_listed_urls
