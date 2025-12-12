from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import TemplateView, View

from django_mitid_auth import login_provider_class
from django_mitid_auth.exceptions import LoginException
from django_mitid_auth.middleware import LoginManager


class LoginView(View):
    def get(self, request):
        back = (
            request.GET.get("back")
            or request.GET.get(REDIRECT_FIELD_NAME)
            or request.COOKIES.get("back")
        )

        provider = login_provider_class()
        request.session["login_method"] = provider.__name__
        response = provider.login(request)
        if back and back != "None":
            response.set_cookie(
                "back",
                back,
                secure=True,
                httponly=True,
                samesite="None",
                expires=datetime.utcnow() + timedelta(seconds=600),
            )
        return response


@method_decorator(csrf_exempt, name="dispatch")
class LoginCallbackView(TemplateView):
    template_name = "django_mitid_auth/error.html"

    def get(self, request, *args, **kwargs):
        return self.handle(request)

    def post(self, request):
        return self.handle(request)

    def handle(self, request):
        try:
            redirect_to = getattr(
                settings, "LOGIN_MITID_REDIRECT_URL", settings.LOGIN_REDIRECT_URL
            )
            return login_provider_class().handle_login_callback(
                request=request,
                success_url=redirect_to,
            )
        except LoginException as e:
            return self.render_to_response(
                {
                    "errors": e.errordict,
                    "login_url": reverse(f"{settings.LOGIN_NAMESPACE}:login"),
                }
            )


class LogoutView(View):
    def get(self, request):
        if (
            settings.LOGIN_PROVIDER_CLASS is not None
            and settings.LOGIN_BYPASS_ENABLED
            and request.session.get("login_bypassed", False)
        ):
            LoginManager.clear_dummy_session(request)
            return redirect(settings.LOGOUT_REDIRECT_URL)
        try:
            return login_provider_class().logout(request)
        except LoginException as e:
            return self.render_to_response({"errors": e.errordict})


@method_decorator(csrf_exempt, name="dispatch")
class LogoutCallback(TemplateView):
    template_name = "django_mitid_auth/error.html"

    @xframe_options_exempt
    def get(self, request, *args, **kwargs):
        return self.handle(request)

    def post(self, request):
        return self.handle(request)

    def handle(self, request):
        try:
            return login_provider_class().handle_logout_callback(request)
        except LoginException as e:
            return self.render_to_response(
                {
                    "errors": e.errordict,
                    "login_url": reverse(f"{settings.LOGIN_NAMESPACE}:login"),
                }
            )
