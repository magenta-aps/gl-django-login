from django.conf import settings
from django.utils.decorators import method_decorator
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View, TemplateView
from django.contrib.auth import REDIRECT_FIELD_NAME

from django_mitid_auth import login_provider_class
from django_mitid_auth.exceptions import LoginException


class LoginView(View):
    def get(self, request):
        request.session["backpage"] = request.GET.get("back") or request.GET.get(
            REDIRECT_FIELD_NAME
        )
        provider = login_provider_class()
        request.session["login_method"] = provider.__class__.__name__
        return provider.login(request)


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
                success_url=request.session.get("backpage") or redirect_to,
            )
        except LoginException as e:
            return self.render_to_response({"errors": e.errordict})


class LogoutView(View):
    def get(self, request):
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
            return self.render_to_response({"errors": e.errordict})
