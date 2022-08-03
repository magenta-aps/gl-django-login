from django.conf import settings
from django.utils.decorators import method_decorator
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.decorators.csrf import csrf_exempt
from django.views.generic.base import View, TemplateView

from django_mitid_auth import login_provider_class
from django_mitid_auth.exceptions import LoginException


class LoginView(View):
    def get(self, request):
        request.session['backpage'] = request.GET.get('back')
        # Setup the oauth login url and redirect the browser to it.
        provider = login_provider_class()
        request.session['login_method'] = provider.__class__.__name__
        return provider.login(request)


@method_decorator(csrf_exempt, name='dispatch')
class LoginCallbackView(TemplateView):
    template_name = 'django_mitid_auth/error.html'

    def get(self, request, *args, **kwargs):
        return self.handle(request)

    def post(self, request):
        return self.handle(request)

    def handle(self, request):
        try:
            return login_provider_class().handle_login_callback(
                request=request,
                success_url=request.session.get('backpage', settings.LOGIN_REDIRECT_URL)
            )
        except LoginException as e:
            return self.render_to_response({'errors': e.errordict})


class LogoutView(View):
    def get(self, request):
        if 'bypassed' in request.session:
            del request.session['bypassed']
        try:
            return login_provider_class().logout(request)
        except LoginException as e:
            return self.render_to_response({'errors': e.errordict})


@method_decorator(csrf_exempt, name='dispatch')
class LogoutCallback(TemplateView):
    template_name = 'django_mitid_auth/error.html'

    @xframe_options_exempt
    def get(self, request, *args, **kwargs):
        return self.handle(request)

    def post(self, request):
        return self.handle(request)

    def handle(self, request):
        try:
            return login_provider_class().handle_logout_callback(request)
        except LoginException as e:
            return self.render_to_response({'errors': e.errordict})
