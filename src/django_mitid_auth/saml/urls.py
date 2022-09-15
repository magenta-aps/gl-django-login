from django.conf import settings
from django.urls import path, reverse_lazy
from django.views.generic import TemplateView

from django_mitid_auth.saml.views import MetadataView

app_name = 'django_mitid_auth.saml'

urlpatterns = [
    path('metadata/', MetadataView.as_view(), name='metadata'),

    path(
        "error/login-timeout/",
        TemplateView.as_view(template_name="django_mitid_auth/login_timeout.html", extra_context={'login_url': reverse_lazy(f"{settings.LOGIN_NAMESPACE}:login")}),
        name="login-timeout",
    ),
    path(
        "error/login-repeat/",
        TemplateView.as_view(template_name="django_mitid_auth/login_repeat.html", extra_context={'login_url': reverse_lazy(f"{settings.LOGIN_NAMESPACE}:login")}),
        name="login-repeat",
    ),
    path(
        "error/login-nocprcvr/",
        TemplateView.as_view(template_name="django_mitid_auth/login_no_cprcvr.html", extra_context={'logout_url': reverse_lazy(f"{settings.LOGIN_NAMESPACE}:logout")}),
        name="login-no-cprcvr",
    ),
]
