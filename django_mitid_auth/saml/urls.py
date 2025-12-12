from django.conf import settings
from django.urls import path, reverse_lazy

from django_mitid_auth.saml.views import AccessDeniedView, MetadataView

app_name = "django_mitid_auth.saml"

urlpatterns = [
    path("metadata/", MetadataView.as_view(), name="metadata"),
    path(
        "error/login-timeout/",
        AccessDeniedView.as_view(
            template_name="django_mitid_auth/login_timeout.html",
            extra_context={
                "login_url": reverse_lazy(f"{settings.LOGIN_NAMESPACE}:login")
            },
        ),
        name="login-timeout",
    ),
    path(
        "error/login-repeat/",
        AccessDeniedView.as_view(
            template_name="django_mitid_auth/login_repeat.html",
            extra_context={
                "login_url": reverse_lazy(f"{settings.LOGIN_NAMESPACE}:login")
            },
        ),
        name="login-repeat",
    ),
    path(
        "error/login-nocprcvr/",
        AccessDeniedView.as_view(
            template_name="django_mitid_auth/login_no_cprcvr.html",
            extra_context={
                "logout_url": reverse_lazy(f"{settings.LOGIN_NAMESPACE}:logout")
            },
        ),
        name="login-no-cprcvr",
    ),
    path(
        "error/login-assurance/",
        AccessDeniedView.as_view(
            template_name="django_mitid_auth/login_assurance.html",
            extra_context={
                "logout_url": reverse_lazy(f"{settings.LOGIN_NAMESPACE}:logout")
            },
        ),
        name="login-assurance",
    ),
]
