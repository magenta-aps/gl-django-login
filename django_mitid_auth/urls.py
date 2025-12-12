from django.urls import include, path

from django_mitid_auth.apps import LoginConfig
from django_mitid_auth.views import (
    LoginCallbackView,
    LoginView,
    LogoutCallback,
    LogoutView,
)

app_name = LoginConfig.name

urlpatterns = [
    path("login/", LoginView.as_view(), name="login"),
    path("login/callback/", LoginCallbackView.as_view(), name="login-callback"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("logout/callback/", LogoutCallback.as_view(), name="logout-callback"),
    path("oid/", include("django_mitid_auth.openid.urls", namespace="oid")),
    path("saml/", include("django_mitid_auth.saml.urls", namespace="saml")),
    # Temporary fallback until we get MitID rolled out everywhere
    path("user/oid/", include("django_mitid_auth.openid.urls", namespace="oid-2")),
]
