from django.urls import path

from django_mitid_auth.views import LoginCallbackView, LogoutCallback, LogoutView

app_name = "django_mitid_auth.saml"

urlpatterns = [
    path("callback/", LoginCallbackView.as_view(), name="login-callback"),
    path("logout/", LogoutView.as_view(), name="logout"),
    # Temporary fallback until we get MitID rolled out everywhere
    path("login/callback/", LoginCallbackView.as_view(), name="login-callback-2"),
    path("logout/callback/", LogoutCallback.as_view(), name="logout-callback"),
]
