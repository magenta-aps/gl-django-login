from django.urls import path

from django_mitid_auth.views import LoginCallbackView, LogoutView

app_name = "django_mitid_auth.saml"

urlpatterns = [
    path("callback/", LoginCallbackView.as_view(), name="login-callback"),
    path("logout/", LogoutView.as_view(), name="logout"),
]
