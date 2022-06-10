from django.urls import path, include

from login.apps import LoginConfig
from login.views import LoginView, LoginCallbackView, LogoutView, LogoutCallback

app_name = LoginConfig.name

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('login/callback/', LoginCallbackView.as_view(), name='login-callback'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('logout/callback/', LogoutCallback.as_view(), name='logout-callback'),
    path('saml/', include('login.saml.urls', namespace='saml')),
]
