from django.urls import path, include
from django.conf import settings

from django_mitid_auth.apps import LoginConfig
from django_mitid_auth.views import LoginView, LoginCallbackView, LogoutView, LogoutCallback

app_name = LoginConfig.name

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('login/callback/', LoginCallbackView.as_view(), name='login-callback'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('logout/callback/', LogoutCallback.as_view(), name='logout-callback'),
]
if settings.LOGIN_PROVIDER_CLASS == 'django_mitid_auth.openid.openid.OpenId':
    urlpatterns += [
        path('oid/', include('django_mitid_auth.openid.urls', namespace='oid')),
    ]
if settings.LOGIN_PROVIDER_CLASS in ('django_mitid_auth.saml.saml2.Saml2', 'django_mitid_auth.saml.oiosaml.OIOSaml'):
    urlpatterns += [
        path('saml/', include('django_mitid_auth.saml.urls', namespace='saml')),
    ]
