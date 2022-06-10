from django.conf.urls import url

from login.saml.views import MetadataView

app_name = 'login.saml'

urlpatterns = [
    url(r'metadata/', MetadataView.as_view(), name='metadata'),
]
