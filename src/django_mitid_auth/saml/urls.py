from django.conf.urls import url

from django_mitid_auth.saml.views import MetadataView

app_name = 'django_mitid_auth.saml'

urlpatterns = [
    url(r'metadata/', MetadataView.as_view(), name='metadata'),
]
