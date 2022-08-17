from django.urls import path

from django_mitid_auth.saml.views import MetadataView

app_name = 'django_mitid_auth.saml'

urlpatterns = [
    path('metadata/', MetadataView.as_view(), name='metadata'),
]
