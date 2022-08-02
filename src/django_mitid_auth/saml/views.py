from django.http.response import Http404
from django.views.generic.base import View
from django_mitid_auth import login_provider_class
from django_mitid_auth.saml.saml2 import Saml2


class MetadataView(View):
    def get(self, request):
        provider = login_provider_class()
        if issubclass(provider, Saml2):
            return provider.metadata(request)
        else:
            raise Http404
