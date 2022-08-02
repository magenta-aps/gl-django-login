from django.conf import settings
from django.utils.module_loading import import_string


def loginprovider():
    return import_string(settings.LOGIN_PROVIDER_CLASS or 'django_mitid_auth.dummy.dummy.DummyProvider')
