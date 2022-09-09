import base64
import logging
from django.conf import settings
from django.contrib import auth
from django.core.cache import caches
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse_lazy
from django_mitid_auth.loginprovider import LoginProvider
from saml2.cache import Cache
from saml2.client import Saml2Client
from saml2.config import Config
from saml2.metadata import entity_descriptor, metadata_tostring_fix
from saml2.saml import name_id_from_string, NameID
from saml2.validate import valid_instance
from saml2 import md
from saml2 import SamlBase

logger = logging.getLogger(__name__)


class Saml2(LoginProvider):
    whitelist = [
        reverse_lazy(settings.LOGIN_NAMESPACE + ':saml:metadata')
    ]

    session_keys = ('saml', 'user_info')

    claims_map = {
        'PersonName': 'http://schemas.microsoft.com/identity/claims/displayname',
    }

    @staticmethod
    def get_client():
        # This is not pretty, but we need to save the client's state between requests, and it will not be pickled as a whole,
        # so extract the important bits and save/restore them
        cache = caches['saml']
        client_state = cache.get('client_state_cache') or {}
        client_identity = cache.get('client_identity_cache') or {}
        identity_cache = Cache()
        identity_cache._db = client_identity
        client = Saml2Client(
            config=Config().load(settings.SAML),
            identity_cache=identity_cache,
            state_cache=client_state
        )
        return client

    @staticmethod
    def save_client(client):
        cache = caches['saml']
        cache.set('client_state_cache', client.state)
        cache.set('client_identity_cache', client.users.cache._db)

    @classmethod
    def login(cls, request, auth_params=None, login_params=None):
        """Kick off a SAML login request."""
        client = cls.get_client()
        saml_session_id, authrequest_data = client.prepare_for_authenticate(
            entityid=settings.SAML['idp_entity_id'],
            attribute_consuming_service_index='1',
            relay_state="https://test.akap.sullissivik.gl/",
            sigalg=settings.SAML['service']['sp']['signing_algorithm'],
            sign_prepare=False,
            sign=True,
        )
        request.session['AuthNRequestID'] = saml_session_id
        cls.save_client(client)
        return HttpResponse(status=authrequest_data['status'], headers=authrequest_data['headers'])

    @classmethod
    def convert_saml_claims(cls, saml_claims):
        return {
            key: saml_claims[claimKey][0]
            for key, claimKey in cls.claims_map.items()
            if claimKey in saml_claims
        }

    @classmethod
    def clear_session(cls, session):
        for key in ['user_info', 'cvr', 'cpr', 'saml']:
            if key in session:
                del session[key]
        session.save()

    @classmethod
    def log_login(cls, request, saml_auth, saml_claims):
        status = "failed" if saml_auth.get_errors() else "successful"
        log_dict = cls.get_log_dict(request, saml_auth, saml_claims)
        logger.info(f"SAML Login {status}: {str(log_dict)}")

    @classmethod
    def log_logout(cls, request, saml_auth, saml_claims):
        status = "failed" if saml_auth.get_errors() else "successful"
        log_dict = cls.get_log_dict(request, saml_auth, saml_claims)
        logger.info(f"SAML Logout {status}: {str(log_dict)}")

    @classmethod
    def get_log_dict(cls, request, saml_auth, saml_claims=None):
        return {
            'ResponseID': saml_auth.get_last_message_id(),
            'AssertionID': saml_auth.get_last_assertion_id(),
            'InResponseTo': saml_auth.get_last_response_in_response_to(),
            'Errors': saml_auth.get_errors(),
            'ErrorReason': saml_auth.get_last_error_reason(),
            'SubjectNameID': saml_auth.get_nameid(),
            'DjangoSessionID': request.session.session_key,
        }

    @classmethod
    def handle_login_callback(cls, request, success_url):
        """Handle an AuthenticationResponse from the IdP."""
        client = cls.get_client()

        samlresponse = request.POST['SAMLResponse']

        samlresponse = cls.workaround_replace_digest(samlresponse)

        # authn_response is of type saml2.response.AuthnResponse
        authn_response = client.parse_authn_request_response(
            samlresponse,
            'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
        )

        request.session['user_info'] = {
            key: values[0] if type(values) == list and len(values) == 1 else values
            for key, values in authn_response.get_identity().items()
        }
        request.session['saml'] = {
            key: value
            if not isinstance(value, NameID)
            else value.to_string().decode("utf-8")
            for key, value in
            authn_response.session_info().items()
        }
        cls.save_client(client)
        return HttpResponseRedirect(success_url)


    @staticmethod
    def workaround_replace_digest(samlresponse):
        # new_method = ''
        new_method = '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />'
        samlresponse = base64.b64decode(samlresponse).decode("utf-8")
        samlresponse = samlresponse.replace(
            '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />',
            new_method
        )
        samlresponse = base64.b64encode(samlresponse.encode("utf-8"))
        return samlresponse

    @classmethod
    def logout(cls, request):
        """Kick off a SAML logout request."""
        client = cls.get_client()
        idp_entity_id = settings.SAML['idp_entity_id']

        responses = client.global_logout(
            name_id_from_string(
                request.session['saml']['name_id']
            )
        )

        logoutrequest_data = responses[idp_entity_id][1]
        cls.save_client(client)
        return HttpResponse(status=logoutrequest_data['status'], headers=logoutrequest_data['headers'])


    @classmethod
    def handle_logout_callback(cls, request):
        """Handle a LogoutResponse from the IdP."""
        client = cls.get_client()

        logout_response = client.parse_logout_request_response(
            request.GET['SAMLResponse'],
            'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
        )
        session_id, message, headers, msg = client.handle_logout_response(
            response=logout_response
        )

        cls.save_client(client)
        if message == '200 Ok':
            auth.logout(request)
            cls.clear_session(request.session)
            request.session.flush()
            redirect_to = settings.LOGOUT_REDIRECT_URL
            return HttpResponseRedirect(redirect_to)


    @classmethod
    def metadata(cls, request):
        """Render the metadata of this service."""

        cnf = Config().load(settings.SAML)
        eid = entity_descriptor(cnf)

        # cls._set_metadata_encryption_method(eid.spsso_descriptor.key_descriptor)

        valid_instance(eid)
        xmldoc = None
        nspair = {"xs": "http://www.w3.org/2001/XMLSchema"}
        xmldoc = metadata_tostring_fix(eid, nspair, xmldoc)
        return HttpResponse(content=xmldoc.decode("utf-8"), content_type='text/xml')

    @staticmethod
    def _set_metadata_encryption_method(key_descriptors):
        if type(key_descriptors) != list:
            key_descriptors = [key_descriptors]
        for key_descriptor in key_descriptors:
            if key_descriptor.use == 'encryption':
                enc1 = md.EncryptionMethod()
                enc1.algorithm = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
                enc2 = EncryptionMethod()
                enc2.algorithm = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
                dig = DigestMethod()
                dig.algorithm = "http://www.w3.org/2000/09/xmldsig#sha1"
                enc2.digest_method = dig
                key_descriptor.encryption_method = [enc1, enc2]

    """
    @classmethod
    def _prepare_django_request(cls, request):

        # Extract data from a Django request in the way that OneLogin expects.
        result = {
            'https': 'on' if request.is_secure() else 'off',
            'http_host': request.META.get('HTTP_HOST', '127.0.0.1'),
            'script_name': request.META['PATH_INFO'],
            'server_port': request.META['SERVER_PORT'],
            'get_data': request.GET.copy(),
            'post_data': request.POST.copy()
        }
        if cls.saml_settings['destination_host'] is not None:
            result['http_host'] = cls.saml_settings['destination_host']
        if cls.saml_settings['destination_https'] is not None:
            result['https'] = cls.saml_settings['destination_https']
            result['server_port'] = '443' if result['https'] else '80'
        if cls.saml_settings['destination_port'] is not None:
            result['server_port'] = cls.saml_settings['destination_port']
        return result
    """

class DigestMethodType(SamlBase):
    c_tag = 'DigestMethodType'
    c_namespace = md.NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_attributes['Algorithm'] = ('algorithm', 'anyURI', True)


class DigestMethod(DigestMethodType):
    c_tag = 'DigestMethod'
    c_namespace = md.NAMESPACE
    c_children = DigestMethodType.c_children.copy()
    c_attributes = DigestMethodType.c_attributes.copy()
    c_child_order = DigestMethodType.c_child_order[:]
    c_cardinality = DigestMethodType.c_cardinality.copy()


class EncryptionMethod(md.EncryptionMethod):
    c_children = {
        **md.EncryptionMethod.c_children.copy(),
        '{http://www.w3.org/2001/04/xmlenc#}DigestMethod': ('digest_method', DigestMethod)
    }
    c_child_order = md.EncryptionMethod.c_child_order[:]
    c_child_order.append('digest_method')
