import logging
from django.conf import settings
from django.contrib import auth
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseServerError
from django.urls import reverse_lazy
from django.core.cache import caches
from django_mitid_auth.loginprovider import LoginProvider
from saml2.config import Config
from saml2.metadata import entity_descriptor, metadata_tostring_fix
from saml2.client import Saml2Client
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from base64 import b64decode
from saml2.attribute_converter import AttributeConverter
import six
from saml2.saml import NAME_FORMAT_UNSPECIFIED, name_id_from_string, NameID, NameIDType_
from saml2.cache import Cache

import defusedxml.ElementTree
from saml2.validate import valid_instance
logger = logging.getLogger(__name__)


class Saml2(LoginProvider):
    """
    Borrows heavily from python3-saml-django
    https://pypi.org/project/python3-saml-django/

    We do this because we don't map logins to preexisting users in django, or even create users as they log in
    Instead we save their details (CPR, CVR etc.) in the session and clear the session on logout
    python3-saml-django couldn't do this for us, so we roll our own
    """

    saml_settings = settings.SAML
    # onelogin_settings = OneLogin_Saml2_Settings(saml_settings, saml_settings['base_directory'])

    whitelist = [
        reverse_lazy(settings.LOGIN_NAMESPACE + ':saml:metadata')
    ]

    session_keys = ('saml', 'user_info')

    claims_map = {
        'PersonName': 'http://schemas.microsoft.com/identity/claims/displayname',
    }

    @staticmethod
    def client():
        cache = caches['saml']
        client_state = cache.get('client_state_cache') or {}
        client_identity = cache.get('client_identity_cache') or {}
        identity_cache = Cache()
        identity_cache._db = client_identity
        client = Saml2Client(config=Config().load(settings.SAML), identity_cache=identity_cache, state_cache=client_state)
        return client

    @staticmethod
    def save_client(client):
        cache = caches['saml']
        cache.set('client_state_cache', client.state)
        cache.set('client_identity_cache', client.users.cache._db)

    @classmethod
    def login(cls, request, auth_params=None, login_params=None):
        """Kick off a SAML login request."""
        client = cls.client()

        saml_session_id, authrequest_data = client.prepare_for_authenticate(entityid=settings.SAML['idp_entity_id'])
        print(authrequest_data)
        request.session['AuthNRequestID'] = saml_session_id
        cls.save_client(client)
        return HttpResponse(status=authrequest_data['status'], headers=authrequest_data['headers'])
        """
        if auth_params is None:
            auth_params = {}
        if login_params is None:
            login_params = {}
        req = Saml2._prepare_django_request(request)
        saml_auth = OneLogin_Saml2_Auth(req, old_settings=cls.onelogin_settings, **auth_params)
        if 'back' in request.GET:
            redirect_to = OneLogin_Saml2_Utils.get_self_url(req) + request.GET['back']
        else:
            redirect_to = OneLogin_Saml2_Utils.get_self_url(req) + cls.saml_settings['login_redirect']
        url = saml_auth.login(redirect_to, **login_params)
        logger.info(saml_auth.get_last_request_xml())
        request.session['AuthNRequestID'] = saml_auth.get_last_request_id()
        return HttpResponseRedirect(url)
        """

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
        client = cls.client()

        # authn_response is of type saml2.response.AuthnResponse
        authn_response = client.parse_authn_request_response(
            request.POST['SAMLResponse'],
            'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
        )

        request.session['user_info'] = {
            key: values[0]
            if type(values) == list and len(values) == 1
            else values
            for key, values in authn_response.get_identity().items()
        }
        print(request.session['user_info'])
        request.session['saml'] = {
            key: value
            if not isinstance(value, NameID)
            else value.to_string().decode("utf-8")
            for key, value in
            authn_response.session_info().items()
        }
        print(request.session['saml'])
        cls.save_client(client)
        return HttpResponseRedirect(success_url)
        """
        if request.method != 'POST':
            return HttpResponse('Method not allowed.', status=405)
        try:
            req = cls._prepare_django_request(request)
            saml_auth = OneLogin_Saml2_Auth(req, old_settings=cls.onelogin_settings)

            request_id = request.session.get('AuthNRequestID', None)
            saml_auth.process_response(request_id=request_id)

            errors = saml_auth.get_errors()
            saml_claims = cls.convert_saml_claims(saml_auth.get_attributes())  # empty dict if there are errors

            cls.log_login(request, saml_auth, saml_claims)
            if not errors:
                request.session['saml'] = {
                    'nameId': saml_auth.get_nameid(),
                    'nameIdFormat': saml_auth.get_nameid_format(),
                    'nameIdNameQualifier': saml_auth.get_nameid_nq(),
                    'nameIdSPNameQualifier': saml_auth.get_nameid_spnq(),
                    'sessionIndex': saml_auth.get_session_index(),
                }
                request.session['user_info'] = saml_claims
                request.session['cvr'] = request.session['user_info'].get('CVR')

                # This data is used during Single Log Out
                if 'RelayState' in req['post_data'] \
                        and OneLogin_Saml2_Utils.get_self_url(req) != req['post_data']['RelayState']:
                    url = saml_auth.redirect_to(req['post_data']['RelayState'])
                    return HttpResponseRedirect(url)
                else:
                    return HttpResponseRedirect(success_url)
            logger.exception(saml_auth.get_last_error_reason())
            return HttpResponse(content="Invalid Response", status=400)
        except PermissionDenied:
            raise
        except Exception as e:
            logger.exception(e)
            return HttpResponse(content="Invalid Response", status=400)
        """

    @classmethod
    def logout(cls, request):
        """Kick off a SAML logout request."""
        client = cls.client()
        idp_entity_id = settings.SAML['idp_entity_id']

        # responses = client.global_logout(name_id_from_string(request.session['saml']['name_id']))
        responses = client.do_logout(
            name_id_from_string(request.session['saml']['name_id']),
            [idp_entity_id],
            reason='',
            expire=None,
            sign=None,
            sign_alg=None,
            digest_alg=None,
        )

        print(f"responses: {responses}")
        logoutrequest_data = responses[idp_entity_id][1]
        print(logoutrequest_data)
        cls.save_client(client)
        return HttpResponse(status=logoutrequest_data['status'], headers=logoutrequest_data['headers'])
        """
        req = cls._prepare_django_request(request)
        saml_auth = OneLogin_Saml2_Auth(req, old_settings=cls.onelogin_settings)
        (name_id, session_index, name_id_format, name_id_nq, name_id_spnq) = (None, None, None, None, None)
        saml_session = request.session.get('saml', None)
        if saml_session:
            name_id = saml_session.get('nameId', None)
            session_index = saml_session.get('sessionIndex', None)
            name_id_format = saml_session.get('nameIdFormat', None)
            name_id_nq = saml_session.get('nameIdNameQualifier', None)
            name_id_spnq = saml_session.get('nameIdSPNameQualifier', None)
        url = saml_auth.logout(
            name_id=name_id, session_index=session_index, nq=name_id_nq, name_id_format=name_id_format, spnq=name_id_spnq,
            return_to=OneLogin_Saml2_Utils.get_self_url(req) + cls.saml_settings['logout_redirect']
        )
        request.session['LogoutRequestID'] = saml_auth.get_last_request_id()
        return HttpResponseRedirect(url)
        """

    @classmethod
    def handle_logout_callback(cls, request):
        """Handle a LogoutResponse from the IdP."""
        client = cls.client()

        # client.handle_logout_request(
        #     request=request.GET['SAMLResponse'],  # TODO: POST or GET?
        #     name_id=name_id_from_string(request.session['saml']['name_id']),
        #     binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'  # POST or Redirect?
        # )
        logout_response = client.parse_logout_request_response(
            request.GET['SAMLResponse'],
            'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
        )
        r = client.handle_logout_response(
            response=logout_response
        )
        print(r)
        cls.save_client(client)

        """
        if request.method != 'GET':
            return HttpResponse('Method not allowed.', status=405)
        req = cls._prepare_django_request(request)
        saml_auth = OneLogin_Saml2_Auth(req, old_settings=cls.onelogin_settings)
        request_id = request.session.get('LogoutRequestID', None)
        try:
            saml_claims = request.session.get('user_info')
            url = saml_auth.process_slo(request_id=request_id, delete_session_cb=lambda: request.session.flush())
            errors = saml_auth.get_errors()
            cls.log_logout(request, saml_auth, saml_claims)
            if not errors:
                auth.logout(request)
                cls.clear_session(request.session)
                redirect_to = url or cls.saml_settings['logout_redirect']
                return HttpResponseRedirect(redirect_to)
            else:
                logger.exception(saml_auth.get_last_error_reason())
                return HttpResponse("Invalid request", status=400)
        except UnicodeDecodeError:
            # Happens when someone messes with the response in the URL.  No need to log an exception.
            return HttpResponse("Invalid request - Unable to decode response", status=400)
        except Exception as e:
            logger.exception(e)
            return HttpResponse("Invalid request", status=400)
        """

    @classmethod
    def metadata(cls, request):
        """Render the metadata of this service."""

        cnf = Config().load(settings.SAML)
        eid = entity_descriptor(cnf)

        valid_instance(eid)
        xmldoc = None
        nspair = {"xs": "http://www.w3.org/2001/XMLSchema"}
        xmldoc = metadata_tostring_fix(eid, nspair, xmldoc)
        print(xmldoc.decode("utf-8"))
        return HttpResponse(content=xmldoc.decode("utf-8"), content_type='text/xml')
        """
        metadata_dict = cls.onelogin_settings.get_sp_metadata()
        errors = cls.onelogin_settings.validate_metadata(metadata_dict)
        if len(errors) == 0:
            resp = HttpResponse(content=metadata_dict, content_type='text/xml')
        else:
            resp = HttpResponseServerError(content=', '.join(errors))
        return resp
        """

    @classmethod
    def _prepare_django_request(cls, request):

        """Extract data from a Django request in the way that OneLogin expects."""
        """
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
