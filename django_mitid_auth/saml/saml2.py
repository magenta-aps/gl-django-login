import base64
import logging

from django.conf import settings
from django.contrib import auth
from django.contrib.sessions.backends.base import SessionBase
from django.core.cache import caches
from django.core.exceptions import BadRequest
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import redirect
from django.urls import reverse, reverse_lazy
from requests import Response
from saml2 import SamlBase, md
from saml2.cache import Cache
from saml2.client import Saml2Client
from saml2.config import Config
from saml2.metadata import entity_descriptor, metadata_tostring_fix
from saml2.response import AuthnResponse
from saml2.saml import NameID, name_id_from_string
from saml2.validate import ResponseLifetimeExceed, valid_instance
from xmltodict import parse as xml_to_dict

from django_mitid_auth.loginprovider import LoginProvider

logger = logging.getLogger(__name__)


class Saml2(LoginProvider):
    session_data_key = getattr(settings, "LOGIN_SESSION_DATA_KEY", None) or "user_info"
    whitelist = [reverse_lazy(settings.LOGIN_NAMESPACE + ":saml:metadata")]

    session_keys = ("saml", session_data_key)

    claims_map = {
        "PersonName": "http://schemas.microsoft.com/identity/claims/displayname",
    }

    cached_metadata = None

    @classmethod
    def saml_settings(cls) -> dict:
        assert type(settings.SAML) is dict
        return settings.SAML

    @classmethod
    def get_client(cls) -> Saml2Client:
        # This is not pretty, but we need to save the client's state between requests,
        # and it will not be pickled as a whole,
        # so extract the important bits and save/restore them
        cache = caches["saml"]
        client_state = cache.get("client_state_cache") or {}
        client_identity = cache.get("client_identity_cache") or {}
        identity_cache = Cache()
        identity_cache._db = client_identity
        client = Saml2Client(
            config=Config().load(cls.saml_settings()),
            identity_cache=identity_cache,
            state_cache=client_state,
        )
        return client

    @staticmethod
    def save_client(client: Saml2Client):
        cache = caches["saml"]
        cache.set("client_state_cache", client.state)
        cache.set("client_identity_cache", client.users.cache._db)

    @classmethod
    def login(
        cls, request: HttpRequest, auth_params: dict | None = None
    ) -> HttpResponse:
        """Kick off a SAML login request."""
        client: Saml2Client = cls.get_client()
        saml_settings = cls.saml_settings()
        if auth_params is None:
            auth_params = {}

        saml_session_id, authrequest_data = client.prepare_for_authenticate(
            entityid=saml_settings["idp_entity_id"],
            attribute_consuming_service_index="1",
            sigalg=saml_settings["service"]["sp"]["signing_algorithm"],
            sign_prepare=False,
            sign=True,
            provider_name=base64.b64encode(
                saml_settings["name"].encode("utf-8")
            ).decode("ascii"),
            **auth_params,
        )
        caches["saml"].set("message_id__" + saml_session_id, True)
        request.session["AuthNRequestID"] = saml_session_id
        cls.save_client(client)
        return HttpResponse(
            status=authrequest_data["status"], headers=authrequest_data["headers"]
        )

    @classmethod
    def clear_session(cls, session: SessionBase):
        extra_session_keys = getattr(settings, "LOGIN_SESSION_KEYS", [])
        for key in [cls.session_data_key, "cvr", "cpr", "saml"] + extra_session_keys:
            if key in session:
                del session[key]
        session.save()

    @classmethod
    def log_login(cls, request: HttpRequest, saml_auth, saml_claims):
        status = "failed" if saml_auth.get_errors() else "successful"
        log_dict = cls.get_log_dict(request, saml_auth, saml_claims)
        logger.info(f"SAML Login {status}: {str(log_dict)}")

    @classmethod
    def log_logout(cls, request: HttpRequest, saml_auth, saml_claims):
        status = "failed" if saml_auth.get_errors() else "successful"
        log_dict = cls.get_log_dict(request, saml_auth, saml_claims)
        logger.info(f"SAML Logout {status}: {str(log_dict)}")

    @classmethod
    def get_log_dict(cls, request: HttpRequest, saml_auth, saml_claims=None):
        return {
            "ResponseID": saml_auth.get_last_message_id(),
            "AssertionID": saml_auth.get_last_assertion_id(),
            "InResponseTo": saml_auth.get_last_response_in_response_to(),
            "Errors": saml_auth.get_errors(),
            "ErrorReason": saml_auth.get_last_error_reason(),
            "SubjectNameID": saml_auth.get_nameid(),
            "DjangoSessionID": request.session.session_key,
        }

    @classmethod
    def handle_login_callback(
        cls, request: HttpRequest, success_url: str
    ) -> HttpResponse:
        """Handle an AuthenticationResponse from the IdP."""
        client = cls.get_client()

        samlresponse = request.POST["SAMLResponse"]
        samlresponse = cls.workaround_replace_digest(samlresponse)
        namespace = settings.LOGIN_NAMESPACE

        try:
            authn_response: AuthnResponse = client.parse_authn_request_response(
                samlresponse, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            )
            in_response_to: str | None = authn_response.in_response_to
            if in_response_to is None:
                raise BadRequest("Missing InResponseTo")
            if caches["saml"].get("message_id__" + in_response_to):
                caches["saml"].set("message_id__" + in_response_to, None)
            else:
                return redirect(
                    getattr(
                        settings,
                        "LOGIN_REPEATED_URL",
                        reverse(f"{namespace}:saml:login-repeat"),
                    )
                )
        except ResponseLifetimeExceed:
            return redirect(
                getattr(
                    settings,
                    "LOGIN_TIMEOUT_URL",
                    reverse(f"{namespace}:saml:login-timeout"),
                )
            )
        request.session[cls.session_data_key] = {
            key: values[0] if type(values) is list and len(values) == 1 else values
            for key, values in authn_response.get_identity().items()
        }
        request.session["saml"] = {
            key: (
                value
                if not isinstance(value, NameID)
                else value.to_string().decode("utf-8")
            )
            for key, value in authn_response.session_info().items()
        }
        cls.save_client(client)
        logger.info(
            "AuthnResponse id: %s, Sikringsniveau: %s, IdentitetSikringsniveau: %s, AuthentikeringsSikringsniveau: %s, "
            "InResponseTo: %s, SubjectNameId: %s, CPR: %s, CVR: %s, Privilegier: %s, DjangoSessionId: %s",
            authn_response.id(),
            request.session["saml"]["ava"].get("levelofassurance"),
            request.session["saml"]["ava"].get("identityassurancelevel"),
            request.session["saml"]["ava"].get("authenticationassurancelevel"),
            authn_response.in_response_to,
            authn_response.name_id,
            request.session["saml"]["ava"].get("cpr"),
            request.session["saml"]["ava"].get("cvr"),
            (
                [
                    xml_to_dict(base64.b64decode(p).decode("utf-8"))
                    for p in request.session["saml"]["ava"]["privilege"]
                    if p
                ]
                if "privilege" in request.session["saml"]["ava"]
                else None
            ),
            request.session.session_key,
        )
        if not set(request.session["saml"]["ava"].get("levelofassurance")).intersection(
            {"Substantial", "High"}
        ):
            return redirect(
                getattr(
                    settings,
                    "LOGIN_ASSURANCE_LEVEL_URL",
                    reverse(f"{namespace}:saml:login-assurance"),
                )
            )
        if request.session[cls.session_data_key].get("cpr") or request.session[
            cls.session_data_key
        ].get("cvr"):
            return HttpResponseRedirect(success_url)
        else:
            return redirect(
                getattr(
                    settings,
                    "LOGIN_NO_CPRCVR_URL",
                    reverse(f"{namespace}:saml:login-no-cprcvr"),
                )
            )

    @staticmethod
    def workaround_replace_digest(samlresponse):
        # new_method = ''
        new_method = (
            '<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />'
        )
        samlresponse = base64.b64decode(samlresponse).decode("utf-8")
        samlresponse = samlresponse.replace(
            '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />',
            new_method,
        )
        samlresponse = base64.b64encode(samlresponse.encode("utf-8"))
        return samlresponse

    @classmethod
    def logout(cls, request: HttpRequest):
        """Kick off a SAML logout request."""
        client: Saml2Client = cls.get_client()
        saml_settings = cls.saml_settings()
        idp_entity_id = saml_settings["idp_entity_id"]
        if "saml" in request.session:
            logger.info(
                "Sikringsniveau: %s, IdentitetSikringsniveau: %s, AuthentikeringsSikringsniveau: %s, "
                "SubjectNameId: %s, CPR: %s, CVR: %s, Privilegier: %s, DjangoSessionId: %s",
                request.session["saml"]["ava"].get("levelofassurance"),
                request.session["saml"]["ava"].get("identityassurancelevel"),
                request.session["saml"]["ava"].get("authenticationassurancelevel"),
                request.session["saml"].get("name_id"),
                request.session["saml"]["ava"].get("cpr"),
                request.session["saml"]["ava"].get("cvr"),
                (
                    [
                        xml_to_dict(base64.b64decode(p).decode("utf-8"))
                        for p in request.session["saml"]["ava"]["privilege"]
                        if p
                    ]
                    if "privilege" in request.session["saml"]["ava"]
                    else None
                ),
                request.session.session_key,
            )
            try:
                responses = client.global_logout(
                    name_id_from_string(request.session["saml"]["name_id"]),
                    sign_alg=saml_settings["service"]["sp"]["signing_algorithm"],
                    sign=True,
                )
                if isinstance(responses, Response):
                    return responses
                if (
                    isinstance(responses, tuple)
                    and responses[1] == "504 Gateway Timeout"
                ):
                    return HttpResponse(status=504, content=responses[1])
                if isinstance(responses, dict):
                    logoutrequest_data = responses[idp_entity_id][1]
                    cls.save_client(client)
                    return HttpResponse(
                        status=logoutrequest_data["status"],
                        headers=logoutrequest_data["headers"],
                    )
            except KeyError:
                pass
        auth.logout(request)
        cls.clear_session(request.session)
        request.session.flush()
        redirect_to = getattr(
            settings, "LOGOUT_MITID_REDIRECT_URL", settings.LOGOUT_REDIRECT_URL
        )
        return HttpResponseRedirect(redirect_to)

    @classmethod
    def handle_logout_callback(cls, request: HttpRequest) -> HttpResponse | None:
        """Handle a LogoutResponse from the IdP."""
        client: Saml2Client = cls.get_client()

        if "SAMLResponse" in request.GET:
            logout_response = client.parse_logout_request_response(
                request.GET["SAMLResponse"],
                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            )
            session_id, message, headers, msg = client.handle_logout_response(
                response=logout_response
            )

            cls.save_client(client)
            if message == "200 Ok":
                auth.logout(request)
                cls.clear_session(request.session)
                request.session.flush()
                redirect_to = getattr(
                    settings, "LOGOUT_MITID_REDIRECT_URL", settings.LOGOUT_REDIRECT_URL
                )
                return HttpResponseRedirect(redirect_to)
            else:
                raise BadRequest(f"Logout failed: {msg}")

        elif "SAMLRequest" in request.GET:
            saml_settings = cls.saml_settings()

            if "saml" in request.session:
                logoutrequest_data = client.handle_logout_request(
                    request.GET["SAMLRequest"],
                    name_id=name_id_from_string(request.session["saml"]["name_id"]),
                    binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                    sign=True,
                    sign_alg=saml_settings["service"]["sp"]["signing_algorithm"],
                    sigalg=request.GET["SigAlg"],
                    signature=request.GET["Signature"],
                    relay_state=None,
                )
            else:
                raise BadRequest("Attempt to log out without a SAML session")

            if logoutrequest_data["status"] in (301, 302, 303):
                auth.logout(request)
                cls.clear_session(request.session)
                request.session.flush()

            return HttpResponse(
                status=logoutrequest_data["status"],
                headers=logoutrequest_data["headers"],
            )
        else:
            raise BadRequest("No SAMLResponse or SAMLRequest in request")

    @classmethod
    def metadata(cls, request: HttpRequest) -> HttpResponse:
        if cls.cached_metadata is None:
            # Render the metadata of this service.
            cnf = Config().load(cls.saml_settings())
            eid = entity_descriptor(cnf)
            cls._set_metadata_encryption_method(eid.spsso_descriptor.key_descriptor)
            valid_instance(eid)
            xmldoc = None
            nspair = {"xs": "http://www.w3.org/2001/XMLSchema"}
            xmldoc = metadata_tostring_fix(eid, nspair, xmldoc)
            cls.cached_metadata = xmldoc.decode("utf-8")
        return HttpResponse(content=cls.cached_metadata, content_type="text/xml")

    @staticmethod
    def _set_metadata_encryption_method(key_descriptors):
        if type(key_descriptors) is not list:
            key_descriptors = [key_descriptors]
        for key_descriptor in key_descriptors:
            if key_descriptor.use == "encryption":
                enc1 = md.EncryptionMethod()
                enc1.algorithm = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
                enc2 = EncryptionMethod()
                enc2.algorithm = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
                dig = DigestMethod()
                dig.algorithm = "http://www.w3.org/2000/09/xmldsig#sha1"
                enc2.digest_method = dig
                key_descriptor.encryption_method = [enc1, enc2]


class DigestMethodType(SamlBase):
    c_tag = "DigestMethodType"
    c_namespace = md.NAMESPACE
    c_children = SamlBase.c_children.copy()
    c_attributes = SamlBase.c_attributes.copy()
    c_child_order = SamlBase.c_child_order[:]
    c_cardinality = SamlBase.c_cardinality.copy()
    c_attributes["Algorithm"] = ("algorithm", "anyURI", True)


class DigestMethod(DigestMethodType):
    c_tag = "DigestMethod"
    c_namespace = "http://www.w3.org/2000/09/xmldsig#"
    c_children = DigestMethodType.c_children.copy()
    c_attributes = DigestMethodType.c_attributes.copy()
    c_child_order = DigestMethodType.c_child_order[:]
    c_cardinality = DigestMethodType.c_cardinality.copy()


class EncryptionMethod(md.EncryptionMethod):
    c_children = {
        **md.EncryptionMethod.c_children.copy(),
        "{http://www.w3.org/2000/09/xmldsig#}DigestMethod": (
            "digest_method",
            DigestMethod,
        ),
    }
    c_child_order = md.EncryptionMethod.c_child_order[:]
    c_child_order.append("digest_method")
