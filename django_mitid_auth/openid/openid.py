import logging

from django.conf import settings
from django.core.exceptions import SuspiciousOperation
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse_lazy
from jwkest.jwk import rsa_load
from oic.oauth2 import ErrorResponse
from oic.oic import Client, rndstr
from oic.oic.message import AuthorizationResponse, RegistrationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.keyio import KeyBundle

from django_mitid_auth.exceptions import LoginException
from django_mitid_auth.loginprovider import LoginProvider

logger = logging.getLogger(__name__)


class OpenId(LoginProvider):
    open_id_settings = {}
    kc_rsa = None
    client_cert = None
    session_data_key = getattr(settings, "LOGIN_SESSION_DATA_KEY", None) or "user_info"
    if getattr(settings, "OPENID_CONNECT", None) and settings.OPENID_CONNECT.get(
        "enabled", True
    ):
        # if openID is enabled setup the key bundle and client_cert
        open_id_settings = settings.OPENID_CONNECT
        key = rsa_load(open_id_settings["private_key"])
        kc_rsa = KeyBundle(
            [
                {"key": key, "kty": "RSA", "use": "ver"},
                {"key": key, "kty": "RSA", "use": "sig"},
            ]
        )

        client_cert = (
            open_id_settings["client_certificate"],
            open_id_settings["private_key"],
        )

    whitelist = [
        reverse_lazy(settings.LOGIN_NAMESPACE + ":oid:login-callback"),
        reverse_lazy(settings.LOGIN_NAMESPACE + ":oid:logout"),
        # Temporary fallback until we get MitID rolled out everywhere
        reverse_lazy(settings.LOGIN_NAMESPACE + ":oid:login-callback-2"),
        reverse_lazy(settings.LOGIN_NAMESPACE + ":oid:logout-callback"),
        reverse_lazy(settings.LOGIN_NAMESPACE + ":oid-2:login-callback"),
        reverse_lazy(settings.LOGIN_NAMESPACE + ":oid-2:logout"),
        reverse_lazy(settings.LOGIN_NAMESPACE + ":oid-2:login-callback-2"),
        reverse_lazy(settings.LOGIN_NAMESPACE + ":oid-2:logout-callback"),
    ]

    @classmethod
    def enabled(cls):
        return cls.open_id_settings.get("enabled", False)

    @classmethod
    def authenticate(cls, request):
        return None  # If the user has nothing in the session, we just don't log him in - there's no SSO cookie that we may want to check

    @classmethod
    def clear_session(cls, session):
        for key in [
            "oid_state",
            "oid_nonce",
            cls.session_data_key,
            "login_method",
            "has_checked_cvr",
        ]:
            if key in session:
                del session[key]
        session.save()

    @classmethod
    def login(cls, request):
        client = Client(
            client_authn_method=CLIENT_AUTHN_METHOD, client_cert=OpenId.client_cert
        )
        provider_info = client.provider_config(  # noqa
            OpenId.open_id_settings["issuer"]
        )
        client_reg = RegistrationResponse(
            **{
                "client_id": OpenId.open_id_settings["client_id"],
                "redirect_uris": [OpenId.open_id_settings["redirect_uri"]],
            }
        )
        client.store_registration_info(client_reg)

        state = rndstr(32)
        nonce = rndstr(32)
        request_args = {
            "response_type": "code",
            "scope": cls.open_id_settings["scope"],
            "client_id": cls.open_id_settings["client_id"],
            "redirect_uri": cls.open_id_settings["redirect_uri"],
            "state": state,
            "nonce": nonce,
        }

        request.session["oid_state"] = state
        request.session["oid_nonce"] = nonce
        request.session["login_method"] = "openid"
        auth_req = client.construct_AuthorizationRequest(request_args=request_args)
        login_url = auth_req.request(client.authorization_endpoint)
        return HttpResponseRedirect(login_url)

    @classmethod
    def handle_login_callback(cls, request, success_url):
        nonce = request.session.get("oid_nonce")
        if nonce:
            # Make sure that nonce is not used twice
            del request.session["oid_nonce"]
        else:
            if "oid_state" in request.session:
                del request.session[
                    "oid_state"
                ]  # if nonce was missing ensure oid_state is too
            logger.exception(SuspiciousOperation("Session `oid_nonce` does not exist!"))
            raise LoginException({"missing": "oid_nonce"})

        if "oid_state" not in request.session:
            logger.exception(SuspiciousOperation("Session `oid_state` does not exist!"))
            raise LoginException({"missing": "oid_state"})

        client = Client(
            client_authn_method=CLIENT_AUTHN_METHOD, client_cert=OpenId.client_cert
        )
        client.keyjar[""] = OpenId.kc_rsa

        client_configuration = {
            "client_id": cls.open_id_settings["client_id"],
            "token_endpoint_auth_method": "private_key_jwt",
        }

        client.store_registration_info(client_configuration)

        aresp = client.parse_response(
            AuthorizationResponse,
            info=request.META["QUERY_STRING"],
            sformat="urlencoded",
        )

        if isinstance(aresp, ErrorResponse):
            # we got an error from the OP
            del request.session["oid_state"]
            logger.error("Got ErrorResponse %s" % str(aresp.to_dict()))
            raise LoginException(aresp.to_dict())

        else:
            # we got a valid response
            if not aresp.get("state", None):
                del request.session["oid_state"]
                logger.error(
                    "did not receive state from OP: {}".format(aresp.to_dict())
                )
                raise LoginException({"Aresp.state": None, **aresp.to_dict()})

            if aresp["state"] != request.session["oid_state"]:
                del request.session["oid_state"]
                logger.exception(
                    SuspiciousOperation(
                        "Session `oid_state` does not match the OID callback state"
                    )
                )
                raise LoginException(
                    {
                        "mismatch": "Session `oid_state` does not match the OID callback state"
                    }
                )

            provider_info = client.provider_config(  # noqa
                cls.open_id_settings["issuer"]
            )
            logger.debug("provider info: {}".format(client.config))

            request_args = {
                "code": aresp["code"],
                "redirect_uri": cls.open_id_settings["redirect_uri"],
            }

            resp = client.do_access_token_request(
                state=aresp["state"],
                scope=cls.open_id_settings["scope"],
                request_args=request_args,
                authn_method="private_key_jwt",
                authn_endpoint="token",
            )

            if isinstance(resp, ErrorResponse):
                del request.session["oid_state"]
                logger.error(
                    "Error received from headnet: {}".format(str(ErrorResponse))
                )
                raise LoginException(aresp.to_dict())
            else:
                respdict = resp.to_dict()
                their_nonce = respdict["id_token"]["nonce"]
                if their_nonce != nonce:
                    del request.session["oid_state"]
                    logger.error(
                        "Nonce mismatch: Token service responded with incorrect nonce (expected %s, got %s)"
                        % (nonce, their_nonce)
                    )
                    raise LoginException(
                        {"Nonce mismatch": "Got incorrect nonce from token server"}
                    )
                request.session["access_token_data"] = respdict
                userinfo = client.do_user_info_request(
                    state=request.session["oid_state"]
                )
                user_info_dict = userinfo.to_dict()

                keys = list(user_info_dict.keys())
                for key in keys:
                    if key.lower() != key:
                        user_info_dict[key.lower()] = user_info_dict[key]
                request.session[cls.session_data_key] = user_info_dict

                request.session["raw_id_token"] = resp["id_token"].jwt
                # always delete the state so it is not reused
                del request.session["oid_state"]
                # after the oauth flow is done and we have the user_info redirect to the original page or the frontpage
                return HttpResponseRedirect(success_url)

    @classmethod
    def logout(cls, request):
        # See also doc here: https://github.com/IdentityServer/IdentityServer4/blob/master/docs/endpoints/endsession.rst
        client = Client(
            client_authn_method=CLIENT_AUTHN_METHOD, client_cert=OpenId.client_cert
        )
        client.store_registration_info(
            RegistrationResponse(
                **{
                    "client_id": cls.open_id_settings["client_id"],
                    "redirect_uris": [cls.open_id_settings["front_channel_logout_uri"]],
                    "post_logout_redirect_uris": [
                        cls.open_id_settings["post_logout_redirect_uri"]
                    ],
                }
            )
        )
        request_args = {
            "scope": cls.open_id_settings["scope"],
            "client_id": cls.open_id_settings["client_id"],
            "redirect_uri": cls.open_id_settings["front_channel_logout_uri"],
            "id_token_hint": request.session.get("raw_id_token"),
            "post_logout_redirect_uri": cls.open_id_settings[
                "post_logout_redirect_uri"
            ],
            "state": rndstr(32),
        }
        auth_req = client.construct_EndSessionRequest(
            request_args=request_args,
            id_token=request.session["access_token_data"]["id_token"],
        )
        logout_url = auth_req.request(cls.open_id_settings["logout_uri"])
        OpenId.clear_session(request.session)
        return HttpResponseRedirect(logout_url)

    @classmethod
    def handle_logout_callback(cls, request):
        their_sid = request.GET.get("sid")
        try:
            our_sid = request.session["access_token_data"]["id_token"]["sid"]
            if their_sid != our_sid:
                logger.info(
                    "Logout SID mismatch (ours: %s, theirs: %s)" % (our_sid, their_sid)
                )
        except KeyError as e:
            logger.exception(e)

        # according to the specs this is rendered in a iframe when the user triggers a logout from OP`s side
        # do a total cleanup and delete everything related to openID
        OpenId.clear_session(request.session)
        return HttpResponse("")
