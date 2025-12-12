import base64
import copy
import os

from xmltodict import parse as xml_to_dict

import django_mitid_auth.saml.oiosaml_attributemaps.attributemap
from django_mitid_auth.saml.saml2 import Saml2


class OIOSaml(Saml2):
    @classmethod
    def saml_settings(cls):
        """
        Example settings from django.conf.settings:
        {
            "enabled": True,
            "debug": 1,
            "entityid": "https://test.akap.sullissivik.gl/saml/metadata/",
            "idp_entity_id": "https://saml.test-nemlog-in.dk/",
            "name": "AKAP Test",
            "description": "AKAP Test",
            "verify_ssl_cert": False,
            "metadata": {  # IdP Metadata
                "remote": [{"url": "https://tu.nemlog-in.dk/media/konm1nal/oio_saml_3_integrationstest-idp-metadata-xml.txt"}]
            },
            "service": {
                "sp": {
                    "name": "AKAP Test",
                    "hide_assertion_consumer_service": False,
                    "endpoints": {
                        "assertion_consumer_service": [
                            (
                                "https://test.akap.sullissivik.gl/login/callback/",
                                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                            )
                        ],
                        "single_logout_service": [
                            (
                                "https://test.akap.sullissivik.gl/logout/callback/",
                                "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                            ),
                        ],
                    },
                    "authn_requests_signed": True,
                    "want_assertions_signed": False,
                    "want_response_signed": False,
                    "required_attributes": [
                        "https://data.gov.dk/model/core/specVersion",
                        "https://data.gov.dk/concept/core/nsis/loa",
                        "https://data.gov.dk/model/core/eid/professional/orgName",
                        "https://data.gov.dk/model/core/eid/cprNumber",
                        "https://data.gov.dk/model/core/eid/fullName",
                    ],
                    "optional_attributes": [
                        "https://data.gov.dk/model/core/eid/professional/cvr",
                    ],
                    "name_id_format": [
                        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                    ],
                    "allow_unsolicited": False,
                    "signing_algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                }
            },
            "key_file": "/ssl/mitid_sp.key",
            "cert_file": "/ssl/mitid_sp.cert",
            "encryption_keypairs": [
                {
                    "key_file": "/ssl/mitid_sp.key",
                    "cert_file": "/ssl/mitid_sp.cert",
                },
            ],
            "xmlsec_binary": "/usr/bin/xmlsec1",
            "delete_tmpfiles": True,
            "organization": {
                "name": [("AKAP Test", "da")],
                "display_name": ["AKAP Test"],
                "url": [("https://magenta.dk", "da")],
            },
            "contact_person": [
                {
                    "given_name": "Lars Peter Thomsen",
                    "email_address": "larsp@magenta.dk",
                    "type": "technical",
                },
                {
                    "given_name": "Magenta Support",
                    "email_address": "support@magenta.dk",
                    "type": "support",
                },
            ],
            "preferred_binding": {
                "attribute_consuming_service": [
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                ],
                "single_logout_service": [
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                ],
            },
        }
        :return:
        """
        saml_settings = copy.deepcopy(super().saml_settings())
        saml_settings["attribute_map_dir"] = os.path.dirname(
            django_mitid_auth.saml.oiosaml_attributemaps.attributemap.__file__
        )
        return saml_settings

    @staticmethod
    def get_privileges(saml_claims):
        """
        Decode privileges claim as specified in
        https://digitaliser.dk/resource/2377872/artefact/OIOSAMLBasicPrivilegeProfile1_0_1.pdf?artefact=true&PID=2377876
        section 3.5
        """
        privileges_base64 = saml_claims.get("Privilege")
        if privileges_base64:
            privileges_xml = base64.b64decode(privileges_base64)
            privileges_dict = xml_to_dict(privileges_xml)
            return privileges_dict
        return None

    @classmethod
    def get_log_dict(cls, request, saml_auth, saml_claims=None):
        if saml_claims is None:
            saml_claims = {}
        return {
            **super().get_log_dict(request, saml_auth, saml_claims),
            "CPR": saml_claims.get("CPR"),
            "CVR": saml_claims.get("CVR"),
            "LevelOfAssurance": saml_claims.get("LevelOfAssurance"),
            "Privileges": cls.get_privileges(saml_claims),
        }

    @classmethod
    def login(cls, request, auth_params=None):
        return super().login(request, auth_params=auth_params)
