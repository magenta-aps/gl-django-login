import base64
import copy
import os
from typing import Dict

from django.http import HttpRequest
from xmltodict import parse as xml_to_dict

import django_mitid_auth.saml.oiosaml_attributemaps.attributemap
from django_mitid_auth.saml.saml2 import Saml2


class OIOSaml(Saml2):
    @classmethod
    def saml_settings(cls) -> dict:
        saml_settings = copy.deepcopy(super().saml_settings())
        saml_settings["attribute_map_dir"] = os.path.dirname(
            django_mitid_auth.saml.oiosaml_attributemaps.attributemap.__file__
        )
        return saml_settings

    @staticmethod
    def get_privileges(saml_claims: Dict[str, str]) -> dict | None:
        """
        Decode privileges claim as specified in
        https://digitaliser.dk/resource/2377872/artefact/OIOSAMLBasicPrivilegeProfile1_0_1.pdf?artefact=true&PID=2377876
        section 3.5
        """
        privileges_base64: str | None = saml_claims.get("Privilege")
        if privileges_base64:
            privileges_xml = base64.b64decode(privileges_base64)
            privileges_dict = xml_to_dict(privileges_xml)
            return privileges_dict
        return None

    @classmethod
    def get_log_dict(
        cls, request: HttpRequest, saml_auth, saml_claims: Dict[str, str] | None = None
    ) -> dict:
        if saml_claims is None:
            saml_claims = {}
        return {
            **super().get_log_dict(request, saml_auth, saml_claims),
            "CPR": saml_claims.get("CPR"),
            "CVR": saml_claims.get("CVR"),
            "LevelOfAssurance": saml_claims.get("LevelOfAssurance"),
            "Privileges": cls.get_privileges(saml_claims),
        }
