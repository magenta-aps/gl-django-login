import base64
from xmltodict import parse as xml_to_dict

from django_mitid_auth.saml.saml2 import Saml2


class OIOSaml(Saml2):

    """
    Maps session['user_info'] keys to SAML claims
    See spec at
    https://www.digitaliser.dk/resource/4390927/artefact/OIOSAMLWebSSOprofile3.0.pdf?artefact=true&PID=4904569
    """
    claims_map = {
        'SpecVer': 'https://data.gov.dk/model/core/specVersion',
        'BootstrapToken': 'https://data.gov.dk/model/core/eid/bootstrapToken',
        'Privilege': 'https://data.gov.dk/model/core/eid/privilegesIntermediate',
        'LevelOfAssurance': 'https://data.gov.dk/concept/core/nsis/loa',
        'IdentityAssuranceLevel': 'https://data.gov.dk/concept/core/nsis/ial',
        'AuthenticationAssuranceLevel': 'https://data.gov.dk/concept/core/nsis/aal',
        'Fullname': 'https://data.gov.dk/model/core/eid/fullName',
        'Firstname': 'https://data.gov.dk/model/core/eid/firstName',
        'Lastname': 'https://data.gov.dk/model/core/eid/lastName',
        'Alias': 'https://data.gov.dk/model/core/eid/alias',
        'Email': 'https://data.gov.dk/model/core/eid/email',
        'Age': 'https://data.gov.dk/model/core/eid/age',
        'CprUUID': 'https://data.gov.dk/model/core/eid/cprUuid',
        'CVR': 'https://data.gov.dk/model/core/eid/professional/cvr',
        'CPR': 'https://data.gov.dk/model/core/eid/cprNumber',
        'PersonName': 'https://data.gov.dk/model/core/eid/fullName',
        'OrganizationName': 'https://data.gov.dk/model/core/eid/professional/orgName',
    }

    @staticmethod
    def get_privileges(saml_claims):
        """
        Decode privileges claim as specified in
        https://digitaliser.dk/resource/2377872/artefact/OIOSAMLBasicPrivilegeProfile1_0_1.pdf?artefact=true&PID=2377876
        section 3.5
        """
        privileges_base64 = saml_claims.get('Privilege')
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
            'CPR': saml_claims.get('CPR'),
            'CVR': saml_claims.get('CVR'),
            'LevelOfAssurance': saml_claims.get('LevelOfAssurance'),
            'Privileges': cls.get_privileges(saml_claims),
        }

    @classmethod
    def login(cls, request, login_params=None):
        if login_params is None:
            login_params = {}
        login_params['set_nameid_policy'] = False
        return super().login(request, login_params=login_params)

    @classmethod
    def populate_session(cls, session, saml_claims):
        super().populate_session(session, saml_claims)
        session['user_info']['DecodedPrivileges'] = cls.get_privileges(saml_claims)
