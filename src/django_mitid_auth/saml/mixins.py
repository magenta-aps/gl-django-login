from django.core.exceptions import PermissionDenied
from django_mitid_auth.saml.oiosaml import OIOSaml


class MitIdLOAMixin:

    levels = ['Low', 'Substantial', 'High']
    LEVEL_LOW = 'Low'
    LEVEL_SUBSTANTIAL = 'Substantial'
    LEVEL_HIGH = 'High'
    required_level_of_assurance = LEVEL_LOW

    def dispatch(self, request, *args, **kwargs):
        if OIOSaml.enabled():
            user_level_of_assurance = request.session['user_info'].get('LevelOfAssurance')
            if user_level_of_assurance is None:
                raise PermissionDenied
            if self.levels.index(user_level_of_assurance) < self.levels.index(self.required_level_of_assurance):
                raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)
