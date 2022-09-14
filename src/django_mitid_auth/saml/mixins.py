from django.core.exceptions import PermissionDenied
from django_mitid_auth.saml.oiosaml import OIOSaml


class MitIdLOAMixin:

    levels = ['Low', 'Substantial', 'High']
    LEVEL_LOW = 'Low'
    LEVEL_SUBSTANTIAL = 'Substantial'
    LEVEL_HIGH = 'High'
    required_level_of_assurance = LEVEL_LOW
    error_template = "django_mitid_auth/insufficient_permissions.html"

    def dispatch(self, request, *args, **kwargs):
        if OIOSaml.enabled():
            user_level_of_assurance = request.session['user_info'].get('LevelOfAssurance')
            if user_level_of_assurance is None \
                    or self.levels.index(user_level_of_assurance) < self.levels.index(self.required_level_of_assurance):
                return self.permission_denied(request, *args, **kwargs)
        return super().dispatch(request, *args, **kwargs)

    def permission_denied(self, request, *args, **kwargs):
        raise PermissionDenied
