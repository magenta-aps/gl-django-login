from django.core.exceptions import PermissionDenied

from django_mitid_auth.saml.oiosaml import OIOSaml


class MitIdLOAMixin:
    levels = ["Low", "Substantial", "High"]
    LEVEL_LOW = "Low"
    LEVEL_SUBSTANTIAL = "Substantial"
    LEVEL_HIGH = "High"
    required_level_of_assurance = LEVEL_LOW

    def dispatch(self, request, *args, **kwargs):
        if OIOSaml.enabled():
            user_level_of_assurance = request.session["saml"]["ava"].get(
                "levelofassurance"
            )
            if (
                type(user_level_of_assurance) is list
                and len(user_level_of_assurance) == 1
            ):
                user_level_of_assurance = user_level_of_assurance[0]
            if user_level_of_assurance is None or self.levels.index(
                user_level_of_assurance
            ) < self.levels.index(self.required_level_of_assurance):
                return self.permission_denied(request, *args, **kwargs)
        return super().dispatch(request, *args, **kwargs)

    def permission_denied(self, request, *args, **kwargs):
        raise PermissionDenied
