import logging
from typing import Callable, Dict

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

logger = logging.getLogger(__name__)


class Saml2Backend(ModelBackend):

    # Map usermodel attributes (keys) to saml2 attributes (values)
    map: Dict[str, str | Callable] = getattr(settings, "SAML_ATTRIBUTE_MAPPING") or {
        "username": "cpr",
        "first_name": "firstname",
        "last_name": "lastname",
        "email": "email",
    }

    def has_module_perms(self, user_obj, app_label):
        print(f"has_module_perms: {self.get_all_permissions(user_obj)}")
        return user_obj.is_active and any(
            perm[: perm.index(".")] == app_label
            for perm in self.get_all_permissions(user_obj)
        )

    def get_all_permissions(self, user_obj, obj=None):
        if not user_obj.is_active or user_obj.is_anonymous or obj is not None:
            return set()
        if not hasattr(user_obj, "_perm_cache"):
            user_obj._perm_cache = super().get_all_permissions(user_obj)
        print(f"cache: {user_obj._perm_cache}")
        return user_obj._perm_cache

    def get_user_permissions(self, user_obj, obj=None):
        x = super().get_user_permissions(user_obj, obj)
        print(f"get_user_permissions: {x}")
        return x

    def get_group_permissions(self, user_obj, obj=None):
        x = super().get_group_permissions(user_obj, obj)
        print(f"get_group_permissions: {x}")
        return x

    @classmethod
    def get_usermodel_attribute_value(cls, ava: dict, key: str) -> str:
        try:
            saml_attribute: str | Callable = cls.map[key]
        except KeyError:
            raise Exception(f"attribute map does not contain key {key}")
        if callable(saml_attribute):
            value = saml_attribute(ava)
        else:
            try:
                value = ava[saml_attribute]
            except KeyError:
                raise Exception(f"SAML data does not contain requested key {saml_attribute}")
        if type(value) is list:
            value = value[0]
        return value

    def authenticate(
            self,
            request,
            saml_data=None,
            create_unknown_user=True,
            assertion_info=None,
            **kwargs,
    ):
        if saml_data is None:
            return None

        if "ava" not in saml_data:
            logger.error('ava not found in saml data')
            return None

        if saml_data is None:
            logger.info("Session info is None")
            return None

        if "ava" not in saml_data:
            logger.error('"ava" key not found in session_info')
            return None

        user_model = get_user_model()
        attributes = {}
        for user_key in self.map.keys():
            attributes[user_key] = self.get_usermodel_attribute_value(saml_data["ava"], user_key)

        if not attributes.get("username"):
            logger.error("Could not get identifier for username in saml data")
            return None

        user, created = user_model.objects.update_or_create(
            **{"username": attributes["username"]},
            defaults=attributes,
        )
        if created:
            logger.info(
                "Created new User object from saml login (username='%s')", user.username
            )
            user.set_unusable_password()
            user.save(update_fields=("password",))
        else:
            logger.info(
                "Logging in existing User from saml login (username='%s')",
                user.username,
            )
        return user
