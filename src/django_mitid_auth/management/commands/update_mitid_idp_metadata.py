import os.path

import requests
from django.conf import settings
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Wait for database to be available"

    def get_url(self):
        return settings.SAML.get("metadata_remote_container") or settings.SAML.get(
            "metadata_remote"
        )

    def get_cache_filename(self):
        if "local" in settings.SAML["metadata"] and len(
            settings.SAML["metadata"]["local"]
        ):
            return settings.SAML["metadata"]["local"][0]

    def handle(self, *args, **options):
        remote_url = self.get_url()
        filename = self.get_cache_filename()
        must_succeed = filename and (
            not os.path.exists(filename) or os.path.getsize(filename) == 0
        )
        if remote_url and filename:
            with open(filename, "wb") as file:
                response = requests.get(remote_url)
                if response.status_code == 200:
                    file.write(response.content)
                elif must_succeed:
                    raise Exception("IdP Metadata file doesn't exist")
