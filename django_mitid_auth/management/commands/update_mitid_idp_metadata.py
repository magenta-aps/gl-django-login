import logging
import os.path
from typing import Any

import requests
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError, CommandParser

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Update MitID IdP metadata"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--fail-on-remote-error",
            action="store_true",
            help="Return status 1 on fetch error, even if a cached file already exists",
        )

    def as_string(self, data: Any) -> str | None:
        if data is not None:
            return str(data)
        return None

    def get_url(self) -> str | None:
        return self.as_string(
            settings.SAML.get("metadata_remote_container")
        ) or self.as_string(settings.SAML.get("metadata_remote"))

    def get_cache_filename(self) -> str | None:
        if "local" in settings.SAML["metadata"] and len(
            settings.SAML["metadata"]["local"]
        ):
            return settings.SAML["metadata"]["local"][0]

    def handle(self, *args, **options):
        remote_url = self.get_url()
        filename = self.get_cache_filename()
        fail_on_remote_error = options["fail_on_remote_error"]
        file_exists = filename and (
            os.path.exists(filename) and os.path.getsize(filename) > 0
        )
        if not remote_url:
            raise CommandError(
                "Remote url not configured, should be set in SAML.metadata_remote_container or SAML.metadata_remote"
            )
        if not filename:
            raise CommandError(
                "Local filename not configured, should be set in SAML.metadata.local[0]"
            )

        if file_exists:
            with open(filename, "rb") as file:
                existing_metadata = file.read()
        else:
            existing_metadata = None

        logger.info(f"Fetching IdP Metadata from {remote_url}")
        error = None
        try:
            response = requests.get(remote_url)
            if response.status_code == 200:
                new_metadata = response.content
                if file_exists and existing_metadata == new_metadata:
                    logger.info("No changes to IdP Metadata")
                else:
                    with open(filename, "wb") as file:
                        file.write(new_metadata)
                    logger.info(f"IdP Metadata updated in file {filename}")
            else:
                error = f"IdP Metadata download failed: {remote_url} returned {response.status_code}."
        except requests.exceptions.ConnectionError:
            error = f"IdP Metadata download failed: Connection error for {remote_url}."

        if error:
            if file_exists:
                error += " Cached file exists."
                if fail_on_remote_error:
                    raise CommandError(error)
                logger.warning(error)
            else:
                error += " Cached file does not exist."
                raise CommandError(error)
