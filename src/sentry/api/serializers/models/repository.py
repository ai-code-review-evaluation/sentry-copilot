from datetime import datetime
from typing import TypedDict

from sentry.api.serializers import Serializer, register
from sentry.models.repository import Repository


class RepositorySerializerResponse(TypedDict):
    id: str
    name: str
    url: str | None
    provider: dict[str, str]
    status: str
    dateCreated: datetime
    integrationId: str | None
    externalSlug: str | None
    externalId: str | None


@register(Repository)
class RepositorySerializer(Serializer):
    def serialize(self, obj: Repository, attrs, user, **kwargs) -> RepositorySerializerResponse:
        external_slug = None
        integration_id = None
        if obj.integration_id:
            integration_id = str(obj.integration_id)
        if obj.provider:
            repo_provider = obj.get_provider()
            provider = {"id": obj.provider, "name": repo_provider.name}
            external_slug = repo_provider.repository_external_slug(obj)
        else:
            provider = {"id": "unknown", "name": "Unknown Provider"}

        return {
            "id": str(obj.id),
            "name": obj.config.get("pending_deletion_name", obj.name),
            "url": obj.url,
            "provider": provider,
            "status": obj.get_status_display(),
            "dateCreated": obj.date_added,
            "integrationId": integration_id,
            "externalSlug": external_slug,
            "externalId": obj.external_id,
        }
