from __future__ import annotations

import logging
from typing import Any

from sentry.hybridcloud.outbox.category import WebhookProviderIdentifier
from sentry.integrations.bitbucket.webhook import BitbucketWebhookEndpoint
from sentry.integrations.middleware.hybrid_cloud.parser import BaseRequestParser
from sentry.integrations.types import IntegrationProviderSlug
from sentry.models.organizationmapping import OrganizationMapping
from sentry.types.region import RegionResolutionError, get_region_by_name

logger = logging.getLogger(__name__)


class BitbucketRequestParser(BaseRequestParser):
    provider = IntegrationProviderSlug.BITBUCKET.value
    webhook_identifier = WebhookProviderIdentifier.BITBUCKET

    def get_bitbucket_webhook_response(self):
        """
        Used for identifying regions from Bitbucket and Bitbucket Server webhooks
        """
        # The organization is provided in the path, so we can skip inferring organizations
        # from the integration credentials
        organization_id = self.match.kwargs.get("organization_id")
        logging_extra: dict[str, Any] = {"path": self.request.path}
        if not organization_id:
            logger.info("%s.no_organization_id", self.provider, extra=logging_extra)
            return self.get_response_from_control_silo()

        try:
            mapping: OrganizationMapping = OrganizationMapping.objects.get(
                organization_id=organization_id
            )
        except OrganizationMapping.DoesNotExist as e:
            logging_extra["error"] = str(e)
            logging_extra["organization_id"] = organization_id
            logger.info("%s.no_mapping", self.provider, extra=logging_extra)
            return self.get_response_from_control_silo()

        try:
            region = get_region_by_name(mapping.region_name)
        except RegionResolutionError as e:
            logging_extra["error"] = str(e)
            logging_extra["mapping_id"] = mapping.id
            logger.info("%s.no_region", self.provider, extra=logging_extra)
            return self.get_response_from_control_silo()
        return self.get_response_from_webhookpayload(
            regions=[region], identifier=mapping.organization_id
        )

    def get_response(self):
        if self.view_class == BitbucketWebhookEndpoint:
            return self.get_bitbucket_webhook_response()
        return self.get_response_from_control_silo()
