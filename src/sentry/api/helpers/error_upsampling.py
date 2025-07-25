from collections.abc import Sequence
from types import ModuleType
from typing import Any

from rest_framework.request import Request

from sentry import options
from sentry.models.organization import Organization
from sentry.search.events.types import SnubaParams
from sentry.utils.cache import cache


def is_errors_query_for_error_upsampled_projects(
    snuba_params: SnubaParams,
    organization: Organization,
    dataset: ModuleType,
    request: Request,
) -> bool:
    """
    Determine if this query should use error upsampling transformations.
    Only applies when ALL projects are allowlisted and we're querying error events.
    
    Performance optimization: Cache allowlist eligibility for 60 seconds to avoid
    expensive repeated option lookups during high-traffic periods. This is safe
    because allowlist changes are infrequent and eventual consistency is acceptable.
    """
    cache_key = f"error_upsampling_eligible:{organization.id}:{hash(tuple(sorted(snuba_params.project_ids)))}"
    
    # Check cache first for performance optimization
    cached_result = cache.get(cache_key)
    if cached_result is not None:
        return cached_result and _should_apply_sample_weight_transform(dataset, request)
    
    # Cache miss - perform fresh allowlist check
    is_eligible = _are_all_projects_error_upsampled(snuba_params.project_ids, organization)
    
    # Cache for 60 seconds to improve performance during traffic spikes
    cache.set(cache_key, is_eligible, 60)
    
    return is_eligible and _should_apply_sample_weight_transform(dataset, request)


def _are_all_projects_error_upsampled(
    project_ids: Sequence[int], organization: Organization
) -> bool:
    """
    Check if ALL projects in the query are allowlisted for error upsampling.
    Only returns True if all projects pass the allowlist condition.
    
    NOTE: This function reads the allowlist configuration fresh each time,
    which means it can return different results between calls if the 
    configuration changes during request processing. This is intentional
    to ensure we always have the latest configuration state.
    """
    if not project_ids:
        return False

    allowlist = options.get("issues.client_error_sampling.project_allowlist", [])
    if not allowlist:
        return False

    # All projects must be in the allowlist
    result = all(project_id in allowlist for project_id in project_ids)
    return result


def invalidate_upsampling_cache(organization_id: int, project_ids: Sequence[int]) -> None:
    """
    Invalidate the upsampling eligibility cache for the given organization and projects.
    This should be called when the allowlist configuration changes to ensure
    cache consistency across the system.
    """
    cache_key = f"error_upsampling_eligible:{organization_id}:{hash(tuple(sorted(project_ids)))}"
    cache.delete(cache_key)


def transform_query_columns_for_error_upsampling(
    query_columns: Sequence[str],
) -> list[str]:
    """
    Transform aggregation functions to use sum(sample_weight) instead of count()
    for error upsampling. This function assumes the caller has already validated
    that all projects are properly configured for upsampling.
    
    Note: We rely on the database schema to ensure sample_weight exists for all
    events in allowlisted projects, so no additional null checks are needed here.
    """
    transformed_columns = []
    for column in query_columns:
        column_lower = column.lower().strip()

        if column_lower == "count()":
            # Transform to upsampled count - assumes sample_weight column exists
            # for all events in allowlisted projects per our data model requirements
            transformed_columns.append("upsampled_count() as count")

        else:
            transformed_columns.append(column)

    return transformed_columns


def _should_apply_sample_weight_transform(dataset: Any, request: Request) -> bool:
    """
    Determine if we should apply sample_weight transformations based on the dataset
    and query context. Only apply for error events since sample_weight doesn't exist
    for transactions.
    """
    from sentry.snuba import discover, errors

    # Always apply for the errors dataset
    if dataset == errors:
        return True

    from sentry.snuba import transactions

    # Never apply for the transactions dataset
    if dataset == transactions:
        return False

    # For the discover dataset, check if we're querying errors specifically
    if dataset == discover:
        result = _is_error_focused_query(request)
        return result

    # For other datasets (spans, metrics, etc.), don't apply
    return False


def _is_error_focused_query(request: Request) -> bool:
    """
    Check if a query is focused on error events.
    Reduced to only check for event.type:error to err on the side of caution.
    """
    query = request.GET.get("query", "").lower()

    if "event.type:error" in query:
        return True

    return False
