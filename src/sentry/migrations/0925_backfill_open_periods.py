# Generated by Django 5.2.1 on 2025-05-30 00:42

import logging
from collections import defaultdict
from datetime import datetime
from enum import Enum
from typing import Any

from django.conf import settings
from django.db import DataError, IntegrityError, migrations, router, transaction
from django.db.backends.base.schema import BaseDatabaseSchemaEditor
from django.db.migrations.state import StateApps

from sentry.new_migrations.migrations import CheckedMigration
from sentry.utils import redis
from sentry.utils.iterators import chunked
from sentry.utils.query import RangeQuerySetWrapperWithProgressBarApprox

logger = logging.getLogger(__name__)

CHUNK_SIZE = 20


# copied constants and enums
class ActivityType(Enum):
    SET_REGRESSION = 6
    SET_RESOLVED = 1
    SET_RESOLVED_IN_RELEASE = 13
    SET_RESOLVED_BY_AGE = 15
    SET_RESOLVED_IN_COMMIT = 16
    SET_RESOLVED_IN_PULL_REQUEST = 21


RESOLVED_ACTIVITY_TYPES = [
    ActivityType.SET_RESOLVED.value,
    ActivityType.SET_RESOLVED_IN_RELEASE.value,
    ActivityType.SET_RESOLVED_BY_AGE.value,
    ActivityType.SET_RESOLVED_IN_COMMIT.value,
    ActivityType.SET_RESOLVED_IN_PULL_REQUEST.value,
]


class GroupStatus:
    UNRESOLVED = 0
    RESOLVED = 1


# end copy


def get_open_periods_for_group(
    apps: StateApps,
    group_id: int,
    status: int,
    project_id: int,
    first_seen: datetime,
    activities: list[Any],
    GroupOpenPeriod: Any,
) -> list[Any]:
    # No activities means the group has been open since the first_seen date
    if not activities:
        return [
            GroupOpenPeriod(
                group_id=group_id,
                project_id=project_id,
                date_started=first_seen,
            )
        ]

    # Since activities can apparently exist from before the start date, we want to ensure the
    # first open period starts at the first_seen date and ends at the first resolution activity after it.
    start_index = 0
    activities_len = len(activities)
    while (
        start_index < activities_len and activities[start_index].type not in RESOLVED_ACTIVITY_TYPES
    ):
        start_index += 1

    open_periods = []
    regression_time: datetime | None = first_seen
    for activity in activities[start_index:]:
        if activity.type == ActivityType.SET_REGRESSION.value and regression_time is None:
            regression_time = activity.datetime

        elif activity.type in RESOLVED_ACTIVITY_TYPES and regression_time is not None:
            if activity.datetime < regression_time:
                logger.warning(
                    "Open period has invalid start and end dates",
                    extra={
                        "group_id": group_id,
                        "activity_datetime": activity.datetime,
                        "regression_time": regression_time,
                    },
                )
                return []

            open_periods.append(
                GroupOpenPeriod(
                    group_id=group_id,
                    project_id=project_id,
                    date_started=regression_time,
                    date_ended=activity.datetime,
                    resolution_activity=activity,
                    user_id=activity.user_id,
                )
            )

            regression_time = None

    # Handle currently open period if the group is unresolved
    if status == GroupStatus.UNRESOLVED and regression_time is not None:
        open_periods.append(
            GroupOpenPeriod(
                group_id=group_id,
                project_id=project_id,
                date_started=regression_time,
            )
        )

    return open_periods


def _backfill_group_open_periods(
    apps: StateApps, group_data: list[tuple[int, datetime, int, int]]
) -> None:
    GroupOpenPeriod = apps.get_model("sentry", "GroupOpenPeriod")
    Activity = apps.get_model("sentry", "Activity")

    group_ids = [group_id for group_id, _, _, _ in group_data]
    groups_with_open_periods = set(
        GroupOpenPeriod.objects.filter(group_id__in=group_ids)
        .values_list("group_id", flat=True)
        .distinct()
    )

    group_ids = [group_id for group_id in group_ids if group_id not in groups_with_open_periods]
    # Filter to REGRESSION and SET_RESOLVED_XX activties to find the bounds of each open period.
    # The only UNRESOLVED activity we would care about is the first UNRESOLVED activity for the group creation,
    # but we don't create an entry for that.

    activities = defaultdict(list)

    try:
        for activity in Activity.objects.filter(
            group_id__in=group_ids,
            type__in=[ActivityType.SET_REGRESSION.value, *RESOLVED_ACTIVITY_TYPES],
        ).order_by("datetime"):
            # Skip activities before the group's first_seen date
            if activity.datetime < activity.group.first_seen:
                continue

            activities[activity.group_id].append(activity)
    except Exception as e:
        logger.exception(
            "Error getting activities",
            extra={"group_ids": group_ids, "error": e},
        )
        return

    open_periods = []
    for group_id, first_seen, status, project_id in group_data:
        # Skip groups that already have open periods
        if group_id in groups_with_open_periods:
            continue

        open_periods.extend(
            get_open_periods_for_group(
                apps,
                group_id,
                status,
                project_id,
                first_seen,
                activities[group_id],
                GroupOpenPeriod,
            )
        )

    with transaction.atomic(router.db_for_write(GroupOpenPeriod)):
        try:
            GroupOpenPeriod.objects.bulk_create(open_periods)
        except (IntegrityError, DataError) as e:
            logger.exception(
                "Error creating open period",
                extra={"group_ids": group_ids, "error": e},
            )


def backfill_group_open_periods(apps: StateApps, schema_editor: BaseDatabaseSchemaEditor) -> None:
    Group = apps.get_model("sentry", "Group")

    backfill_key = "backfill_group_open_periods_from_activity_0702_1"
    redis_client = redis.redis_clusters.get(settings.SENTRY_MONITORS_REDIS_CLUSTER)

    progress_id = int(redis_client.get(backfill_key) or 0)
    for group_data in chunked(
        RangeQuerySetWrapperWithProgressBarApprox(
            Group.objects.filter(id__gt=progress_id).values_list(
                "id", "first_seen", "status", "project_id"
            ),
            result_value_getter=lambda item: item[0],
        ),
        CHUNK_SIZE,
    ):
        logger.info(
            "Processing batch for group open period backfill",
            extra={"last_group_id": group_data[-1][0]},
        )
        _backfill_group_open_periods(apps, group_data)
        # Save progress to redis in case we have to restart
        redis_client.set(backfill_key, group_data[-1][0], ex=60 * 60 * 24 * 7)


class Migration(CheckedMigration):
    # This flag is used to mark that a migration shouldn't be automatically run in production.
    # This should only be used for operations where it's safe to run the migration after your
    # code has deployed. So this should not be used for most operations that alter the schema
    # of a table.
    # Here are some things that make sense to mark as post deployment:
    # - Large data migrations. Typically we want these to be run manually so that they can be
    #   monitored and not block the deploy for a long period of time while they run.
    # - Adding indexes to large tables. Since this can take a long time, we'd generally prefer to
    #   run this outside deployments so that we don't block them. Note that while adding an index
    #   is a schema change, it's completely safe to run the operation after the code has deployed.
    # Once deployed, run these manually via: https://develop.sentry.dev/database-migrations/#migration-deployment

    is_post_deployment = True

    dependencies = [
        ("sentry", "0924_dashboard_add_unique_constraint_for_user_org_position"),
    ]

    operations = [
        migrations.RunPython(
            backfill_group_open_periods,
            migrations.RunPython.noop,
            hints={"tables": ["sentry_groupopenperiod"]},
        ),
    ]
