from __future__ import annotations

from dataclasses import dataclass

from sentry.constants import CRASH_RATE_ALERT_AGGREGATE_ALIAS
from sentry.incidents.handlers.condition import *  # noqa
from sentry.incidents.metric_issue_detector import MetricIssueDetectorValidator
from sentry.incidents.models.alert_rule import AlertRuleDetectionType, ComparisonDeltaChoices
from sentry.incidents.utils.format_duration import format_duration_idiomatic
from sentry.incidents.utils.types import AnomalyDetectionUpdate, ProcessedSubscriptionUpdate
from sentry.integrations.metric_alerts import TEXT_COMPARISON_DELTA
from sentry.issues.grouptype import GroupCategory, GroupType
from sentry.ratelimits.sliding_windows import Quota
from sentry.snuba.metrics import format_mri_field, is_mri_field
from sentry.snuba.models import QuerySubscription, SnubaQuery
from sentry.types.actor import parse_and_validate_actor
from sentry.types.group import PriorityLevel
from sentry.workflow_engine.handlers.detector import DetectorOccurrence, StatefulDetectorHandler
from sentry.workflow_engine.handlers.detector.base import EventData, EvidenceData
from sentry.workflow_engine.models.alertrule_detector import AlertRuleDetector
from sentry.workflow_engine.models.data_condition import Condition, DataCondition
from sentry.workflow_engine.models.data_source import DataPacket
from sentry.workflow_engine.processors.data_condition_group import ProcessedDataConditionGroup
from sentry.workflow_engine.types import DetectorException, DetectorPriorityLevel, DetectorSettings

COMPARISON_DELTA_CHOICES: list[None | int] = [choice.value for choice in ComparisonDeltaChoices]
COMPARISON_DELTA_CHOICES.append(None)

QUERY_AGGREGATION_DISPLAY = {
    "count()": "Number of events",
    "count_unique(tags[sentry:user])": "Number of users affected",
    "percentage(sessions_crashed, sessions)": "Crash free session rate",
    "percentage(users_crashed, users)": "Crash free user rate",
    "failure_rate()": "Failure rate",
    "apdex()": "Apdex score",
}


MetricUpdate = ProcessedSubscriptionUpdate | AnomalyDetectionUpdate
MetricResult = float | dict


@dataclass
class MetricIssueEvidenceData(EvidenceData[MetricResult]):
    alert_id: int


class MetricIssueDetectorHandler(StatefulDetectorHandler[MetricUpdate, MetricResult]):
    def create_occurrence(
        self,
        evaluation_result: ProcessedDataConditionGroup,
        data_packet: DataPacket[MetricUpdate],
        priority: DetectorPriorityLevel,
    ) -> tuple[DetectorOccurrence, EventData]:
        try:
            alert_rule_detector = AlertRuleDetector.objects.get(detector=self.detector)
            alert_id = alert_rule_detector.alert_rule_id
        except AlertRuleDetector.DoesNotExist:
            alert_id = None

        try:
            detector_trigger = DataCondition.objects.get(
                condition_group=self.detector.workflow_condition_group, condition_result=priority
            )
        except DataCondition.DoesNotExist:
            raise DetectorException(
                f"Failed to find detector trigger for detector id {self.detector.id}, cannot create metric issue occurrence"
            )

        try:
            query_subscription = QuerySubscription.objects.get(id=data_packet.source_id)
        except QuerySubscription.DoesNotExist:
            raise DetectorException(
                f"Failed to find query subscription for detector id {self.detector.id}, cannot create metric issue occurrence"
            )

        try:
            snuba_query = SnubaQuery.objects.get(id=query_subscription.snuba_query_id)
        except SnubaQuery.DoesNotExist:
            raise DetectorException(
                f"Failed to find snuba query for detector id {self.detector.id}, cannot create metric issue occurrence"
            )

        try:
            assignee = parse_and_validate_actor(
                str(self.detector.created_by_id), self.detector.project.organization_id
            )
        except Exception:
            assignee = None

        return (
            DetectorOccurrence(
                issue_title=self.detector.name,
                subtitle=self.construct_title(snuba_query, detector_trigger, priority),
                evidence_data={
                    "alert_id": alert_id,
                },
                evidence_display=[],  # XXX: may need to pass more info here for the front end
                type=MetricIssue,
                level="error",
                culprit="",
                assignee=assignee,
                priority=priority,
            ),
            {},
        )

    def extract_dedupe_value(self, data_packet: DataPacket[MetricUpdate]) -> int:
        return int(data_packet.packet.timestamp.timestamp())

    def extract_value(self, data_packet: DataPacket[MetricUpdate]) -> MetricResult:
        # this is a bit of a hack - anomaly detection data packets send extra data we need to pass along
        values = data_packet.packet.values
        if isinstance(data_packet.packet, AnomalyDetectionUpdate):
            return {None: values}
        return values.get("value")

    def construct_title(
        self,
        snuba_query: SnubaQuery,
        detector_trigger: DataCondition,
        priority: DetectorPriorityLevel,
    ) -> str:
        comparison_delta = self.detector.config.get("comparison_delta")
        detection_type = self.detector.config.get("detection_type")
        agg_display_key = snuba_query.aggregate

        if is_mri_field(agg_display_key):
            aggregate = format_mri_field(agg_display_key)
        elif CRASH_RATE_ALERT_AGGREGATE_ALIAS in agg_display_key:
            agg_display_key = agg_display_key.split(f"AS {CRASH_RATE_ALERT_AGGREGATE_ALIAS}")[
                0
            ].strip()
            aggregate = QUERY_AGGREGATION_DISPLAY.get(agg_display_key, agg_display_key)
        else:
            aggregate = QUERY_AGGREGATION_DISPLAY.get(agg_display_key, agg_display_key)

        if detection_type == "dynamic":
            alert_type = aggregate
            return f"Detected an anomaly in the query for {alert_type}"

        # Determine the higher or lower comparison
        higher_or_lower = ""
        if detector_trigger.type == Condition.GREATER:
            higher_or_lower = "greater than" if comparison_delta else "above"
        else:
            higher_or_lower = "less than" if comparison_delta else "below"

        label = "Warning" if priority == DetectorPriorityLevel.MEDIUM else "Critical"

        # Format the time window for the threshold
        time_window = format_duration_idiomatic(snuba_query.time_window // 60)

        # If the detector_trigger has a comparison delta, format the comparison string
        comparison: str | int | float = "threshold"
        if comparison_delta:
            comparison_delta_minutes = comparison_delta // 60
            comparison = TEXT_COMPARISON_DELTA.get(
                comparison_delta_minutes, f"same time {comparison_delta_minutes} minutes ago "
            )
        else:
            comparison = detector_trigger.comparison

        template = "{label}: {metric} in the last {time_window} {higher_or_lower} {comparison}"
        return template.format(
            label=label.capitalize(),
            metric=aggregate,
            higher_or_lower=higher_or_lower,
            comparison=comparison,
            time_window=time_window,
        )


# Example GroupType and detector handler for metric alerts. We don't create these issues yet, but we'll use something
# like these when we're sending issues as alerts
@dataclass(frozen=True)
class MetricIssue(GroupType):
    type_id = 8001
    slug = "metric_issue"
    description = "Metric issue triggered"
    category = GroupCategory.METRIC_ALERT.value
    category_v2 = GroupCategory.METRIC.value
    creation_quota = Quota(3600, 60, 100)
    default_priority = PriorityLevel.HIGH
    enable_auto_resolve = False
    enable_escalation_detection = False
    enable_status_change_workflow_notifications = False
    detector_settings = DetectorSettings(
        handler=MetricIssueDetectorHandler,
        validator=MetricIssueDetectorValidator,
        config_schema={
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "description": "A representation of a metric alert firing",
            "type": "object",
            "required": ["detection_type"],
            "properties": {
                "threshold_period": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 20,
                },  # remove after we complete backfill
                "comparison_delta": {
                    "type": ["integer", "null"],
                    "enum": COMPARISON_DELTA_CHOICES,
                },
                "detection_type": {
                    "type": "string",
                    "enum": [detection_type.value for detection_type in AlertRuleDetectionType],
                },
                "sensitivity": {"type": ["string", "null"]},  # remove after we complete backfill
                "seasonality": {"type": ["string", "null"]},  # remove after we complete backfill
            },
        },
    )
