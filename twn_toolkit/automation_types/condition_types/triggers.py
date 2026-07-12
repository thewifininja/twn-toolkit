"""Manual and calendar automation trigger registrations."""

from .network_triggers import (
    _evaluate_manual,
    _evaluate_schedule,
    _parse_manual_form,
    _parse_schedule_form,
    _validate_manual,
    _validate_schedule,
)
from ..models import ConditionType


def registered_conditions() -> tuple[ConditionType, ...]:
    return (
        ConditionType("schedule.calendar", "Calendar schedule", "Trigger from one or more one-time or recurring calendar rules.", _validate_schedule, _evaluate_schedule, _parse_schedule_form),
        ConditionType("manual.trigger", "Manual trigger", "Run attached actions only when a user explicitly starts the automation.", _validate_manual, _evaluate_manual, _parse_manual_form),
    )
