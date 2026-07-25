from __future__ import annotations

from typing import Any, Mapping

from .automation_types.actions import registered_actions
from .automation_types.conditions import registered_conditions
from .automation_types.condition_types.triggers import registered_triggers
from .automation_types.models import (
    ActionResult,
    ActionType,
    ConditionResult,
    ConditionType,
    evaluation_result,
)
from .network_tools import ToolInputError


class AutomationRegistry:
    """Internal registry for trusted condition and action implementations."""

    def __init__(self) -> None:
        self.conditions: dict[str, ConditionType] = {}
        self.triggers: dict[str, ConditionType] = {}
        self.actions: dict[str, ActionType] = {}

    def add_condition(self, condition: ConditionType) -> None:
        if condition.id in self.conditions or condition.id in self.triggers:
            raise ValueError(f"Duplicate automation condition type: {condition.id}")
        self.conditions[condition.id] = condition

    def add_action(self, action: ActionType) -> None:
        if action.id in self.actions:
            raise ValueError(f"Duplicate automation action type: {action.id}")
        self.actions[action.id] = action

    def add_trigger(self, trigger: ConditionType) -> None:
        if trigger.id in self.triggers or trigger.id in self.conditions:
            raise ValueError(f"Duplicate automation trigger type: {trigger.id}")
        self.triggers[trigger.id] = trigger

    def validate_condition(self, type_id: str, config: dict[str, Any]) -> dict[str, Any]:
        try:
            condition = self.conditions[type_id]
        except KeyError as exc:
            raise ToolInputError(f"Unknown condition type: {type_id}") from exc
        return condition.validate(config)

    def validate_action(self, type_id: str, config: dict[str, Any]) -> dict[str, Any]:
        try:
            action = self.actions[type_id]
        except KeyError as exc:
            raise ToolInputError(f"Unknown action type: {type_id}") from exc
        return action.validate(config)

    def validate_trigger(self, type_id: str, config: dict[str, Any]) -> dict[str, Any]:
        try:
            trigger = self.triggers[type_id]
        except KeyError as exc:
            raise ToolInputError(f"Unknown trigger type: {type_id}") from exc
        return trigger.validate(config)

    def evaluate_condition(
        self, type_id: str, config: dict[str, Any]
    ) -> ConditionResult:
        return evaluation_result(
            self.conditions[type_id].evaluate(config),
            kind="condition",
            type_id=type_id,
        )

    def evaluate_trigger(
        self, type_id: str, config: dict[str, Any]
    ) -> ConditionResult:
        return evaluation_result(
            self.triggers[type_id].evaluate(config),
            kind="schedule" if type_id == "schedule.calendar" else "manual",
            type_id=type_id,
        )

    def condition_config_from_form(self, type_id: str, form: Mapping[str, Any]) -> dict[str, Any]:
        try:
            condition = self.conditions[type_id]
        except KeyError as exc:
            raise ToolInputError(f"Unknown condition type: {type_id}") from exc
        if condition.parse_form is None:
            raise ToolInputError(f"Condition type {type_id} does not provide a form parser.")
        return condition.validate(condition.parse_form(form))

    def action_config_from_form(self, type_id: str, form: Mapping[str, Any], existing: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            action = self.actions[type_id]
        except KeyError as exc:
            raise ToolInputError(f"Unknown action type: {type_id}") from exc
        if action.parse_form is None:
            raise ToolInputError(f"Action type {type_id} does not provide a form parser.")
        return action.validate(action.parse_form(form, existing or {}))

    def trigger_config_from_form(
        self, type_id: str, form: Mapping[str, Any]
    ) -> dict[str, Any]:
        try:
            trigger = self.triggers[type_id]
        except KeyError as exc:
            raise ToolInputError(f"Unknown trigger type: {type_id}") from exc
        if trigger.parse_form is None:
            raise ToolInputError(f"Trigger type {type_id} does not provide a form parser.")
        return trigger.validate(trigger.parse_form(form))

    def secret_fields_for_action(self, type_id: str) -> tuple[str, ...]:
        action = self.actions.get(type_id)
        # Unknown/legacy action rows must remain fail-closed when rendered. These
        # were the two secret-bearing fields supported before metadata moved onto
        # ActionType, so retaining them prevents an old or test definition from
        # exposing credentials merely because its implementation is unavailable.
        return action.secret_fields if action else ("password", "headers")


def build_automation_registry() -> AutomationRegistry:
    registry = AutomationRegistry()
    for condition in registered_conditions():
        registry.add_condition(condition)
    for trigger in registered_triggers():
        registry.add_trigger(trigger)
    for action in registered_actions():
        registry.add_action(action)
    return registry


AUTOMATION_REGISTRY = build_automation_registry()

__all__ = (
    "AUTOMATION_REGISTRY",
    "ActionResult",
    "ActionType",
    "AutomationRegistry",
    "ConditionResult",
    "ConditionType",
    "build_automation_registry",
)
