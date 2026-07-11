from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping


@dataclass(frozen=True)
class ConditionResult:
    met: bool
    status: str
    summary: str
    evidence: dict[str, Any]


@dataclass(frozen=True)
class ActionResult:
    status: str
    summary: str
    output: dict[str, Any]


@dataclass(frozen=True)
class ConditionType:
    id: str
    label: str
    description: str
    validate: Callable[[dict[str, Any]], dict[str, Any]]
    evaluate: Callable[[dict[str, Any]], ConditionResult]
    parse_form: Callable[[Mapping[str, Any]], dict[str, Any]] | None = None


@dataclass(frozen=True)
class ActionType:
    id: str
    label: str
    description: str
    validate: Callable[[dict[str, Any]], dict[str, Any]]
    execute: Callable[[dict[str, Any], ConditionResult], ActionResult]
    parse_form: Callable[[Mapping[str, Any], dict[str, Any]], dict[str, Any]] | None = None
    secret_fields: tuple[str, ...] = ()
