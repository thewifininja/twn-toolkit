"""SNMP automation condition registration."""

from .monitoring import _evaluate_snmp, _parse_snmp_form, _validate_snmp
from ..models import ConditionType


def registered_conditions() -> tuple[ConditionType, ...]:
    return (
        ConditionType("snmp.value", "SNMP OID value", "Trigger when saved SNMP hosts match a per-host group of OID rules.", _validate_snmp, _evaluate_snmp, _parse_snmp_form),
    )
