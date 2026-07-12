"""ICMP, DNS, and TCP automation condition registrations."""

from .network_triggers import (
    _evaluate_dns,
    _evaluate_ping,
    _evaluate_tcp,
    _parse_dns_form,
    _parse_ping_form,
    _parse_tcp_form,
    _validate_dns,
    _validate_ping,
    _validate_tcp,
)
from ..models import ConditionType


def registered_conditions() -> tuple[ConditionType, ...]:
    return (
        ConditionType("ping.multi", "Multi-host ping", "Trigger when a selected number of ICMP targets are unreachable.", _validate_ping, _evaluate_ping, _parse_ping_form),
        ConditionType("dns.lookup", "DNS lookup", "Trigger when DNS queries fail or return unexpected answers.", _validate_dns, _evaluate_dns, _parse_dns_form),
        ConditionType("tcp.reachability", "TCP service reachability", "Trigger when TCP services do not match their expected open or closed state.", _validate_tcp, _evaluate_tcp, _parse_tcp_form),
    )
