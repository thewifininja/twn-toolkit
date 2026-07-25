"""ICMP, DNS, and TCP automation condition registrations."""

from .network_triggers import (
    _evaluate_dns,
    _evaluate_dns_performance,
    _evaluate_ping,
    _evaluate_tcp,
    _parse_dns_form,
    _parse_dns_performance_form,
    _parse_ping_form,
    _parse_tcp_form,
    _validate_dns,
    _validate_dns_performance,
    _validate_ping,
    _validate_tcp,
)
from ..models import ConditionType


def registered_conditions() -> tuple[ConditionType, ...]:
    return (
        ConditionType("ping.multi", "Ping health", "Trigger when selected ICMP targets are unreachable or breach optional loss, latency, or jitter limits.", _validate_ping, _evaluate_ping, _parse_ping_form),
        ConditionType("dns.lookup", "DNS lookup", "Trigger when DNS queries fail or return unexpected answers.", _validate_dns, _evaluate_dns, _parse_dns_form),
        ConditionType("dns.performance", "DNS performance", "Trigger when DNS queries fail or exceed a response-time limit.", _validate_dns_performance, _evaluate_dns_performance, _parse_dns_performance_form),
        ConditionType("tcp.reachability", "TCP service reachability", "Trigger when TCP services do not match their expected open or closed state.", _validate_tcp, _evaluate_tcp, _parse_tcp_form),
    )
