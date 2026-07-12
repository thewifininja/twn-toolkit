"""Built-in automation condition registrations grouped by domain."""

from .certificate import registered_conditions as certificate_conditions
from .network import registered_conditions as network_conditions
from .snmp import registered_conditions as snmp_conditions
from .triggers import registered_conditions as trigger_conditions


def registered_conditions():
    return (
        *trigger_conditions(),
        *network_conditions(),
        *snmp_conditions(),
        *certificate_conditions(),
    )


__all__ = ("registered_conditions",)
