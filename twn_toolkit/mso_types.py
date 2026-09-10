"""Explicit saved-list schemas and UI metadata for Mainframe Synced Objects."""
from __future__ import annotations

from dataclasses import dataclass
import math
import uuid


@dataclass(frozen=True)
class ListType:
    filename: str
    label: str
    permission: str
    endpoint: str


LIST_TYPES = {
    'ping.profile': ListType('ping_profiles.json', 'Ping profile', 'tools.ping', 'tools.ping_tool'),
    'dns.hosts': ListType('dns_hosts_profiles.json', 'DNS query list', 'tools.dns_response', 'tools.dns_response'),
    'dns.servers': ListType('dns_servers_profiles.json', 'DNS server list', 'tools.dns_response', 'tools.dns_response'),
    'ntp.hosts': ListType('ntp_host_profiles.json', 'NTP target list', 'tools.ntp_test', 'tools.ntp_test'),
    'traceroute.hosts': ListType('traceroute_host_profiles.json', 'Traceroute target list', 'tools.traceroute', 'tools.traceroute'),
    'tcp.hosts': ListType('port_scan_hosts_profiles.json', 'TCP scanner host list', 'tools.port_scanner', 'tools.port_scanner'),
    'tcp.ports': ListType('port_scan_ports_profiles.json', 'TCP scanner port list', 'tools.port_scanner', 'tools.port_scanner'),
    'wol.targets': ListType('wol_target_profiles.json', 'Wake-on-LAN group', 'tools.wake_on_lan', 'tools.wake_on_lan'),
    'snmp.credentials': ListType('snmp_credentials_profiles.json', 'SNMP credential', 'tools.snmp_test', 'tools.snmp_test'),
    'snmp.hosts': ListType('snmp_host_profiles.json', 'SNMP host profile', 'tools.snmp_test', 'tools.snmp_test'),
    'snmp.oids': ListType('snmp_oid_profiles.json', 'SNMP OID profile', 'tools.snmp_test', 'tools.snmp_test'),
    'radius.attributes': ListType('radius_attributes_profiles.json', 'RADIUS attribute set', 'tools.radius_test', 'tools.radius_test'),
    'lldp.persona': ListType('lldp_personas.json', 'LLDP persona', 'tools.lldp_lab', 'tools.lldp_lab'),
}
FILE_TYPES = {spec.filename: kind for kind, spec in LIST_TYPES.items()}


def default_profiles(kind):
    if kind == 'snmp.oids':
        from copy import deepcopy
        from .profiles import SNMPOidProfileStore
        return deepcopy(SNMPOidProfileStore.DEFAULTS)
    return []


def _text(payload, key):
    value = payload.get(key)
    if not isinstance(value, str):
        raise ValueError(f'Invalid {key} in shared profile.')
    return value.strip()


def _lines(values, host_key):
    if not isinstance(values, list) or not 1 <= len(values) <= 100:
        raise ValueError('Invalid saved target list.')
    lines = []
    for item in values:
        if not isinstance(item, dict):
            raise ValueError('Invalid saved target.')
        host, label = item.get(host_key), item.get('label', '')
        if not isinstance(host, str) or not isinstance(label, str) or any(c in host + label for c in '\r\n='):
            raise ValueError('Invalid saved target.')
        lines.append(f'{label} = {host}' if label else host)
    return '\n'.join(lines)


def validate_list(kind, payload):
    from .network_tools import parse_dns_hosts, parse_dns_servers, parse_ping_targets, parse_tcp_ports, parse_radius_attributes
    if not isinstance(payload, dict):
        raise ValueError('Invalid shared profile.')
    name = _text(payload, 'name')
    if not 1 <= len(name) <= (120 if kind == 'lldp.persona' else 100):
        raise ValueError('Invalid shared profile name.')
    if kind in {'dns.hosts', 'dns.servers'}:
        key, parser = ('host', parse_dns_hosts) if kind == 'dns.hosts' else ('address', parse_dns_servers)
        return {'name': name, 'values': parser(_lines(payload.get('values'), key))}
    if kind in {'ntp.hosts', 'traceroute.hosts', 'tcp.hosts', 'tcp.ports', 'wol.targets'}:
        source = _text(payload, 'values')
        if kind == 'tcp.ports':
            targets = parse_tcp_ports(source, limit=200)
        elif kind == 'wol.targets':
            from .wol_tools import parse_wol_targets
            targets = parse_wol_targets(source)
        else:
            targets = parse_ping_targets(source, limit={'ntp.hosts': 20, 'traceroute.hosts': 10, 'tcp.hosts': 50}[kind])
        result = {'name': name, 'values': source, 'count': len(targets)}
        if kind not in {'tcp.hosts', 'tcp.ports'}:
            result['targets'] = targets
        return result
    if kind in {'snmp.oids', 'radius.attributes'}:
        source = _text(payload, 'source')
        if kind == 'snmp.oids':
            from .snmp_tools import parse_oid_profile
            entries = parse_oid_profile(source)
        else:
            entries = parse_radius_attributes(source)
        return {'name': name, 'source': source, 'count': len(entries)}
    if kind == 'snmp.credentials':
        from .snmp_tools import validate_snmp_credential
        fields = ('name', 'version', 'community', 'username', 'security_level', 'auth_protocol', 'auth_key', 'priv_protocol', 'priv_key', 'context_name')
        if any(key in payload and not isinstance(payload[key], str) for key in fields):
            raise ValueError('Invalid SNMP credential fields.')
        return validate_snmp_credential({key: payload[key] for key in fields if key in payload})
    if kind == 'snmp.hosts':
        from .network_tools import validate_hosts
        host = _text(payload, 'host')
        validate_hosts(host, limit=1)
        port, timeout, retries = payload.get('port'), payload.get('timeout'), payload.get('retries')
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('Invalid SNMP port.')
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not .2 <= timeout <= 30:
            raise ValueError('Invalid SNMP timeout.')
        if type(retries) is not int or not 0 <= retries <= 5:
            raise ValueError('Invalid SNMP retries.')
        credential = payload.get('credential_id')
        try:
            if str(uuid.UUID(credential)) != credential:
                raise ValueError()
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError('A shared SNMP host requires a credential identity.') from exc
        return {'name': name, 'host': host, 'port': port, 'timeout': timeout, 'retries': retries, 'credential_id': credential}
    if kind == 'lldp.persona':
        from .lldp_tools import validate_persona
        text_fields = ('name', 'preset', 'system_name', 'system_description', 'source_mac',
                       'chassis_id', 'port_id', 'port_description', 'management_address')
        int_fields = ('chassis_id_subtype', 'port_id_subtype', 'pvid', 'ttl', 'med_class',
                      'med_policy_vlan', 'med_policy_priority', 'med_policy_dscp',
                      'interval_seconds', 'duration_minutes')
        bool_fields = ('med_enabled', 'med_policy_enabled', 'med_policy_unknown',
                       'med_policy_tagged', 'quiet_lldpd')
        for fields, expected in ((text_fields, str), (int_fields, int), (bool_fields, bool)):
            if any(type(payload.get(key)) is not expected for key in fields):
                raise ValueError('Invalid LLDP persona fields.')
        capabilities = payload.get('capabilities')
        if not isinstance(capabilities, list) or any(not isinstance(item, str) for item in capabilities):
            raise ValueError('Invalid LLDP capabilities.')
        allowed = (*text_fields, *int_fields, *bool_fields, 'capabilities', 'custom_tlvs')
        return validate_persona({key: payload[key] for key in allowed if key in payload}, interface=None)

    raise ValueError('Unsupported shared list type.')
