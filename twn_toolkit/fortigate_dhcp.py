"""Read-only, identity-checked FortiGate/Fabric DHCP inventory."""
from __future__ import annotations

import json
import ipaddress
import time

from .fortigate import FortiGateError
from .fortigate_fabric import FabricTarget, InventoryError, discover

MAX_DEVICES = 32
MAX_CONTEXTS = 64
MAX_ROWS = 10000
MAX_BYTES = 900 * 1024
SERVER_FIELDS = ('id', 'status', 'interface', 'netmask', 'default-gateway', 'dns-service',
    'dns-server1', 'dns-server2', 'dns-server3', 'dns-server4', 'lease-time', 'domain',
    'server-type', 'ip-mode', 'ntp-service', 'ntp-server1', 'ntp-server2', 'ntp-server3',
    'timezone', 'timezone-option', 'next-server', 'filename', 'tftp-server',
    'wifi-ac-service', 'wifi-ac1', 'wifi-ac2', 'wins-server1', 'wins-server2',
    'mac-acl-default-action', 'vci-match', 'vci-string', 'ddns-update',
    'dhcp-settings-from-fortiipam', 'auto-managed-status', 'shared-subnet')
CHILD_FIELDS = {
    'ip-range': ('id', 'start-ip', 'end-ip', 'lease-time', 'vci-match', 'vci-string', 'uci-match', 'uci-string'),
    'exclude-range': ('id', 'start-ip', 'end-ip'),
    'reserved-address': ('id', 'type', 'ip', 'mac', 'action', 'description',
                         'circuit-id', 'circuit-id-type', 'remote-id', 'remote-id-type'),
    'options': ('id', 'code', 'type', 'value', 'ip', 'vci-match', 'vci-string'),
}
INTERFACE_FIELDS = ('name', 'alias', 'ip', 'type', 'interface', 'vlanid', 'status',
                    'vrf', 'role', 'dhcp-relay-service', 'dhcp-relay-ip')
LEASE_FIELDS = ('id', 'ip', 'mac', 'hostname', 'interface', 'expire_time', 'expiry',
                'reserved', 'server_id', 'server-id', 'server_mkey', 'status', 'type', 'vci')


def project(row, fields):
    return {k: row[k] for k in fields if k in row}


def rows(value):
    if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
        raise InventoryError('Appliance returned an unexpected inventory shape.')
    if len(value) > MAX_ROWS:
        raise InventoryError('Inventory exceeds 10,000 rows; narrow the VDOM or device scope.')
    return value



def collect_inventory(client, *, fabric=False, vdom='root', check=lambda: None):
    """Snapshot selected devices. Separate lookup errors from empty configuration."""
    data = {'captured': time.time(), 'devices': [], 'scopes': [], 'leases': [],
            'warnings': [], 'api_calls': 0, 'read_only': True}
    targets = discover(client, fabric)
    data['api_calls'] = 2 if fabric else 1
    contexts = [(t, v) for t in targets for v in (t.vdoms if vdom == '*' else (vdom,))]
    if len(contexts) > MAX_CONTEXTS:
        raise InventoryError('Inventory exceeds 64 device/VDOM combinations; select a specific VDOM.')
    dns_cache = {}
    with client.pooled() as pooled:
        for target, vd in contexts:
            check()
            device = {'serial': target.serial, 'hostname': target.hostname, 'model': target.model,
                      'vdom': vd, 'via_fabric': bool(target.path), 'errors': [], 'scope_count': 0, 'configuration_read': False}
            data['devices'].append(device)
            def fetch(endpoint, **params):
                check()
                data['api_calls'] += 1
                return target.get(pooled, endpoint, vd, **params)
            def error(label, exc):
                # Never retain raw appliance errors (may contain credentials/configuration).
                device['errors'].append(label + ' unavailable: ' + (
                    str(exc) if isinstance(exc, InventoryError) else
                    'API access denied (HTTP 403).' if getattr(exc, 'status_code', None) == 403 else
                    'API authentication failed (HTTP 401).' if getattr(exc, 'status_code', None) == 401 else
                    'API endpoint unavailable (HTTP 404).' if getattr(exc, 'status_code', None) == 404 else
                    'Read failed; check connectivity and API permissions.'))
            try:
                servers = rows(fetch('/api/v2/cmdb/system.dhcp/server'))
            except (FortiGateError, ValueError, TypeError) as exc:
                error('DHCP configuration', exc)
                continue
            device['configuration_read'] = True
            interfaces = {}
            try:
                interfaces = {x['name']: project(x, INTERFACE_FIELDS) for x in rows(fetch(
                    '/api/v2/cmdb/system/interface', format='|'.join(INTERFACE_FIELDS))) if 'name' in x}
            except (FortiGateError, ValueError, TypeError) as exc:
                error('Interface details', exc)
            if any(s.get('dns-service') == 'default' for s in servers) and target.serial not in dns_cache:
                try:
                    check()
                    data['api_calls'] += 1
                    dns = target.get(pooled, '/api/v2/cmdb/system/dns', format='primary|secondary')
                    if isinstance(dns, list):
                        dns = dns[0] if dns else {}
                    dns_cache[target.serial] = [dns[k] for k in ('primary', 'secondary') if dns.get(k) and dns[k] != '0.0.0.0']
                except (FortiGateError, ValueError, TypeError, AttributeError) as exc:
                    error('System DNS settings', exc)
                    dns_cache[target.serial] = []
            for server in servers:
                scope = project(server, SERVER_FIELDS)
                for key, fields in CHILD_FIELDS.items():
                    scope[key] = [project(r, fields) for r in rows(server.get(key, []))]
                networks = set()
                for address_range in scope['ip-range']:
                    try:
                        networks.add(str(ipaddress.IPv4Network(f"{address_range['start-ip']}/{scope['netmask']}", strict=False)))
                    except (KeyError, ValueError):
                        pass
                scope['subnets'] = sorted(networks)
                scope.update(device=target.hostname, serial=target.serial, vdom=vd,
                             interface_details=interfaces.get(server.get('interface'), {}))
                if server.get('dns-service') == 'default':
                    scope['system_dns'] = dns_cache.get(target.serial, [])
                data['scopes'].append(scope)
            device['scope_count'] = len(servers)
            try:
                for lease in rows(fetch('/api/v2/monitor/system/dhcp', ipv6='false')):
                    data['leases'].append({**project(lease, LEASE_FIELDS), 'device': target.hostname,
                                           'serial': target.serial, 'vdom': vd})
            except (FortiGateError, ValueError, TypeError) as exc:
                error('Live leases', exc)
            if len(json.dumps(data).encode()) > MAX_BYTES:
                raise InventoryError('Inventory exceeds the retained result limit; select one device or VDOM. No truncated inventory was saved.')
    data['partial'] = any(d['errors'] for d in data['devices'])
    data['message'] = ('Partial inventory' if data['partial'] else 'Inventory complete') + f": {len(data['scopes'])} DHCP servers."
    return data


def lease_duration(value):
    if value is None:
        return 'Not reported'
    try:
        seconds = int(value)
    except (ValueError, TypeError):
        return str(value)
    if seconds == 0:
        return 'Unlimited (0 seconds)'
    remaining = seconds
    parts = []
    for unit, size in [('d', 86400), ('h', 3600), ('m', 60), ('s', 1)]:
        n, remaining = divmod(remaining, size)
        if n:
            parts.append(f'{n}{unit}')
    return ' '.join(parts)
