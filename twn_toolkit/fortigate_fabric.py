"""Shared read-only FortiGate Fabric discovery and response identity checks."""
from dataclasses import dataclass
import re
from .fortigate import FortiGateError
MAX_DEVICES = 32
SERIAL = re.compile(r'[A-Za-z0-9_-]{1,64}\Z')
class InventoryError(FortiGateError):
    """Locally generated, display-safe inventory validation failure."""

def rows(value):
    if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
        raise InventoryError('Appliance returned an unexpected Fabric inventory shape.')
    return value

@dataclass(frozen=True)
class FabricTarget:
    serial: str
    hostname: str
    path: str = ''
    model: str = ''
    vdoms: tuple = ('root',)

    def get(self, client, endpoint, vdom=None, **params):
        # Only fixed internal API endpoints may be routed. Never accept URLs from a form.
        if not endpoint.startswith('/api/v2/') or any(c in endpoint for c in ('?', '#', '..')):
            raise ValueError('Invalid inventory endpoint.')
        parts = self.path.split(':') if self.path else [self.serial]
        if any(not SERIAL.fullmatch(p) for p in parts) or parts[-1] != self.serial:
            raise InventoryError('Invalid Fabric target path.')
        route = ('/csf/' + self.path if self.path else '') + endpoint
        result = client.request('GET', route, params={**params, **({'vdom': vdom} if vdom else {})})
        if result.get('serial') != self.serial or result.get('status') != 'success':
            raise InventoryError('Response identity did not match the selected FortiGate. Data rejected.')
        if vdom and result.get('vdom') != vdom:
            raise InventoryError('Response VDOM did not match the selected VDOM. Data rejected.')
        if result.get('limit_reached'):
            raise InventoryError('Appliance returned an incomplete page; narrow the inventory scope.')
        return result.get('results')


def discover(client, fabric):
    status = client.test_connection()
    serial = status.get('serial', '')
    if not SERIAL.fullmatch(serial) or status.get('status') != 'success':
        raise InventoryError('Unable to verify the connected FortiGate identity.')
    info = status.get('results', {})
    root = FabricTarget(serial, info.get('hostname') or serial, model=info.get('model_number', ''))
    # A single-device scan remains usable without Security Fabric permissions.
    if not fabric:
        return [root]
    result = root.get(client, '/api/v2/monitor/system/csf')
    devices = rows(result.get('devices', {}).get('fortigate', []))
    if len(devices) > MAX_DEVICES:
        raise InventoryError('Fabric exceeds 32 FortiGates; use a direct profile for a smaller scope.')
    targets, seen = [], set()
    for d in devices:
        sn = d.get('serial', '')
        path = '' if sn == serial else d.get('proxy_path') or d.get('path', '')
        parts = path.split(':')
        if not SERIAL.fullmatch(sn) or sn in seen or (sn != serial and
                (not path or parts[0] != serial or parts[-1] != sn or
                 any(not SERIAL.fullmatch(p) for p in parts))):
            raise InventoryError('Fabric discovery returned an ambiguous device identity or path.')
        vdoms = d.get('vdoms') or ['root']
        if not isinstance(vdoms, list) or any(not isinstance(v, str) or not v or len(v)>80 for v in vdoms):
            raise InventoryError('Invalid VDOM inventory.')
        targets.append(FabricTarget(sn, d.get('host_name') or d.get('state', {}).get('hostname') or sn,
                                   path, d.get('model_number', ''), tuple(vdoms)))
        seen.add(sn)
    if serial not in seen:
        targets.insert(0, root)
    if len(targets) > MAX_DEVICES:
        raise InventoryError('Fabric exceeds 32 FortiGates; use a direct profile for a smaller scope.')
    return targets

