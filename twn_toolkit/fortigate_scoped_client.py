"""Selected-gate transport for reviewed actions and wireless history."""
from dataclasses import dataclass, field
from urllib.parse import unquote

from .fortigate import FortiGateClient
from .fortigate_fabric import FabricTarget, SERIAL, InventoryError

BASE_AP = '/api/v2/cmdb/wireless-controller/wtp'
BASE_SWITCH = '/api/v2/cmdb/switch-controller/managed-switch'
STATUS = '/api/v2/monitor/system/status'
RENAME_OPERATIONS = {'rename-aps', 'rename-switches'}
WRITE_OPERATIONS = RENAME_OPERATIONS | {'switch-order'}
HISTORY_READS = {
    '/api/v2/log/memory/event/wireless', '/api/v2/log/disk/event/wireless',
    '/api/v2/monitor/wifi/client', '/api/v2/monitor/wireless-controller/client',
    '/api/v2/monitor/wireless-controller/clients', '/api/v2/monitor/wireless-controller/wtp/client',
}


def base_profile(profile):
    """Remove only transient job targeting before comparing the saved profile."""
    return {key: value for key, value in profile.items()
            if key not in ('_fabric_target', '_fabric_operation')}


@dataclass(frozen=True)
class FabricScopedClient(FortiGateClient):
    target: dict = field(default_factory=dict)
    operation: str = ''

    def request(self, method, endpoint, params=None, json=None, *, _budget=None):
        target = FabricTarget(**self.target)
        parts = target.path.split(':') if target.path else [target.serial]
        if parts[-1] != target.serial or any(not SERIAL.fullmatch(part) for part in parts):
            raise InventoryError('Invalid selected FortiGate identity or path.')
        base = BASE_AP if self.operation == 'rename-aps' else BASE_SWITCH
        decoded = unquote(endpoint)
        object_endpoint = (endpoint.startswith(base + '/') and
                           bool(decoded[len(base) + 1:]) and '/' not in decoded[len(base) + 1:])
        allowed = (
            endpoint == STATUS or
            (self.operation in WRITE_OPERATIONS and (endpoint == base or object_endpoint)) or
            (self.operation == 'wireless-history' and endpoint in HISTORY_READS)
        )
        if not allowed or any(char in decoded for char in ('?', '#', '..')):
            raise InventoryError('This endpoint is not supported for the selected Fabric task.')
        if method not in ('GET', 'PUT') or (
                method == 'PUT' and (self.operation not in WRITE_OPERATIONS or not object_endpoint)):
            raise InventoryError('This operation is not supported for the selected Fabric task.')
        if method == 'PUT':
            if self.operation == 'switch-order':
                if json is not None or (params or {}).get('action') != 'move' or not (params or {}).get('after'):
                    raise InventoryError('Invalid reviewed switch move.')
            else:
                expected = {'name', 'switch-id'} if self.operation == 'rename-switches' else {'name'}
                if (not isinstance(json, dict) or len(json) != 1 or not set(json) <= expected or
                        (params or {}).get('action')):
                    raise InventoryError('Invalid reviewed rename operation.')
        prefix = '/csf/' + target.path if target.path else ''

        def validate(result, vdom):
            if result.get('serial') != target.serial or result.get('status') != 'success':
                raise InventoryError('Response identity did not match the selected FortiGate. '
                                     'Data rejected; reconcile any attempted change.')
            if vdom and result.get('vdom') != vdom:
                raise InventoryError('Response VDOM did not match the selected VDOM. '
                                     'Data rejected; reconcile any attempted change.')
            # The existing wireless log reader owns pagination and its cumulative budget.
            if result.get('limit_reached') and not endpoint.startswith('/api/v2/log/'):
                raise InventoryError('FortiGate returned incomplete data; narrow the scope before continuing.')
            return result

        # Existing workers retain intent before calling. Verify the proxy before each
        # PUT; a missing or mismatched acknowledgement remains unknown, never replayed.
        if method == 'PUT':
            validate(super().request('GET', prefix + STATUS), None)
        result = super().request(method, prefix + endpoint, params=params, json=json, _budget=_budget)
        return validate(result, (params or {}).get('vdom'))
