"""Owner/tool/profile-bound single-gate selection for reviewed actions."""
import time
from flask import abort, g, request
from .diagnostic_routes import diagnostic_store

OPERATIONS = {'rename-aps':'fortigate.rename_aps', 'rename-switches':'fortigate.rename_switches',
              'switch-order':'fortigate.switch_order', 'wireless-history':'fortigate.wireless_client_history'}


def selected_profile(profile, operation):
    if not profile:
        return profile
    identifier = request.form.get('fabric_discovery', '')
    serials = [value for value in request.form.getlist('fabric_serial') if value]
    if not identifier and not serials:
        return profile
    if operation not in OPERATIONS:
        abort(400, 'This task does not support this Fabric selection.')
    job = diagnostic_store().get(identifier, g.current_user['id']) if identifier else None
    if (not job or job['tool']!='appliance_read' or job['state']!='succeeded' or
            job['config'].get('mode')!='fabric_discovery' or
            job['config'].get('tool_id')!=OPERATIONS[operation] or
            job['config'].get('profile')!=profile or time.time()-job['completed']>900 or len(serials)!=1):
        abort(400, 'Discover the Fabric again and select one gate for this profile and task.')
    target = next((t for t in job['summary'].get('targets', []) if t['serial']==serials[0]), None)
    if not target:
        abort(400, 'The selected gate was not in this Fabric discovery.')
    return {**profile, '_fabric_target':target, '_fabric_operation':operation}
