"""Experimental, read-only switch topology inspection. No inferred guard state."""
import time
from .fortigate_fabric import discover, rows, InventoryError
from .fortigate import FortiGateError

STATUS = '/api/v2/monitor/switch-controller/managed-switch/status'
CONFIG = '/api/v2/cmdb/switch-controller/managed-switch'
MAX_SWITCHES = 128
MAX_PORTS = 4096


def text(value):
    return str(value or '')[:256]


def analyze(switches):
    """Explain physical relationships without declaring forwarding loops."""
    index = {s['id']: s for s in switches}
    findings = []
    for switch in switches:
        if switch.get('connection') != 'Connected':
            continue
        peers = {}
        for port in switch['ports']:
            peer = port['peer']
            if not peer or port['link'] != 'up':
                continue
            peers.setdefault(peer, []).append(port)
            reason = ''
            if peer == switch['id']:
                reason = 'Port reports its own switch as its inter-switch peer.'
            elif peer not in index:
                reason = 'Peer is outside the collected switch inventory; reciprocal link cannot be checked.'
            else:
                remote = next((p for p in index[peer]['ports'] if p['name'] == port['peer_port']), None)
                if not remote or remote['peer'] != switch['id'] or remote['peer_port'] != port['name']:
                    reason = 'The reported peer port does not report the reciprocal link. This may be stale or incomplete topology data.'
            if reason:
                findings.append(dict(switch=switch['id'], ports=port['name'], kind='Review', message=reason))
            if port['stp_config'] == 'disabled' and not port['mclag']:
                findings.append(dict(switch=switch['id'], ports=port['name'], kind='Review',
                    message='STP is configured disabled on an inter-switch link. Review the intended redundancy design; this alone does not prove a loop.'))
        for peer, ports in peers.items():
            if len(ports) < 2:
                continue
            grouped = len({p['peer_trunk'] for p in ports}) == 1 and bool(ports[0]['peer_trunk'])
            duplicate = len({p['peer_port'] for p in ports if p['peer_port']}) != len(ports)
            findings.append(dict(switch=switch['id'], ports=', '.join(p['name'] for p in ports),
                kind='Topology' if grouped and not duplicate else 'Review',
                message=(f'Parallel links to {peer} share a reported peer trunk. Aggregate health and STP state are not verified.'
                         if grouped and not duplicate else f'Multiple links to {peer} have no unambiguous shared peer trunk/remote-port mapping. Review cabling and aggregation.')))
    return findings


def collect(client, *, fabric=False, vdom='root', check=lambda: None):
    data = dict(captured=time.time(), gates=[], partial=False, api_calls=0, switch_count=0, port_count=0)
    check()
    targets = discover(client, fabric)
    data['api_calls'] += 2 if fabric else 1
    for target in targets:
        check()
        gate = dict(hostname=target.hostname, serial=target.serial, vdom=vdom, via_fabric=bool(target.path), switches=[], findings=[], errors=[])
        data['gates'].append(gate)
        try:
            data['api_calls'] += 1
            inventory = rows(target.get(client, STATUS, vdom))
        except FortiGateError as exc:
            gate['errors'].append(text(str(exc).replace(client.api_key, '[redacted]')))
            data['partial'] = True
            continue
        check()
        config = {}
        try:
            data['api_calls'] += 1
            for entry in rows(target.get(client, CONFIG, vdom, format='switch-id|ports')):
                identifier = str(entry.get('switch-id', ''))
                if identifier in config:
                    raise InventoryError('Duplicate switch configuration identity.')
                config[identifier] = {p.get('port-name'): p for p in rows(entry.get('ports', []))}
        except FortiGateError as exc:
            config = {}
            gate['errors'].append('Configuration unavailable: ' + text(str(exc).replace(client.api_key, '[redacted]')))
            data['partial'] = True
        ids, serials = set(), set()
        for raw in inventory:
            check()
            identifier, serial = raw.get('switch-id'), raw.get('serial')
            if (not isinstance(identifier, str) or not identifier or len(identifier)>256 or
                    not isinstance(serial, str) or not serial or len(serial)>256 or identifier in ids or serial in serials):
                raise InventoryError('Missing or ambiguous switch identity. Snapshot rejected.')
            ids.add(identifier); serials.add(serial)
            if identifier not in config:
                data['partial'] = True
                gate['errors'].append('Port configuration unavailable for ' + identifier + '.')
            switch = dict(id=identifier, serial=serial, firmware=text(raw.get('os_version')),
                connection=text(raw.get('status')), ports=[])
            gate['switches'].append(switch)
            data['switch_count'] += 1
            seen_ports = set()
            for p in rows(raw.get('ports', [])):
                name = p.get('interface')
                if not isinstance(name, str) or not name or len(name)>256 or name in seen_ports:
                    raise InventoryError('Missing or ambiguous port identity. Snapshot rejected.')
                seen_ports.add(name)
                cfg = config.get(identifier, {}).get(name, {})
                switch['ports'].append(dict(name=name, link=text(p.get('status')),
                    peer=text(p.get('isl_peer_device_name')), peer_port=text(p.get('isl_peer_port_name')),
                    peer_trunk=text(p.get('isl_peer_trunk_name')), fortilink=p.get('fortilink_port') is True,
                    mclag=p.get('mclag') is True or p.get('mclag_icl') is True,
                    stp_config=text(cfg.get('stp-state')) or 'Unavailable',
                    loop_config=text(cfg.get('loop-guard')) or 'Unavailable',
                    stp_state='Unavailable', loop_state='Unavailable'))
                data['port_count'] += 1
                if data['port_count'] > MAX_PORTS:
                    raise InventoryError('Inspector exceeds 4,096 ports. Select a smaller gate scope.')
            if data['switch_count'] > MAX_SWITCHES:
                raise InventoryError('Inspector exceeds 128 switches. Select a smaller gate scope.')
        gate['findings'] = analyze(gate['switches'])
    data['review_count'] = sum(f['kind']=='Review' for g in data['gates'] for f in g['findings'])
    data['coverage'] = 'Operational Loop Guard, STP roles/states and full LLDP are unavailable in this API prototype. No loop-free assessment is possible.'
    return data
