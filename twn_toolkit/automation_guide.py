"""Validate and atomically create a reviewed, paused first automation."""
import hashlib
import hmac
import time
from twn_toolkit.auth import load_or_create_secret_key
import json
from contextlib import contextmanager
from copy import copy

from twn_toolkit.automation_registry import AUTOMATION_REGISTRY
from twn_toolkit.schedule_tools import schedule_preview, validate_schedule_config
from twn_toolkit.ssh_commandlets import build_ssh_command_plans


def prepare_guide(store, form):
    name = ' '.join(str(form.get('name', '')).split())
    if not 2 <= len(name) <= 80:
        raise ValueError('Enter an automation name of 2–80 characters.')
    if len(str(form.get('username', ''))) > 256 or len(str(form.get('password', ''))) > 4096:
        raise ValueError('SSH credentials exceed the guided input limit.')
    interval = int(form.get('interval_seconds', 30))
    trigger_after = int(form.get('trigger_after', 3))
    recover_after = int(form.get('recover_after', 3))
    cooldown = int(form.get('cooldown_seconds', 300))
    if not (1 <= interval <= 86400 and 1 <= trigger_after <= 100 and
            1 <= recover_after <= 100 and 0 <= cooldown <= 604800):
        raise ValueError('Review the check interval, trigger/recovery thresholds and cooldown.')
    source_id = str(form.get('source_id', ''))
    action_id = str(form.get('action_id', ''))
    source_kind = str(form.get('source_kind', 'manual'))
    if source_kind == 'saved':
        source = store.get_condition_definition(source_id)
        if not source:
            raise ValueError('Select a saved condition or schedule.')
    elif source_kind == 'manual':
        source = {'type': 'manual.trigger', 'config': {}}
    elif source_kind == 'ping':
        source = {'type': 'ping.multi', 'config': {'targets': form.get('targets', ''),
                  'timeout': 1, 'probe_count': 1, 'failure_mode': 'at_least', 'failure_count': 1}}
    elif source_kind == 'daily':
        source = {'type': 'schedule.calendar', 'config': validate_schedule_config({
            'timezone': form.get('timezone', 'UTC'), 'missed_policy': 'skip',
            'rules': [{'id': 'guided-daily', 'type': 'daily', 'time': form.get('daily_time', '09:00')}]})}
    else:
        raise ValueError('Choose when this automation should run.')
    validator = AUTOMATION_REGISTRY.validate_trigger if source['type'] in AUTOMATION_REGISTRY.triggers else AUTOMATION_REGISTRY.validate_condition
    source = {'type': source['type'], 'config': validator(source['type'], source['config'])}
    if form.get('action_kind', 'new_ssh') == 'saved':
        action = store.get_action_definition(action_id, include_secrets=True)
        if not action:
            raise ValueError('Select a saved action.')
    elif form.get('action_kind', 'new_ssh') == 'new_ssh':
        action = {'type': 'ssh.collect', 'config': {
            'hosts': form.get('ssh_hosts', ''), 'username': form.get('username', ''),
            'password': form.get('password', ''), 'commands': form.get('commands', ''),
            'port': int(form.get('port', 22)), 'command_timeout': int(form.get('command_timeout', 300)),
            'allow_unknown_hosts': form.get('allow_unknown_hosts') == 'on', 'send_ctrl_y': False}}
    else:
        raise ValueError('Choose a saved action or create SSH command collection.')
    action = {'type': action['type'], 'config': AUTOMATION_REGISTRY.validate_action(action['type'], action['config'])}
    values = {'name': name, 'interval_seconds': interval, 'trigger_after': trigger_after,
              'recover_after': recover_after, 'cooldown_seconds': cooldown,
              'condition': source, 'actions': [action]}
    if source_kind == 'saved':
        values['condition_definition_ids'] = [source_id]
    if form.get('action_kind') == 'saved':
        values['action_definition_ids'] = [action_id]
    digest = hmac.new(load_or_create_secret_key(str(store.instance_path)).encode(), json.dumps(values, sort_keys=True, separators=(',', ':')).encode(), hashlib.sha256).hexdigest()
    source_type = source['type']
    if source_type == 'manual.trigger':
        when = 'When you explicitly choose Run now.'
        recovery = 'No automatic health recovery or repeat schedule.'
        next_run = 'Only after an explicit Run now; saving does not execute actions.'
    elif source_type == 'system.startup':
        event = 'host boot' if source['config']['mode'] == 'host_boot' else 'complete toolkit start'
        when = f"After the next {event} following arming; wait up to {source['config']['network_wait_seconds']} seconds for network readiness."
        recovery = 'The current startup becomes the baseline when armed; one run per matching startup.'
        next_run = 'The next matching startup event, not a predicted calendar time.'
    elif source_type == 'network.interface_change':
        when = f"When monitored addresses change and remain stable for {source['config']['stabilization_seconds']} seconds."
        recovery = 'The first observation establishes a silent baseline; later stable changes trigger runs.'
        next_run = 'Depends on a future address change after arming; validation does not observe or change interfaces.'
    elif source_type == 'schedule.calendar':
        when = 'At the selected calendar occurrences, after you arm the automation.'
        recovery = 'Calendar runs do not use health-recovery thresholds.'
        occurrences = schedule_preview(source['config'], time.time(), 3)
        next_run = 'Next scheduled occurrences: ' + '; '.join(item['display'] for item in occurrences) if occurrences else 'No future occurrences in the selected schedule.'
    else:
        when = f'Check every {interval} seconds; run after {trigger_after} consecutive met checks.'
        recovery = f'Reset after {recover_after} clear checks; cooldown {cooldown} seconds before another eligible run.'
        next_run = 'Depends on future checks after you arm it; validation sends no probes.'
    commands = []
    if action['type'] == 'ssh.collect':
        config = action['config']
        plans = build_ssh_command_plans(config['matrix'], config['commands'], config['command_timeout'])['plans']
        if len(plans) > 20 or any(len(p['commands']) > 20 for p in plans):
            raise ValueError('Guided SSH setup supports 20 hosts and 20 commands. Use the advanced editor for larger plans.')
        if sum(len(c.encode()) for p in plans for c in p['commands']) > 128 * 1024:
            raise ValueError('Rendered commands exceed the guided review limit. Use a smaller plan or the advanced editor.')
        commands = [{'host': p['host'], 'commands': p['commands']} for p in plans]
        doing = f"Run the reviewed SSH commands on {len(plans)} hosts."
    else:
        doing = AUTOMATION_REGISTRY.actions[action['type']].label
    from .json_stream import iter_pretty_json
    secret_fields = set(AUTOMATION_REGISTRY.actions[action['type']].secret_fields)
    settings = {key: value for key, value in action['config'].items()
                if key not in secret_fields and key not in {'commands', 'matrix', 'hosts', 'variables', 'target_count'}}
    public = {'Trigger settings': source['config'], 'Action settings': settings}
    parts = []
    size = 0
    for part in iter_pretty_json(public):
        size += len(part)
        if size > 64 * 1024:
            raise ValueError('Saved settings exceed the guided review limit. Use the advanced editor.')
        parts.append(part)
    return values, digest, {'when': when, 'doing': doing, 'recovery': recovery,
                            'next_run': next_run, 'commands': commands, 'settings': ''.join(parts)}


def save_guide_atomically(store, values, actor):
    with store._connect() as connection:
        connection.execute('BEGIN IMMEDIATE')
        @contextmanager
        def borrowed():
            yield connection
        isolated = copy(store)
        isolated._connect = borrowed
        for key, expected, getter in (
            ('condition_definition_ids', values['condition'], isolated.get_condition_definition),
            ('action_definition_ids', values['actions'][0], lambda ident: isolated.get_action_definition(ident, include_secrets=True)),
        ):
            if values.get(key):
                current = getter(values[key][0])
                if not current:
                    raise ValueError('A reusable object changed after review. Validate again before creating.')
                validator = AUTOMATION_REGISTRY.validate_action if key == 'action_definition_ids' else (
                    AUTOMATION_REGISTRY.validate_trigger if current['type'] in AUTOMATION_REGISTRY.triggers else AUTOMATION_REGISTRY.validate_condition)
                normalized = {'type': current['type'], 'config': validator(current['type'], current['config'])}
                if normalized != expected:
                    raise ValueError('A reusable object changed after review. Validate again before creating.')
        return isolated.save(**values, created_by=actor)
