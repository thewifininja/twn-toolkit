"""Validated, reviewable installation plans. No changes occur while planning."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import socket
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .setup_dependencies import host_platform, inventory, selected_packages, executable_path
from .server_settings import normalize_preferred_fqdn


@dataclass
class SetupPlan:
    location: str
    service: bool = False
    packages: list[str] = field(default_factory=list)
    hostname: str = ''
    timezone: str = ''
    network: bool = False
    lldpd: bool = False
    pf_interfaces: list[str] = field(default_factory=list)

    @classmethod
    def read(cls, value: dict) -> 'SetupPlan':
        if not isinstance(value, dict) or set(value) - set(cls.__dataclass_fields__):
            raise ValueError('Setup configuration contains unknown fields.')
        plan = cls(**value)
        for key in ('service','network','lldpd'):
            if type(getattr(plan,key)) is not bool:
                raise ValueError(f'{key} must be true or false.')
        for key in ('location','hostname','timezone'):
            if not isinstance(getattr(plan,key),str):
                raise ValueError(f'{key} must be text.')
        for key in ('packages','pf_interfaces'):
            values = getattr(plan,key)
            if not isinstance(values,list) or len(values)>40 or not all(isinstance(v,str) for v in values):
                raise ValueError(f'{key} must be a bounded list of names.')
        return plan


def read_settings(path: Path) -> dict:
    if not path.exists():
        return {}
    if path.stat().st_size > 1024*1024:
        raise ValueError(f'Settings file is too large: {path.name}')
    value = json.loads(path.read_text())
    if not isinstance(value,dict):
        raise ValueError(f'Invalid settings object: {path.name}')
    return value


def service_definition(system: str) -> tuple[str,str]:
    from .service_cli import _service_definition_details, SYSTEMD_UNIT_PATH, LAUNCHD_PLIST_PATH
    path = SYSTEMD_UNIT_PATH if system=='Linux' else LAUNCHD_PLIST_PATH
    if not path.is_file():
        return '', ''
    owner, _, location = _service_definition_details(path,system=system)
    return owner, location or '<unrecognized>'


def installed_service(root: Path, system: str) -> bool:
    _, location = service_definition(system)
    return bool(location) and Path(location).resolve()==root.resolve()


def initial_plan(root: Path, host: dict) -> SetupPlan:
    server = read_settings(root/'instance/server_settings.json')
    times = read_settings(root/'instance/time_settings.json')
    service = installed_service(root,host['system'])
    # Preserve installed capability choice; a rerun must not silently remove it.
    network = False
    unit = Path('/etc/systemd/system/twn-toolkit.service')
    if service and host['system'] == 'Linux' and unit.is_file():
        network = 'CAP_NET_RAW' in unit.read_text()
    return SetupPlan(str(root), service=service, hostname=server.get('preferred_fqdn',''),
                     timezone=times.get('timezone',''), network=network)


def validate(plan: SetupPlan, root: Path, host: dict, *, prerequisites: bool = True) -> Path:
    SetupPlan.read(asdict(plan))
    if not plan.location or any(ord(c)<32 for c in plan.location):
        raise ValueError('Choose a valid installation folder.')
    raw = Path(plan.location).expanduser()
    if not raw.is_absolute():
        raise ValueError('Use an absolute installation path or ~/folder.')
    target = raw.resolve()
    if target == Path('/') or any(c in str(target) for c in '\n\r\0'):
        raise ValueError('Choose a dedicated toolkit folder.')
    space_root = target if target.exists() else target.parent
    if space_root.exists() and shutil.disk_usage(space_root).free < 512*1024*1024:
        raise ValueError('Keep at least 512 MiB free for setup. Package builds can require additional space.')
    if host['system'] not in {'Linux','Darwin'}:
        raise ValueError('Guided setup supports Linux and macOS.')
    if os.geteuid() == 0:
        raise ValueError('Run guided setup as your regular account. Selected privileged steps will use sudo.')
    if target != root:
        if target.is_relative_to(root) or root.is_relative_to(target):
            raise ValueError('The destination cannot contain, or be inside, the current checkout.')
        if (root/'instance').exists() and any((root/'instance').iterdir()):
            raise ValueError('An existing instance must be relocated offline with its data. Choose the current folder; see docs/guided-installation.md.')
        if target.exists() and (not target.is_dir() or any(target.iterdir())):
            raise ValueError('The destination must be empty. Existing files will not be overwritten.')
        if not target.parent.is_dir():
            raise ValueError('Create the destination parent folder first.')
    owner, service_root = service_definition(host['system'])
    if plan.service and service_root:
        if service_root=='<unrecognized>' or Path(service_root).resolve() != target:
            raise ValueError('An existing toolkit service points to a different or unrecognized location. Use that checkout or explicitly uninstall the old service first.')
        if owner and owner != pwd.getpwuid(os.getuid()).pw_name:
            raise ValueError('Re-run setup as the existing toolkit service account; ownership is not changed automatically.')
    if plan.service and host['system'] == 'Darwin':
        from .service_cli import _validate_macos_service_location, service_user
        # service_cli has no third-party imports and this location check is observational.
        _validate_macos_service_location(target, service_user(None))
    if plan.service and host['system'] == 'Linux' and not Path('/run/systemd/system').is_dir():
        raise ValueError('Automatic service mode needs a running systemd host. Choose manual mode here.')
    if not plan.service and installed_service(root,host['system']):
        raise ValueError('A toolkit service is already installed. Keep service mode, or explicitly uninstall it with ./twn service uninstall before choosing manual mode.')
    if plan.network and (host['system'] != 'Linux' or not plan.service):
        raise ValueError('Linux network capabilities require service mode. On macOS select ChmodBPF instead.')
    normalize_preferred_fqdn(plan.hostname)
    if plan.timezone:
        try:
            ZoneInfo(plan.timezone)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError('Choose a valid timezone or follow the host.') from exc
    if plan.pf_interfaces:
        if host['system'] != 'Darwin' or len(set(plan.pf_interfaces)) != len(plan.pf_interfaces):
            raise ValueError('PF compatibility requires unique macOS interface names.')
        available = {name for _,name in socket.if_nameindex()}
        if any(not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.:-]{0,31}', name) or name not in available for name in plan.pf_interfaces):
            raise ValueError('Choose currently present interfaces for PF compatibility.')
    if not prerequisites:
        return target
    rows = inventory(root,system=host['system'])
    if any(row['id']=='venv' and not row['present'] for row in rows) and 'venv' not in plan.packages:
        raise ValueError('Python virtual-environment support is missing. Select that prerequisite or install python3-venv before setup.')
    selected_packages(plan.packages,host)
    if plan.packages and not host['manager']:
        raise ValueError('The package manager is unavailable. Install it using the platform instructions, or deselect optional packages.')
    if plan.lldpd and not any(row['id']=='lldpd' and row['present'] for row in inventory(target,system=host['system'])) and 'lldpd' not in plan.packages:
        raise ValueError('Select the lldpd package or install it first before enabling its daemon.')
    if plan.lldpd and host['system']=='Darwin':
        raise ValueError('Manage the macOS lldpd daemon separately; setup never runs Homebrew as root. See docs/guided-installation.md.')
    if plan.lldpd and host['system']=='Linux' and not Path('/run/systemd/system').is_dir():
        raise ValueError('Automatic lldpd daemon setup needs systemd; configure the daemon manually here.')
    return target


def package_commands(plan: SetupPlan, host: dict) -> list[list[str]]:
    packages,casks = selected_packages(plan.packages,host)
    if not packages and not casks:
        return []
    manager = host['manager']
    if not manager:
        raise ValueError('Package manager is unavailable; no package command will run.')
    if host['adapter']=='apt':
        return [['sudo',manager,'install','--',*packages]]
    if host['adapter']=='pacman':
        # Never run -Sy alone: that would create an unsupported partial upgrade.
        return [['sudo',manager,'-S','--needed','--',*packages]]
    if host['adapter']=='brew':
        if os.geteuid()==0:
            raise ValueError('Homebrew must never run as root.')
        return ([ [manager,'install','--formula',*packages] ] if packages else []) + ([ [manager,'install','--cask',*casks] ] if casks else [])
    raise ValueError('Unsupported package-manager adapter.')


def review(plan: SetupPlan, root: Path, host: dict) -> list[tuple[str,str]]:
    target = Path(plan.location).expanduser().resolve()
    username = pwd.getpwuid(os.getuid()).pw_name
    rows = [('Platform',host['name']),('Location',str(target)),('Run mode','Automatic service' if plan.service else 'Manual startup'),
            ('Service user',username),('Hostname',plan.hostname or 'Automatic / local addresses'),('Timezone',plan.timezone or 'Follow host'),
            ('Optional tools',', '.join(plan.packages) or 'None'),('LLDP daemon','Enable and start' if plan.lldpd else 'Keep current state'),
            ('Network permissions','Linux service capabilities' if plan.network else 'Keep OS permissions'),
            ('Multicast PF',', '.join(plan.pf_interfaces) or 'No changes')]
    if target != root and not target.exists() and not os.access(target.parent,os.W_OK):
        user = pwd.getpwuid(os.getuid())
        rows.append(('Command',shlex.join(['sudo','/usr/bin/install','-d','-o',str(user.pw_uid),'-g',str(user.pw_gid),'-m','0755',str(target)])))
    if target != root:
        rows.append(('Copy','Release source only; no .venv, instance, Git history, or private files. Source stays intact.'))
    from .setup_dependencies import DEPENDENCIES
    rows.extend((spec.name,spec.note) for spec in DEPENDENCIES if spec.id in plan.packages and spec.note)
    rows.extend(('Command',shlex.join(command)) for command in package_commands(plan,host))
    if plan.packages:
        rows.append(('Packages','Package-manager prompts remain enabled. Package scripts can start system services.'))
    if plan.service:
        rows.append(('Command',shlex.join([str(target/'twn'),'service','install','--user',username]+(['--network-capabilities'] if plan.network else []))))
    if plan.lldpd:
        rows.append(('Command',shlex.join(['sudo','systemctl','enable','--now','lldpd'] if host['system']=='Linux' else ['launchctl','print','system/homebrew.mxcl.lldpd'])))
    if plan.pf_interfaces:
        rows.append(('Command',shlex.join(['sudo',str(target/'.venv/bin/python'),'-m','twn_toolkit.macos_multicast_pf_cli','install','--interfaces',*plan.pf_interfaces])))
        rows.append(('PF consent','Only the dedicated TWN anchor; preserve backup/removal. No live PF reload. Restart macOS before relying on new rules.'))
    rows.append(('Authorization','The OS requests privileges only for selected steps. Toolkit never stores your password.'))
    return rows
