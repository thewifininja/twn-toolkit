"""Shared external dependency inventory; importable before Python packages exist."""
from __future__ import annotations

from dataclasses import dataclass
import os
import importlib.util
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from pathlib import Path
import platform
import shutil


@dataclass(frozen=True)
class Dependency:
    id: str
    name: str
    purpose: str
    commands: tuple[str, ...] = ()
    apt: tuple[str, ...] = ()
    pacman: tuple[str, ...] = ()
    brew: tuple[str, ...] = ()
    systems: tuple[str, ...] = ('Linux', 'Darwin')
    category: str = 'optional'
    note: str = ''
    all_commands: bool = False


DEPENDENCIES = (
    Dependency('python', 'Python 3.10+', 'Toolkit runtime and virtual environment', ('python3',), ('python3','python3-venv'), ('python',), ('python',), category='bootstrap'),
    Dependency('venv', 'Python virtual-environment support', 'Create the isolated toolkit Python environment', apt=('python3-venv',), pacman=('python',), brew=('python',), category='system', note='Required before installing Python dependencies.'),
    Dependency('tzdata', 'Timezone database', 'City/region timezone selection', apt=('tzdata',), pacman=('tzdata',), category='system', note='OS timezone data. If absent, install it and revisit setup to select a city; Follow host works without an override.'),
    Dependency('build', 'Native Python build tools', 'Compile dependencies when compatible binary wheels are unavailable', ('cc','make','pkg-config','cargo'), ('build-essential','python3-dev','libffi-dev','libssl-dev','pkg-config','cargo'), ('base-devel','rust'), category='optional', all_commands=True, note='On macOS install Apple Command Line Tools and Rust separately if pip needs native builds.'),
    Dependency('ping', 'Ping', 'Ping, Path MTU and automation fallback', ('ping',), ('iputils-ping',), ('iputils',), category='system'),
    Dependency('traceroute', 'Traceroute', 'Route diagnostics', ('traceroute',), ('traceroute',), ('traceroute',)),
    Dependency('tcpdump', 'tcpdump', 'Packet capture', ('tcpdump',), ('tcpdump',), ('tcpdump',), ('tcpdump',), note='Capture permissions must be verified separately.'),
    Dependency('iperf3', 'iPerf3', 'Throughput client and managed server', ('iperf3',), ('iperf3',), ('iperf3',), ('iperf3',), note='The toolkit manages its own listeners; do not enable a separate iPerf daemon.'),
    Dependency('fping', 'fping', 'Accelerated live Ping', ('fping',), ('fping',), ('fping',), ('fping',), note='Presence alone does not prove raw-socket permission.'),
    Dependency('lsof', 'lsof', 'Listener recovery fallback', ('lsof',), ('lsof',), ('lsof',), ('lsof',)),
    Dependency('lldpd', 'lldpd + lldpcli', 'LLDP Lab neighbors and announcements', ('lldpd','lldpcli'), ('lldpd',), ('lldpd',), ('lldpd',), all_commands=True,
               note='Requires a running daemon and access to its control socket. Package scripts may start the daemon.'),
    Dependency('interfaces', 'Interface tools', 'Address discovery, Wake-on-LAN and interface changes', ('ip','ifconfig'), ('iproute2',), ('iproute2',), systems=('Linux',), category='system'),
    Dependency('nmcli', 'NetworkManager', 'Raspberry Pi interface and Wi-Fi management', ('nmcli',), ('network-manager',), ('networkmanager',), systems=('Linux',),
               note='Installing can affect host networking. Setup never enables or reconfigures NetworkManager.'),
    Dependency('iw', 'iw', 'Raspberry Pi radio/channel inspection', ('iw',), ('iw',), ('iw',), systems=('Linux',)),
    Dependency('ethtool', 'ethtool', 'Raspberry Pi permanent MAC fallback', ('ethtool',), ('ethtool',), ('ethtool',), systems=('Linux',)),
    Dependency('ps', 'Process tools', 'Process identity and recovery', ('ps',), ('procps',), ('procps-ng',), category='system'),
    Dependency('sudo', 'sudo', 'Selected privileged service/helper actions', ('sudo',), ('sudo',), ('sudo',), category='system'),
    Dependency('systemctl', 'systemd', 'Linux autostart service management', ('systemctl',), systems=('Linux',), category='system', note='Requires a running systemd host; setup does not replace the init system.'),
    Dependency('hash', 'SHA-256 tools', 'Requirements change detection', ('shasum','sha256sum'), ('coreutils',), ('coreutils',), category='system', note='Python provides a fallback.'),
    Dependency('macos-tools', 'macOS system tools', 'IPv6 probes, interfaces, boot identity, launchd and PF', ('ping6','traceroute6','ifconfig','sysctl','launchctl','pfctl'), systems=('Darwin',), category='system', all_commands=True, note='Provided by macOS; restore missing OS tools through the operating system.'),
    Dependency('bpf', 'Wireshark ChmodBPF', 'macOS packet-capture device permissions', systems=('Darwin',), category='permission', note='Optional Homebrew cask; grants BPF access. A new login or restart may be required.'),
    Dependency('certbot', 'Certbot', 'ACME DNS-01 certificates', ('certbot',), category='python', note='Installed from the toolkit hash-locked Python requirements, not a second system package.'),
    Dependency('eapol_test', 'eapol_test', 'RADIUS EAP (currently disabled)', ('eapol_test',), category='disabled', note='EAP remains disabled. No EAP package is installed by setup.'),
)


def executable_path(root: Path | None = None) -> str:
    # Match service PATH, including Homebrew sbin used by lldpd on Apple Silicon.
    parts = ([str(root / '.venv' / 'bin')] if root else []) + os.environ.get('PATH', '').split(os.pathsep)
    parts += ['/opt/homebrew/bin','/opt/homebrew/sbin','/usr/local/bin','/usr/local/sbin','/usr/bin','/usr/sbin','/bin','/sbin','/opt/homebrew/opt/lsof/bin','/opt/homebrew/opt/lsof/sbin','/usr/local/opt/lsof/bin','/usr/local/opt/lsof/sbin']
    return os.pathsep.join(dict.fromkeys(p for p in parts if p))


def host_platform() -> dict[str, str]:
    system = platform.system()
    release = {}
    if system == 'Linux':
        try:
            for line in Path('/etc/os-release').read_text().splitlines():
                key, sep, value = line.partition('=')
                if sep:
                    release[key] = value.strip('"')
        except OSError:
            pass
    family = (release.get('ID','')+' '+release.get('ID_LIKE','')).split()
    adapter = 'brew' if system == 'Darwin' else 'pacman' if 'arch' in family else 'apt' if any(x in family for x in ('ubuntu','debian')) else ''
    command = {'brew':'brew','apt':'apt-get','pacman':'pacman'}.get(adapter, '')
    return {'system':system, 'name':release.get('PRETTY_NAME', system), 'adapter':adapter,
            'manager':shutil.which(command, path=executable_path()) or '' if command else ''}


def inventory(root: Path | None = None, *, system: str | None = None) -> list[dict]:
    system = system or platform.system()
    rows = []
    for spec in DEPENDENCIES:
        if system not in spec.systems:
            continue
        paths = {command:shutil.which(command, path=executable_path(root)) for command in spec.commands}
        present = (all(paths.values()) if spec.all_commands else any(paths.values())) if paths else False
        if spec.id == 'venv':
            present = importlib.util.find_spec('venv') is not None and importlib.util.find_spec('ensurepip') is not None
        if spec.id == 'tzdata':
            try:
                ZoneInfo('UTC')
                present = True
            except ZoneInfoNotFoundError:
                present = False
        if spec.id == 'bpf':
            present = Path('/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist').is_file()
        rows.append({'id':spec.id,'name':spec.name,'purpose':spec.purpose,'commands':paths,
                     'present':present,'category':spec.category,'note':spec.note})
    return rows


def selected_packages(selected: list[str], host: dict[str,str]) -> tuple[list[str], list[str]]:
    if len(selected) != len(set(selected)):
        raise ValueError('Each optional dependency may be selected only once.')
    specs = {spec.id:spec for spec in DEPENDENCIES}
    packages, casks = [], []
    for key in selected:
        spec = specs.get(key)
        if not spec or host['system'] not in spec.systems or spec.category in {'python','disabled','bootstrap'}:
            raise ValueError(f'Dependency cannot be installed through this setup: {key}')
        if key == 'bpf' and host['adapter'] == 'brew':
            casks.append('wireshark-chmodbpf')
            continue
        names = getattr(spec, host['adapter'], ()) if host['adapter'] in {'apt','pacman','brew'} else ()
        if not names:
            raise ValueError(f'No supported package mapping for {spec.name} on this host; use the manual guidance.')
        packages.extend(names)
    return sorted(set(packages)), sorted(set(casks))
