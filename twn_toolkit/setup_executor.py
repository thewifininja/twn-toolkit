"""Apply reviewed setup plans through existing installer, settings and service CLIs."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import json
import fcntl
import sqlite3
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys

from .release_bundle import _release_files
from .setup_dependencies import executable_path, inventory
from .setup_plan import SetupPlan, package_commands, validate


@contextmanager
def setup_lock(root: Path):
    workspace = root/'.twn-upgrades'
    workspace.mkdir(exist_ok=True,mode=0o700)
    lock = workspace/'operation.lock'
    # Use the updater's exclusion protocol. Never steal or remove someone else's lock.
    fd = os.open(lock,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        os.write(fd,b'guided-setup\n')
        yield
    finally:
        os.close(fd)
        lock.unlink()


def run_command(command: list[str], *, root: Path, unattended: bool = False):
    command = list(command)
    if unattended and command[0]=='sudo':
        command.insert(1,'-n')
    env = dict(os.environ, PATH=executable_path(root), TWN_TOOLKIT_SETUP_ACTIVE='1', PIP_NO_INPUT='1')
    if unattended:
        env['NONINTERACTIVE'] = '1'
        env['TWN_TOOLKIT_SETUP_UNATTENDED'] = '1'
        if any(Path(part).name == 'apt-get' for part in command):
            command.insert(command.index('install')+1,'-y')
            env['DEBIAN_FRONTEND'] = 'noninteractive'
        elif any(Path(part).name == 'pacman' for part in command):
            command.insert(command.index('-S')+1,'--noconfirm')
    # Package output and native privilege prompts belong to the real terminal.
    result = subprocess.run(command,cwd=root,env=env,check=False,stdin=subprocess.DEVNULL if unattended else None)
    if result.returncode:
        raise RuntimeError(f'{Path(command[0]).name} failed with exit status {result.returncode}. Setup stopped; see the output above. Completed package changes are not rolled back.')


def prepare_location(source: Path, target: Path, run):
    if source == target:
        return
    if not target.exists():
        if os.access(target.parent,os.W_OK):
            target.mkdir(mode=0o755)
        else:
            user = pwd.getpwuid(os.getuid())
            run(['sudo','/usr/bin/install','-d','-o',str(user.pw_uid),'-g',str(user.pw_gid),'-m','0755',str(target)])
    # Recheck after creation and refuse races/nonempty locations. No data or venv copying.
    if not target.is_dir() or any(target.iterdir()):
        raise ValueError('Destination is no longer empty; no files were copied.')
    if target.stat().st_uid != os.getuid() or not os.access(target,os.W_OK):
        raise ValueError('Destination must be owned and writable by the installing account.')
    for file in _release_files(source):
        if not file.resolve().is_relative_to(source) or any(parent.is_symlink() for parent in file.parents if parent != source and parent.is_relative_to(source)):
            raise ValueError('Release source contains a linked directory; use a regular checkout.')
        destination = target/file.relative_to(source)
        destination.parent.mkdir(parents=True,exist_ok=True)
        with file.open('rb') as src, destination.open('xb') as dst:
            shutil.copyfileobj(src,dst)
        destination.chmod(stat.S_IMODE(file.stat().st_mode))


def apply(plan: SetupPlan, source: Path, host: dict, *, unattended=False, runner=run_command, report=print):
    target = validate(plan,source,host)
    if any(not (source/name).is_file() for name in ('install.sh','requirements.txt','twn')):
        raise ValueError('The checkout is incomplete.')
    def run(command):
        runner(command,root=target if target.exists() else source,unattended=unattended)
    with setup_guard(source):
        with setup_lock(source):
            ensure_idle(source)
            report('Preparing installation location')
            prepare_location(source,target,run)
            with setup_guard(target) if target != source else _no_lock():
                with setup_lock(target) if target != source else _no_lock():
                    _prepare_locked(plan,target,host,run,report)
                # A service launcher must not see an upgrade-operation lock at boot.
                if target != source:
                    _start(plan,target,host,run,report)
        if target == source:
            _start(plan,target,host,run,report)
    return target


@contextmanager
def _no_lock():
    yield


def _prepare_locked(plan, target, host, run, report):
    fresh = not (target/'instance').exists() or not any((target/'instance').iterdir())
    if not fresh:
        report('Stopping toolkit processes before updating the environment')
        run([str(target/'twn'),'stop'])
    report('Installing selected system dependencies')
    for command in package_commands(plan,host):
        run(command)
    found = {row['id']:row for row in inventory(target,system=host['system'])}
    missing = [key for key in plan.packages if not found[key]['present']]
    if missing:
        raise RuntimeError('Installed package did not provide its expected files: '+', '.join(missing)+'. Resolve this before retrying.')
    report('Preparing the hash-locked Python environment')
    run([str(target/'install.sh'),'--non-interactive','--prepare-only'])
    report('Saving toolkit hostname and display timezone')
    run([str(target/'.venv/bin/python'),'-m','twn_toolkit.setup_cli','--configure-instance',
         '--root',str(target),'--hostname',plan.hostname,'--timezone',plan.timezone])
    if fresh and not (target/'instance/tls/enabled').exists():
        report('Generating the local HTTPS certificate')
        run([str(target/'twn'),'enable-https'])
    if plan.lldpd:
        report('Enabling the selected LLDP daemon')
        run(['sudo','systemctl','enable','--now','lldpd'])
    if plan.pf_interfaces:
        report('Installing the explicitly selected multicast compatibility rules')
        run(['sudo',str(target/'.venv/bin/python'),'-m','twn_toolkit.macos_multicast_pf_cli','install','--interfaces',*plan.pf_interfaces])
        report('PF files are configured. Restart macOS before relying on them; inspect with sudo ./twn multicast-pf status.')


def _start(plan,target,host,run,report):
    if plan.service:
        report('Installing and verifying the toolkit service')
        run([str(target/'twn'),'service','install','--user',pwd.getpwuid(os.getuid()).pw_name]+(['--network-capabilities'] if plan.network else []))
    else:
        report('Starting toolkit for this session; automatic boot startup is disabled')
        run([str(target/'twn'),'restart'])
    report('Checking the running toolkit')
    run([str(target/'twn'),'status'])
    run([str(target/'.venv/bin/python'),'-m','twn_toolkit.setup_cli','--verify','--root',str(target)]+(['--expect-service'] if plan.service else [])+(['--expect-network'] if plan.network else []))
    marker = target/'instance/installation.initialized'
    marker.touch(mode=0o600)


@contextmanager
def setup_guard(root: Path):
    directory = root/'.twn-upgrades'
    directory.mkdir(exist_ok=True, mode=0o700)
    with (directory/'setup.guard').open('a') as handle:
        fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try:
            yield
        finally:
            fcntl.flock(handle,fcntl.LOCK_UN)


def ensure_idle(root: Path):
    for name,table,predicate in (
        ('diagnostic_jobs','diagnostic_jobs',"state IN ('queued','running','cancel_requested') OR token!=''"),
        ('remote_sessions','remote_sessions',"state IN ('connecting','running')"),
        ('distributed_jobs','distributed_jobs',"state IN ('queued','claimed','running','cancel_requested')")):
        path = root/'instance'/f'{name}.sqlite3'
        if path.exists():
            with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=1) as db:
                if db.execute(f'SELECT COUNT(*) FROM {table} WHERE {predicate}').fetchone()[0]:
                    raise ValueError('Active jobs or terminals exist. Finish them before re-running setup.')
