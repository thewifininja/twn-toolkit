"""Standalone, Python-3.10-compatible runtime migration and recovery.

Packaged in a release zipapp so recovery never imports the installation being
replaced. Only the prepared worker imports the application's dependencies.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
import urllib.request
import uuid
import zipfile

from .release_bundle import (
    MAX_BUNDLE_BYTES, UpgradeError, parse_version, validate_release_bundle,
)

TERMINAL = {"succeeded", "rolled_back", "failed"}


def write_json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open('w', encoding='utf-8') as handle:
        json.dump(value, handle, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.chmod(0o600)
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def environment() -> dict[str, str]:
    env = os.environ.copy()
    for name in ('PYTHONPATH', 'PYTHONHOME', 'VIRTUAL_ENV', 'TWN_TOOLKIT_NETWORK_BROKER',
                 'TWN_TOOLKIT_SERVICE_RUN', 'TWN_TOOLKIT_LAUNCHD_DIRECT', 'TWN_TOOLKIT_LAUNCHD_ROLE',
                 'TWN_TOOLKIT_RELOAD_SERVICE_LAUNCHER', 'TWN_TOOLKIT_UPGRADE_REQUEST_ID',
                 'TWN_TOOLKIT_SUPPRESS_START_EVENT'):
        env.pop(name, None)
    return env


def run(command, *, cwd=None, quiet=False, timeout=60, env=None):
    options = {'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL} if quiet else {'capture_output': True}
    return subprocess.run([str(part) for part in command], cwd=cwd, text=True,
                          timeout=timeout, env=env or environment(), **options)


def python_version(python: Path) -> tuple[int, int]:
    result = run([python, '-I', '-c', 'import sys; print("%d.%d" % sys.version_info[:2])'])
    if result.returncode or not re.fullmatch(r'3\.\d+\s*', result.stdout):
        raise UpgradeError('The selected Python interpreter could not be verified.')
    return tuple(map(int, result.stdout.strip().split('.')))


def choose_python(explicit: str | None = None) -> Path:
    candidates = [explicit] if explicit else [
        sys.executable,
        *[shutil.which(name) for name in ('python3', 'python3.15', 'python3.14', 'python3.13', 'python3.12', 'python3.11')],
        *[str(Path(base) / name) for base in ('/opt/homebrew/bin', '/usr/local/bin', '/usr/bin')
          for name in ('python3.12', 'python3.13', 'python3.11', 'python3.14', 'python3.15')],
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            try:
                if python_version(Path(candidate)) >= (3, 11):
                    return Path(candidate).absolute()
            except (OSError, subprocess.SubprocessError, UpgradeError):
                pass
    raise UpgradeError('Install Python 3.11+ alongside the existing Python, then retry with --python /path/to/python3.12. No services or installed files were changed.')


def snapshot(path: Path, *, link_parent: Path | None = None) -> dict:
    if path.is_symlink():
        target = Path(os.readlink(path))
        resolved = target if target.is_absolute() else (link_parent or path.parent) / target
        return {'kind': 'link', 'target': os.readlink(path), 'environment': snapshot(resolved.resolve())}
    if not path.is_dir():
        raise UpgradeError('The preserved virtual environment is missing.')
    files = {}
    for item in sorted(path.rglob('*')):
        if '__pycache__' in item.parts or item.suffix in {'.pyc', '.pyo'}:
            continue
        relative = item.relative_to(path).as_posix()
        if item.is_symlink():
            files[relative] = ['link', os.readlink(item)]
        elif item.is_file():
            files[relative] = ['file', hashlib.sha256(item.read_bytes()).hexdigest(), stat.S_IMODE(item.stat().st_mode)]
    return {'kind': 'directory', 'files': files}


def runtime_record(root: Path, backup: Path) -> tuple[dict, Path] | None:
    path = backup / 'runtime.json'
    if not path.exists():
        return None
    record = json.loads(path.read_text())
    relative = Path(record['previous'])
    if record.get('format') != 1 or Path(record['root']) != root or relative.is_absolute() or '..' in relative.parts:
        raise UpgradeError('Runtime recovery metadata is invalid.')
    previous = root / relative
    if previous.parent.parent != root / '.twn-upgrades/runtime-migrations' or previous.name != 'previous-venv':
        raise UpgradeError('Runtime recovery location is invalid.')
    return record, previous


def verify_runtime_backup(root: Path, backup: Path) -> None:
    stored = runtime_record(root, backup)
    if stored is None:
        return
    record, previous = stored
    original = root / '.venv'
    source = previous if previous.exists() or previous.is_symlink() else original
    if snapshot(source, link_parent=root) != record['snapshot']:
        raise UpgradeError('Preserved runtime integrity verification failed; no recovery files were replaced.')
    # Directory environments can be probed at the saved path. A saved symlink
    # may be relative to the original root, so probe its original target.
    probe = source / 'bin/python'
    if record['snapshot']['kind'] == 'link':
        target = Path(record['snapshot']['target'])
        probe = (target if target.is_absolute() else root / target) / 'bin/python'
    if list(python_version(probe)) != record['python_version']:
        raise UpgradeError('The original Python interpreter is no longer available for rollback.')


def restore_runtime_backup(root: Path, backup: Path) -> None:
    stored = runtime_record(root, backup)
    if stored is None:
        return
    verify_runtime_backup(root, backup)
    _, previous = stored
    if previous.exists() or previous.is_symlink():
        active = root / '.venv'
        temporary = root / ('.venv-restore-' + uuid.uuid4().hex)
        if previous.is_symlink():
            temporary.symlink_to(os.readlink(previous), target_is_directory=True)
        else:
            shutil.copytree(previous, temporary, symlinks=True)
        if active.exists() or active.is_symlink():
            displaced = previous.parent / ('failed-venv-' + uuid.uuid4().hex)
            os.replace(active, displaced)
        os.replace(temporary, active)


def check_root(root: Path) -> None:
    if root.stat().st_uid != os.geteuid():
        raise UpgradeError('Run the migration as the toolkit installation owner, without sudo.')
    for name in ('twn', 'instance', '.venv/bin/python', 'twn_toolkit/version.py'):
        if not (root / name).exists():
            raise UpgradeError('Choose an existing toolkit installation with an intact environment.')
    workspace = root / '.twn-upgrades'
    if workspace.is_symlink():
        raise UpgradeError('The upgrade workspace must not be a symbolic link.')
    if (root / '.venv').is_symlink():
        raise UpgradeError('A linked .venv requires operator review. Already-migrated installations should use the normal updater and recovery commands.')



@contextmanager
def migration_lock(root: Path, identifier: str, *, recover=False):
    workspace = root / '.twn-upgrades'
    workspace.mkdir(mode=0o700, exist_ok=True)
    workspace.chmod(0o700)
    with (workspace / 'setup.guard').open('a') as guard:
        try:
            fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise UpgradeError('Guided setup or another runtime migration is active.') from exc
        lock = workspace / 'operation.lock'
        if recover:
            if not lock.exists() or lock.read_text().strip() != identifier:
                raise UpgradeError('The recovery operation does not own the upgrade lock.')
        else:
            try:
                fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError as exc:
                raise UpgradeError('Another upgrade/recovery is active. Inspect its status before proceeding.') from exc
            with os.fdopen(fd, 'w') as handle:
                handle.write(identifier + '\n')
        try:
            yield
        finally:
            # An interrupted migration keeps the lock for explicit recovery.
            plan = workspace / 'runtime-migrations' / identifier / 'plan.json'
            if not plan.exists() or json.loads(plan.read_text()).get('state') in TERMINAL:
                lock.unlink(missing_ok=True)


def ensure_idle(root: Path) -> None:
    # Reuse the installed release's supported idle check, before any stop or
    # environment switch. Fail closed if the old installation cannot check it.
    result = run([root / '.venv/bin/python', '-c',
                  'from pathlib import Path; from twn_toolkit.setup_executor import ensure_idle; '
                  'import sys; ensure_idle(Path(sys.argv[1]))', root], cwd=root)
    if result.returncode:
        raise UpgradeError('The installed toolkit could not confirm idle jobs/terminals. Finish active work and retry; nothing was stopped.')


def verify_checksum(bundle: Path, checksum: str) -> None:
    if not re.fullmatch(r'[a-fA-F0-9]{64}', checksum):
        raise UpgradeError('A valid published SHA-256 checksum is required.')
    if not bundle.is_file() or bundle.stat().st_size > MAX_BUNDLE_BYTES:
        raise UpgradeError('Release bundle is missing or too large.')
    if hashlib.sha256(bundle.read_bytes()).hexdigest().lower() != checksum.lower():
        raise UpgradeError('The release bundle checksum does not match.')


def extract(bundle: Path, destination: Path, manifest: dict) -> None:
    with zipfile.ZipFile(bundle) as archive:
        for relative in manifest['files']:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read('payload/' + relative))


def tool_archive(destination: Path) -> None:
    # Retain an immutable worker/recovery copy outside the source being replaced.
    source = Path(sys.argv[0]).absolute()
    if zipfile.is_zipfile(source):
        shutil.copy2(source, destination)
        return
    package = Path(__file__).parent
    with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('__main__.py', 'from twn_toolkit.runtime_migration import main\nraise SystemExit(main())\n')
        for item in package.rglob('*.py'):
            archive.write(item, 'twn_toolkit/' + item.relative_to(package).as_posix())
    destination.chmod(0o600)


def stage(root: Path, bundle: Path, checksum: str, python: Path, identifier: str, *, initialize_only=False) -> Path:
    verify_checksum(bundle, checksum)
    current = (root / 'twn_toolkit/version.py').read_text()
    match = re.search(r'^APP_VERSION\s*=\s*["\']([^"\']+)["\']', current, re.M)
    if not match:
        raise UpgradeError('The installed version could not be identified.')
    manifest = validate_release_bundle(bundle, current_version=match[1], check_python=False)
    if manifest.get('minimum_python') != '3.11':
        raise UpgradeError('This migration tool requires a Python-3.11 release bundle.')
    if python_version(python) < (3, 11):
        raise UpgradeError('A supported interpreter is required.')
    workspace = root / '.twn-upgrades/runtime-migrations'
    workspace.mkdir(mode=0o700, exist_ok=True)
    journal = workspace / identifier
    journal.mkdir(mode=0o700)
    tool = journal / 'migrate.pyz'
    tool_archive(tool)
    saved_bundle = journal / 'release.zip'
    shutil.copy2(bundle, saved_bundle)
    plan = {'format': 1, 'id': identifier, 'root': str(root), 'from_version': match[1],
            'version': manifest['version'], 'state': 'staging', 'pid': os.getpid(),
            'bundle_sha256': checksum.lower(), 'tool_sha256': hashlib.sha256(tool.read_bytes()).hexdigest(),
            'backup': '', 'service_reload': False}
    write_json(journal / 'plan.json', plan)
    if not initialize_only:
        finish_staging(journal, python)
    return journal


def finish_staging(journal: Path, python: Path) -> None:
    root, plan = load_plan(journal)
    try:
        bundle = journal / 'release.zip'
        manifest = validate_release_bundle(bundle, current_version=plan['from_version'], check_python=False)
        payload = journal / 'payload'
        payload.mkdir()
        extract(bundle, payload, manifest)
        # Reserve space for the environment, recovery point, and rollback copy.
        size = sum(p.stat().st_size for base in (root / 'instance', root / '.venv') for p in base.rglob('*') if p.is_file())
        if shutil.disk_usage(root).free < size + 1024 * 1024 * 1024:
            raise UpgradeError('Not enough space for a staged runtime and recovery point.')
        venv = journal / 'venv'
        print('Preparing an isolated Python environment; the installed toolkit is still running.', flush=True)
        if run([python, '-m', 'venv', venv], quiet=True, timeout=180).returncode:
            raise UpgradeError('Could not create the staged environment; the installed environment is unchanged.')
        staged_python = venv / 'bin/python'
        print('Installing and checking the release dependencies before downtime.', flush=True)
        for command in (
            [staged_python, payload / 'scripts/lock_dependencies.py', '--check'],
            [staged_python, '-m', 'pip', 'install', '--require-hashes', '-r', payload / 'requirements.txt'],
            [staged_python, '-m', 'pip', 'check'],
            [staged_python, '-m', 'compileall', '-q', payload / 'twn_toolkit'],
            ['/bin/sh', '-n', payload / 'install.sh'],
            ['/bin/sh', '-n', payload / 'twn'],
            [staged_python, '-c', 'import sys; from twn_toolkit import create_app; create_app(sys.argv[1])', journal / 'smoke-instance'],
        ):
            if run(command, cwd=payload, quiet=True, timeout=1200).returncode:
                raise UpgradeError('Staged dependency/source validation failed. The installed environment and services are unchanged; package-manager output was not retained.')
        tool = journal / 'migrate.pyz'
        if run([staged_python, '-c', 'import sys; sys.path.insert(0, sys.argv[1]); import twn_toolkit.upgrade_manager', tool], quiet=True).returncode:
            raise UpgradeError('The isolated migration worker could not be imported with the target dependencies.')
        if shutil.disk_usage(root).free < size + 256 * 1024 * 1024:
            raise UpgradeError('Not enough space remains for backup and runtime rollback.')
        save_state(journal, plan, 'prepared')
    except Exception:
        save_state(journal, plan, 'failed')
        raise


def load_plan(journal: Path) -> tuple[Path, dict]:
    journal = journal.absolute()
    plan_path = journal / 'plan.json'
    if plan_path.stat().st_uid != os.geteuid() or stat.S_IMODE(plan_path.stat().st_mode) & 0o077:
        raise UpgradeError('Runtime journal must be private and owned by this account.')
    plan = json.loads(plan_path.read_text())
    root = Path(plan['root'])
    if not root.is_absolute() or root.resolve() != root or journal.resolve() != journal or root.stat().st_uid != os.geteuid():
        raise UpgradeError('Runtime journal ownership/location is invalid.')
    if plan.get('format') != 1 or journal != root / '.twn-upgrades/runtime-migrations' / plan['id']:
        raise UpgradeError('Runtime journal location is invalid.')
    if not re.fullmatch(r'[a-f0-9]{32}', plan['id']):
        raise UpgradeError('Runtime journal identifier is invalid.')
    if hashlib.sha256((journal / 'migrate.pyz').read_bytes()).hexdigest() != plan['tool_sha256']:
        raise UpgradeError('The preserved migration tool failed integrity verification.')
    verify_checksum(journal / 'release.zip', plan['bundle_sha256'])
    if plan.get('backup') and Path(plan['backup']).parent != root / '.twn-upgrades/backups':
        raise UpgradeError('Runtime backup location is invalid.')
    return root, plan


def save_state(journal: Path, plan: dict, state: str, **values) -> None:
    plan.update(values, state=state, pid=os.getpid())
    write_json(journal / 'plan.json', plan)
    write_json(Path(plan['root']) / '.twn-upgrades/status.json', {
        'id': plan['id'], 'operation': 'runtime-migration', 'state': state,
        'message': 'Python runtime migration: ' + state.replace('_', ' '),
        'from_version': plan['from_version'], 'target_version': plan['version'],
        'updated_at': time.time(), 'runtime_journal': str(journal),
    })


def perform(journal: Path, *, recover=False) -> None:
    # Imported from the preserved zipapp and executed by its permanent staged
    # interpreter, so source replacement and .venv cutover cannot change imports.
    from . import upgrade_manager as manager
    root, plan = load_plan(journal)
    instance = root / 'instance'
    env = environment()
    env['TWN_TOOLKIT_UPGRADE_REQUEST_ID'] = plan['id']
    backup = Path(plan['backup']) if plan['backup'] else None

    def rollback():
        if backup is not None:
            # If target startup partially succeeded, stop all target workers
            # before restoring code, instance data, and the original environment.
            if (root / '.venv/bin/python').exists():
                stopped = run([root / 'twn', 'stop'], cwd=root, env=env, timeout=120)
                if stopped.returncode:
                    raise UpgradeError('Target services could not be stopped; recovery files were preserved.')
            manager._restore_backup(root, instance, backup)
        manager._preserve_prepared_service_reload(instance, plan['service_reload'])
        os.environ['TWN_TOOLKIT_RELOAD_SERVICE_LAUNCHER'] = '1'
        manager._install_and_validate(root, instance, plan['from_version'], install_dependencies=False,
                                      upgrade_request_id=plan['id'], suppress_start_event=plan['service_reload'])
        save_state(journal, plan, 'rolled_back')

    try:
        if recover:
            if plan['state'] in TERMINAL:
                raise UpgradeError('This migration is already complete.')
            rollback()
            return
        if plan['state'] != 'prepared':
            raise UpgradeError('Interrupted migration: use --recover with this journal.')
        ensure_idle(root)
        save_state(journal, plan, 'stopping')
        stopped = run([root / 'twn', 'stop'], cwd=root, env=env, timeout=120)
        if stopped.returncode:
            raise UpgradeError('Services could not be stopped; no source or environment switch was attempted.')
        save_state(journal, plan, 'backing_up')
        (root / '.twn-upgrades/backups').mkdir(mode=0o700, exist_ok=True)
        record = {'format': 1, 'root': str(root), 'previous': str((journal / 'previous-venv').relative_to(root)),
                  'snapshot': snapshot(root / '.venv'), 'python_version': list(python_version(root / '.venv/bin/python'))}
        backup = manager._create_backup(root, instance, root / '.twn-upgrades/backups', {
            'from_version': plan['from_version'], 'target_version': plan['version'], 'operation': 'runtime-migration'},
            runtime_backup=record)
        save_state(journal, plan, 'backed_up', backup=str(backup))
        # Publish intent first so interruption during handoff remains recoverable.
        save_state(journal, plan, 'handoff', service_reload=True)
        prepared = manager._prepare_service_reload(root, plan['id'])
        save_state(journal, plan, 'handoff', service_reload=prepared)
        save_state(journal, plan, 'switching_runtime')
        os.replace(root / '.venv', journal / 'previous-venv')
        temporary = root / ('.venv-next-' + plan['id'])
        temporary.symlink_to(journal / 'venv', target_is_directory=True)
        os.replace(temporary, root / '.venv')
        save_state(journal, plan, 'applying')
        manifest = validate_release_bundle(journal / 'release.zip', current_version=plan['from_version'])
        manager._extract_and_apply(root, journal / 'release.zip', manifest, root / '.twn-upgrades')
        manager._preserve_prepared_service_reload(instance, prepared)
        # Dependencies were installed and checked before downtime. Avoid a second
        # network installation and leave the preserved old environment untouched.
        (instance / 'requirements.sha256').write_text(hashlib.sha256((root / 'requirements.txt').read_bytes()).hexdigest() + '\n')
        save_state(journal, plan, 'validating')
        os.environ['TWN_TOOLKIT_RELOAD_SERVICE_LAUNCHER'] = '1'
        manager._install_and_validate(root, instance, plan['version'], install_dependencies=False,
                                      upgrade_request_id=plan['id'], suppress_start_event=prepared)
        save_state(journal, plan, 'succeeded')
    except Exception:
        if plan['state'] == 'prepared':
            save_state(journal, plan, 'failed')
        elif plan['state'] not in TERMINAL:
            # A failed stop may leave services partially running: restart the
            # old installation, or retain the journal/lock if recovery fails.
            try:
                save_state(journal, plan, 'rolling_back')
                rollback()
            except Exception as recovery_error:
                save_state(journal, plan, 'recovery_required')
                raise UpgradeError('Automatic recovery could not finish. Preserve all files and rerun the migration tool with --recover ' + str(journal)) from recovery_error
        raise


def download_release(destination: Path, version: str) -> tuple[Path, str]:
    request = urllib.request.Request('https://api.github.com/repos/thewifininja/twn-toolkit/releases/tags/v' + version,
                                     headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'twn-runtime-migration'})
    with urllib.request.urlopen(request, timeout=30) as response:
        release = json.loads(response.read(2 * 1024 * 1024))
    if release.get('draft') or release.get('prerelease') or release.get('tag_name') != 'v' + version:
        raise UpgradeError('Choose a published stable toolkit release.')
    name = 'twn-toolkit-v' + version + '.zip'
    assets = {item['name']: item.get('browser_download_url', '') for item in release.get('assets', [])}
    for asset_name in (name, name + '.sha256'):
        if not assets.get(asset_name, '').startswith('https://github.com/thewifininja/twn-toolkit/releases/download/'):
            raise UpgradeError('The release is missing its official verified bundle assets.')
    with urllib.request.urlopen(assets[name + '.sha256'], timeout=30) as response:
        checksum = response.read(4096).decode('ascii').split()[0]
    bundle = destination / name
    with urllib.request.urlopen(assets[name], timeout=30) as response, bundle.open('wb') as output:
        size = 0
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_BUNDLE_BYTES:
                raise UpgradeError('Release download exceeds the bundle limit.')
            output.write(chunk)
    verify_checksum(bundle, checksum)
    return bundle, checksum


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Migrate a toolkit installation without manually editing source or virtual environments.')
    parser.add_argument('--root', type=Path)
    parser.add_argument('--version', help='Exact reviewed stable release version')
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--sha256', help='Published checksum for a local bundle')
    parser.add_argument('--python', help='Installed Python 3.11+ executable; otherwise discovered automatically')
    parser.add_argument('--yes', action='store_true')
    parser.add_argument('--recover', type=Path, metavar='JOURNAL')
    parser.add_argument('--prepared', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if args.prepared or args.recover:
            journal = (args.prepared or args.recover).absolute()
            root, plan = load_plan(journal)
            if args.prepared and int(plan['pid']) != os.getpid():
                raise UpgradeError('Only the original migration worker may activate this prepared journal.')
            if args.recover:
                try:
                    os.kill(int(plan['pid']), 0)
                except ProcessLookupError:
                    pass
                else:
                    raise UpgradeError('The migration worker is still running; recovery was not started.')
            if args.recover and plan['state'] == 'staging':
                with migration_lock(root, plan['id'], recover=True):
                    save_state(journal, plan, 'failed')
                print('Interrupted preparation cancelled; the installed toolkit was never stopped or replaced.')
                return 0
            if Path(sys.executable).absolute() != journal / 'venv/bin/python':
                os.execve(str(journal / 'venv/bin/python'), [str(journal / 'venv/bin/python'), str(journal / 'migrate.pyz'),
                          '--recover' if args.recover else '--prepared', str(journal)], environment())
            with migration_lock(root, plan['id'], recover=True):
                perform(journal, recover=bool(args.recover))
            return 0
        if not args.root or not args.version:
            parser.error('--root and --version are required for a new migration')
        root = args.root.resolve()
        args.version = args.version.removeprefix('v')
        parse_version(args.version)
        check_root(root)
        python = choose_python(args.python)
        ensure_idle(root)
        if not args.yes:
            if not sys.stdin.isatty() or input('Stage the verified release, stop services, back up, and migrate this installation? [y/N] ').lower() not in {'y', 'yes'}:
                raise UpgradeError('Migration cancelled; rerun with --yes only after reviewing the maintenance window.')
        identifier = uuid.uuid4().hex
        workspace = root / '.twn-upgrades'
        workspace.mkdir(mode=0o700, exist_ok=True)
        if args.bundle:
            if not args.sha256:
                raise UpgradeError('A local bundle requires its published --sha256 checksum.')
            bundle, checksum = args.bundle.resolve(), args.sha256
        else:
            bundle, checksum = download_release(workspace, args.version)
        # Publish the private journal before claiming operation.lock: every
        # subsequent interruption has a discoverable, recoverable owner record.
        journal = stage(root, bundle, checksum, python, identifier, initialize_only=True)
        _, plan = load_plan(journal)
        if plan['version'] != args.version:
            save_state(journal, plan, 'failed')
            raise UpgradeError('The selected version does not match the bundle.')
        with migration_lock(root, identifier):
            try:
                ensure_idle(root)
                finish_staging(journal, python)
            except Exception:
                _, plan = load_plan(journal)
                if plan['state'] == 'staging':
                    save_state(journal, plan, 'failed')
                raise
            print('Staged and checked the new runtime. Switching through the isolated migration worker.', flush=True)
            os.execve(str(journal / 'venv/bin/python'), [str(journal / 'venv/bin/python'), str(journal / 'migrate.pyz'), '--prepared', str(journal)], environment())
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, UpgradeError) as error:
        # Do not print subprocess/package-manager output: index URLs may carry credentials.
        print('Runtime migration did not complete: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
