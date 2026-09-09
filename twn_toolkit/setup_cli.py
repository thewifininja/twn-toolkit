"""Guided installer and explicit unattended setup plans."""
from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from zoneinfo import available_timezones

from .setup_dependencies import DEPENDENCIES, host_platform, inventory
from .setup_plan import SetupPlan, initial_plan, read_settings, review, validate


def configure_instance(root: Path, hostname: str, timezone: str):
    from .server_settings import ServerSettingsStore
    from .time_settings import TimeSettingsStore, normalize_timezone_name
    from .server_settings import normalize_preferred_fqdn
    # Validate both settings before writing either; preserve unrelated GUI settings.
    normalize_preferred_fqdn(hostname)
    normalize_timezone_name(timezone)
    server = ServerSettingsStore(str(root/'instance'))
    current = server.get()
    if current['preferred_fqdn'] != hostname:
        server.save(current['listen_host'],current['allowed_networks'],preferred_fqdn=hostname)
    time_store = TimeSettingsStore(root/'instance')
    if time_store.get()['timezone'] != timezone:
        time_store.save(timezone)


def verify(root: Path, *, expect_service=False, expect_network=False):
    from .system_diagnostics import command_dependencies, platform_capabilities
    from .lldp_tools import lldpcli_capability
    print('\nDependency verification (this setup account, not proof of service-user permissions):')
    for row in command_dependencies():
        print(f"  {'FOUND' if row['available'] else 'UNAVAILABLE'}  {row['name']}: {row['detail']}")
    for row in platform_capabilities():
        print(f"  {row['name']}: {row.get('detail','')}")
    lldp = lldpcli_capability()
    print('  LLDP daemon/control socket: '+lldp['message'])
    if expect_service:
        from .service_cli import service_runtime_status
        deadline = time.monotonic()+30
        while True:
            status=service_runtime_status(root,manager_timeout_seconds=2)
            if status['healthy'] and status['manager_active'] and status['manages_this_checkout']:
                break
            if time.monotonic()>=deadline:
                raise RuntimeError('The installed service did not reach a healthy state; run ./twn service status.')
            time.sleep(1)
        print('  Installed service: healthy and managing this checkout.')
    if expect_network:
        pid=int((root/'instance/twn-toolkit.pid').read_text().strip())
        lines=Path(f'/proc/{pid}/status').read_text().splitlines()
        capabilities=int(next(line.split(':',1)[1].strip() for line in lines if line.startswith('CapEff:')),16)
        required=sum(1<<bit for bit in (10,12,13))
        if capabilities & required != required:
            raise RuntimeError('The service process does not have the requested network capabilities.')
        print('  Running service process: requested network capabilities verified.')
    print('Verify effective permissions again in Settings > Diagnostics while using the installed service.')
    print('Python package integrity was verified with pip check and hash-locked requirements.')


def yes_no(label, default=False):
    answer = input(f"{label} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return default if not answer else answer in {'y','yes'}


def choose_timezone(current):
    zones = ['']+sorted(available_timezones())
    print('Timezone: search by city or region, or press Enter to keep '+(current or 'Follow host')+'.')
    while True:
        query = input('City/region (or "host"): ').strip()
        if not query:
            return current
        if query.casefold()=='host':
            return ''
        matches = [zone for zone in zones if query.casefold() in zone.casefold().replace('_',' ')]
        if not matches:
            print('No matches. Try a nearby city or region.')
            continue
        for n,zone in enumerate(matches[:20],1):
            print(f'  {n}. {zone.replace("_"," ")}')
        if len(matches)>20:
            print('First 20 matches; narrow your search if needed.')
        selected = input('Number, or Enter to search again: ').strip()
        if selected.isdigit() and 1<=int(selected)<=min(20,len(matches)):
            return matches[int(selected)-1]


def plain_editor(root,host,plan):
    print(f"TWN GUIDED INSTALLATION\nDetected: {host['name']}\nPackage manager: {host['manager'] or 'unavailable'}")
    plan.service = yes_no('Run automatically as a service?',plan.service)
    if plan.service and host['system']=='Darwin':
        print('Service location must be outside Desktop, Documents, Downloads and cloud folders. Suggested: ~/twn-toolkit.')
    plan.location = input(f'Installation folder [{plan.location}]: ').strip() or plan.location
    rows = inventory(root,system=host['system'])
    print('\nOptional tools are individual choices. Bundled Python dependencies are installed from requirements.txt.')
    for row in rows:
        spec = next(spec for spec in DEPENDENCIES if spec.id==row['id'])
        if row['present'] or row['category'] in {'python','disabled','bootstrap'}:
            print(f"  {row['name']}: {'found' if row['present'] else row['category']} — {row['note']}")
            continue
        if not host['manager'] or (not getattr(spec,host['adapter'],()) and spec.id!='bpf'):
            print(f"  {row['name']}: manual setup needed. {row['note']}")
            continue
        if yes_no(f"Install {row['name']} ({row['purpose']})? {row['note']}",row['id'] in plan.packages):
            if row['id'] not in plan.packages:
                plan.packages.append(row['id'])
        elif row['id'] in plan.packages:
            plan.packages.remove(row['id'])
    plan.hostname = input(f'Preferred DNS hostname [{plan.hostname or "automatic"}] ("auto" clears): ').strip() or plan.hostname
    if plan.hostname=='auto':
        plan.hostname=''
    plan.timezone = choose_timezone(plan.timezone)
    if host['system']=='Linux':
        plan.network = plan.service and yes_no('Grant the toolkit service network capabilities for privileged diagnostics?',plan.network)
        plan.lldpd = yes_no('Enable and start the lldpd daemon?',plan.lldpd)
    else:
        print('Optional PF compatibility manages only the TWN anchor, preserves backups, and requires a restart. It never reloads the live ruleset.')
        if yes_no('Configure multicast PF compatibility?',bool(plan.pf_interfaces)):
            interfaces = [name for _,name in socket.if_nameindex() if not name.startswith('lo')]
            for n,name in enumerate(interfaces,1):
                print(f'  {n}. {name}')
            choices = input('Interface numbers, separated by commas: ').split(',')
            plan.pf_interfaces=[interfaces[int(n.strip())-1] for n in choices if n.strip().isdigit() and 1<=int(n.strip())<=len(interfaces)]
            if not plan.pf_interfaces:
                raise ValueError('No interfaces selected; PF setup was not authorized.')
        else:
            plan.pf_interfaces=[]
    validate(plan,root,host)
    print('\nREVIEW')
    for label,value in review(plan,root,host):
        print(f'{label}: {value}')
    return plan if yes_no('Install this plan?') else None


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--plain',action='store_true',help='Use text prompts instead of the full-screen interface')
    parser.add_argument('--no-motion',action='store_true',help='Disable the animated banner')
    parser.add_argument('--config',type=Path,help='Read a JSON SetupPlan instead of prompting')
    parser.add_argument('--dry-run',action='store_true',help='Print the plan without making changes')
    parser.add_argument('--yes',action='store_true',help='Explicitly approve a --config plan; native prompts are disabled')
    parser.add_argument('--dependencies',action='store_true',help='Print the complete dependency inventory and exit')
    parser.add_argument('--configure-instance',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--hostname',default='',help=argparse.SUPPRESS)
    parser.add_argument('--timezone',default='',help=argparse.SUPPRESS)
    parser.add_argument('--expect-service',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--expect-network',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--verify',action='store_true',help='Report dependencies and current-account capabilities')
    args=parser.parse_args(argv)
    if sys.version_info < (3,10):
        parser.error('Python 3.10 or newer is required. Install a supported Python first.')
    root=args.root.resolve()
    try:
        if args.configure_instance:
            configure_instance(root,args.hostname,args.timezone)
            return 0
        if args.verify:
            verify(root,expect_service=args.expect_service,expect_network=args.expect_network)
            return 0
        host=host_platform()
        if args.dependencies:
            print(json.dumps({'host':host,'dependencies':inventory(root)},indent=2))
            return 0
        if os.environ.get('TWN_TOOLKIT_UPGRADE_REQUEST_ID') or os.environ.get('TWN_TOOLKIT_INSTALL_STATUS_FILE'):
            raise ValueError('Guided setup cannot run inside an unattended upgrade or rollback.')
        if args.yes and not args.config:
            raise ValueError('--yes requires an explicit --config plan.')
        plan=SetupPlan.read(read_settings(args.config)) if args.config else initial_plan(root,host)
        if args.dry_run:
            # A dry run is observational even on unsupported or root environments.
            print(json.dumps({'plan':asdict(plan),'review':review(plan,root,host),'dependencies':inventory(root)},indent=2))
            return 0
        if args.config:
            if not args.yes:
                raise ValueError('Review with --dry-run, then explicitly approve the config with --yes.')
        else:
            if not sys.stdin.isatty() or not sys.stdout.isatty():
                raise ValueError('Use a terminal for guided setup, or --config FILE --yes for automation.')
            if args.plain:
                plan=plain_editor(root,host,plan)
            else:
                try:
                    from .setup_tui import edit_plan
                except ImportError:
                    print('Full-screen terminal support is unavailable; using text setup.')
                    plan=plain_editor(root,host,plan)
                else:
                    import curses
                    try:
                        plan=edit_plan(root,host,plan,motion=not args.no_motion)
                    except curses.error:
                        print('This terminal cannot display full-screen setup; using text setup.')
                        plan=plain_editor(root,host,plan)
            if plan is None:
                print('Setup cancelled. No installation changes were made.')
                return 0
        from .setup_executor import apply
        print('\nTWN / INSTALLING YOUR REVIEWED PLAN\nNative package and privilege prompts follow; passwords are never recorded.')
        count=0
        def stage(message):
            nonlocal count
            count+=1
            print(f'\n[{count:02d}] {message}',flush=True)
        target=apply(plan,root,host,unattended=args.yes,report=stage)
        print(f'\nTWN / SETUP COMPLETE\nLocation: {target}\nRun ./twn status there for verified access URLs. Create the initial administrator through the browser.')
        if not plan.service:
            print('Manual mode: ./twn start when needed; ./twn stop when finished. No automatic boot startup.')
        print('Review any unavailable capabilities above; installed packages alone do not establish permissions.')
        return 0
    except (ValueError,RuntimeError,OSError,TypeError,subprocess.SubprocessError) as exc:
        print(f'Setup stopped: {exc}',file=sys.stderr)
        return 1
    except (KeyboardInterrupt,EOFError):
        print('\nSetup cancelled. Completed installation steps, if any, have not been rolled back.',file=sys.stderr)
        return 130


if __name__=='__main__':
    raise SystemExit(main())
