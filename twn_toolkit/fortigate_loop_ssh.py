"""Fixed read-only FortiGate diagnostics; never arbitrary commands or remediation."""
import re
import time
from .ssh_security import open_ssh_client, close_ssh_client

PREFIX = 'diagnose switch-controller switch-info '
COMMANDS = {'guard':'loop-guard ', 'stp':'stp ', 'lldp':'lldp neighbors-summary '}


def parse_output(kind, output, switch):
    if '--More--' in output or '\x1b' in output or re.search(r'command fail|parse error|permission denied', output, re.I):
        raise ValueError('Incomplete or rejected diagnostic output.')
    vdoms = set(re.findall(r'Vdom:\s*(\S+)', output))
    if vdoms != {'root'}:
        raise ValueError('Diagnostic VDOM could not be verified.')
    if kind=='stp' and not re.search(r'^'+re.escape(switch)+r':\s*$', output, re.M):
        raise ValueError('STP switch identity could not be verified.')
    if kind=='lldp' and not re.search(r'Managed Switch\s*:\s*'+re.escape(switch)+r'\s',output):
        raise ValueError('LLDP switch identity could not be verified.')
    rows=[];instance=None
    for line in output.splitlines():
        match=re.match(r'Instance ID (\d+)',line.strip())
        if match:instance=match[1]
        fields=line.split()
        if not fields or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',fields[0]):continue
        if kind=='guard' and len(fields)>=7 and fields[1] in ('enabled','disabled'):
            rows.append(dict(port=fields[0],instance='',role=fields[1],state=fields[2],flags='',detail=' '.join(fields[3:])[:256]))
        elif kind=='stp' and instance is not None and len(fields)>=7 and fields[4] in ('ROOT','DESIGNATED','ALTERNATIVE','ALTERNATE','BACKUP','DISABLED','MASTER') and fields[5] in ('FORWARDING','DISCARDING','LEARNING','BLOCKING'):
            rows.append(dict(port=fields[0],instance=instance,role=fields[4],state=fields[5],flags=' '.join(fields[7:] if fields[6].isdigit() else fields[6:]),detail=''))
        elif kind=='lldp' and len(fields)>=3 and fields[1] in ('Up','Down'):
            rows.append(dict(port=fields[0],instance='',role='',state=fields[1],flags='',detail=' '.join(fields[2:])[:256]))
    if not rows or len(rows)>4096:raise ValueError('Diagnostic row format is unavailable or exceeds the limit.')
    return rows


def read_command(client, command, check, deadline):
    check()
    if time.monotonic()>=deadline:raise TimeoutError('Diagnostic time budget exhausted.')
    channel=client.get_transport().open_session(timeout=10)
    try:
        channel.exec_command(command)
        content=bytearray()
        end=min(deadline,time.monotonic()+15)
        while time.monotonic()<end:
            check()
            if channel.recv_ready():content.extend(channel.recv(8192))
            elif channel.exit_status_ready():
                if channel.recv_stderr_ready():raise ValueError('Diagnostic returned an error stream.')
                return content.decode('utf-8')
            else:time.sleep(.05)
            if len(content)>262144:raise ValueError('Diagnostic exceeds 256 KiB.')
        raise ValueError('Diagnostic timed out; partial output discarded.')
    finally:channel.close()


def supplement(data, settings, check):
    gate=next((g for g in data['gates'] if not g['via_fabric']),None)
    if not gate:return
    data['ssh_commands']=0
    gate['diagnostic_errors']=[]
    client=None
    try:
        if gate['vdom']!='root' or len(gate['switches'])>16:
            raise ValueError('SSH prototype supports root VDOM and up to 16 switches.')
        deadline=time.monotonic()+60
        client=open_ssh_client(**settings)
        data['ssh_commands']+=1
        identity=read_command(client,'get system status | grep Serial',check,deadline)
        match=re.search(r'Serial-Number:\s*([A-Za-z0-9_-]+)',identity)
        if not match or match[1]!=gate['serial']:raise ValueError('SSH FortiGate identity mismatch.')
        for switch in gate['switches']:
            if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',switch['id']):
                gate['diagnostic_errors'].append(switch['id']+': unsupported CLI identifier.')
                continue
            switch['diagnostics']={}
            for kind,command in COMMANDS.items():
                check()
                try:
                    data['ssh_commands']+=1
                    output=read_command(client,PREFIX+command+switch['id'],check,deadline)
                    rows=parse_output(kind,output,switch['id'])
                    switch['diagnostics'][kind]=rows
                    for row in rows:
                        flags=set(row['flags'].split())
                        if kind=='stp' and flags & {'LP','RG','BG','IC','MV'}:
                            gate['findings'].append(dict(kind='Protection',switch=switch['id'],ports=row['port'],message='STP instance '+row['instance']+' reports protection/inconsistency flags: '+row['flags']))
                        elif kind=='stp' and row['role'] in ('ALTERNATIVE','ALTERNATE','BACKUP') and row['state'] in ('DISCARDING','BLOCKING'):
                            gate['findings'].append(dict(kind='Topology',switch=switch['id'],ports=row['port'],message='STP instance '+row['instance']+' reports a blocked alternate path; this can be normal redundancy.'))
                        elif kind=='guard' and row['role']=='enabled' and row['state'].lower() in ('blocked','blocking','loop-detected'):
                            gate['findings'].append(dict(kind='Protection',switch=switch['id'],ports=row['port'],message='Loop Guard reports '+row['state']+'.'))
                except ValueError as exc:
                    gate['diagnostic_errors'].append(switch['id']+' · '+kind+': '+str(exc))
    except Exception as exc:
        # Transport exceptions may contain private connection details. Retain only type.
        gate['diagnostic_errors'].append('SSH diagnostics unavailable ('+type(exc).__name__+').')
    finally:close_ssh_client(client)
    data['coverage']='SSH diagnostics supplement the connected gate only. Missing sources, downstream gates and unrecognized formats remain unavailable; this is not a loop-free assessment.'
    data['partial'] = data['partial'] or bool(gate['diagnostic_errors'])
    data['protection_count']=sum(f['kind']=='Protection' for g in data['gates'] for f in g['findings'])
