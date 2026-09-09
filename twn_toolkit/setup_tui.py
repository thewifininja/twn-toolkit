#!/usr/bin/env python3
"""Interactive setup plan editor. Execution starts only after the reviewed plan is accepted."""
import curses
import platform
import random
import textwrap
import time
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

LOGO = [
    '████████╗██╗    ██╗███╗   ██╗',
    '╚══██╔══╝██║    ██║████╗  ██║',
    '   ██║   ██║ █╗ ██║██╔██╗ ██║',
    '   ██║   ██║███╗██║██║╚██╗██║',
    '   ██║   ╚███╔███╔╝██║ ╚████║',
    '   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═══╝',
]
PAGES = ['Preflight', 'Run mode', 'Location', 'System tools', 'Identity & time', 'Network access', 'Review']
from .setup_dependencies import DEPENDENCIES, inventory
from .setup_plan import SetupPlan, review, validate
from .server_settings import normalize_preferred_fqdn
import socket


def timezone_label(zone):
    if zone == 'Follow host':
        return 'Follow this computer’s timezone'
    if zone == 'UTC':
        return 'UTC / Coordinated Universal Time'
    region, _, place = zone.partition('/')
    return place.replace('_', ' ').replace('/', ' / ')+' · '+region



class Wizard:
    def __init__(self, screen, root, host, plan, motion=True):
        self.s = screen
        self.motion = motion
        self.root, self.host, self.original = root, host, plan
        self.accepted = False
        self.page = -1
        self.row = 0
        self.focus = 0  # 0: fields, 1: Back, 2: Next
        self.offset = 0
        self.error = ''
        self.editing = None
        self.buffer = ''
        self.confirm_exit = False
        self.locations = {}
        self.host_label = host['name']
        self.manager = host['adapter'] or 'unsupported'
        self.manager_path = host['manager']
        kind = 2 if host['system'] == 'Darwin' else 1 if host['adapter'] == 'pacman' else 0
        self.inventory = inventory(root,system=host['system'])
        self.specs = {spec.id:spec for spec in DEPENDENCIES}
        self.tool_presence = {row['id']:row['present'] for row in self.inventory}
        self.optional = [row for row in self.inventory if row['category'] in {'optional','permission'} or
                         (row['category']=='system' and not row['present'] and getattr(self.specs[row['id']],self.manager,()))]
        self.interface_choices = [name for _,name in socket.if_nameindex() if not name.startswith('lo')]
        self.tz_open, self.tz_query, self.tz_row = False, '', 0
        self.zones = ['Follow host', 'UTC'] + sorted((z for z in available_timezones()
            if z.split('/')[0] in {'Africa','America','Antarctica','Arctic','Asia','Atlantic','Australia','Europe','Indian','Pacific'}), key=timezone_label)
        self.review_lines = []
        self.data = dict(platform=kind, service=plan.service, hostname=plan.hostname,
                         timezone=plan.timezone or 'Follow host', network=plan.network,
                         lldpd=plan.lldpd, pf=bool(plan.pf_interfaces))
        self.data.update({'tool_'+row['id']:row['id'] in plan.packages for row in self.optional})
        self.data.update({'pf_'+name:name in plan.pf_interfaces for name in self.interface_choices})
        self.locations[(kind,plan.service)] = plan.location
        self.install_start = None
        self.done = False
        self.hits = []
        self.colors = {}
        self.started = time.monotonic()
        self.configure()

    def configure(self):
        curses.curs_set(0)
        self.s.keypad(True)
        self.s.timeout(80)
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            # Phosphor green, warm white, and muted gray on near-black.
            palette = [ (252, 233), (46, 233), (241, 233), (232, 84), (84, 235), (215, 233), (28, 233) ]
            if curses.COLORS < 256:
                palette = [(7,0),(2,0),(7,0),(0,2),(2,0),(3,0),(2,0)]
            for n, pair in enumerate(palette, 1):
                curses.init_pair(n, *pair)
                self.colors[n] = curses.color_pair(n)
            self.s.bkgd(' ', self.colors[1])
        try:
            curses.mousemask(curses.ALL_MOUSE_EVENTS)
            curses.set_escdelay(25)
        except (AttributeError, curses.error):
            pass

    def put(self, y, x, text, color=1, bold=False, limit=None):
        h, w = self.s.getmaxyx()
        if not 0 <= y < h or x >= w - 1:
            return
        text = str(text)
        if x < 0:
            text, x = text[-x:], 0
        count = max(0, min(w - x - 1, limit if limit is not None else w))
        try:
            self.s.addstr(y, x, text[:count], self.colors.get(color, 0) | (curses.A_BOLD if bold else 0))
        except curses.error:
            pass

    def para(self, y, x, text, width, color=3):
        lines = textwrap.wrap(text, max(10, width))
        for n, line in enumerate(lines):
            self.put(y+n, x, line, color)
        return y + len(lines)

    def location(self):
        key = self.data['platform'], self.data['service']
        return self.locations.get(key,str(self.root))

    def items(self):
        d = self.data
        if self.page == 1:
            return [('service', 'Run as a service', 'Start at boot. No open terminal needed. Best for an always-on agent.', True),
                    ('service', 'Start it myself', 'On-demand use. No automatic startup. You can enable a service later.', False)]
        if self.page == 2:
            return [('location', 'Installation folder', 'Enter to edit. Your location is remembered for each platform and run mode.', None)]
        if self.page == 3:
            return [('tool_'+row['id'],row['name']+('  [found]' if row['present'] else '  [optional]'),
                     row['purpose']+'. '+row['note'], 'toggle') for row in self.optional]
        if self.page == 4:
            return [('hostname', 'Preferred hostname (optional)', 'Blank uses local addresses. Configure DNS and a matching HTTPS certificate separately.', None),
                    ('timezone', 'Display timezone', 'Enter opens a searchable city/region selector. No timezone names to memorize.', None)]
        if self.page == 5:
            if self.host['system']=='Linux':
                items = [('lldpd','Enable LLDP daemon','Enable/start lldpd via systemd; package installation alone is not readiness.','toggle')]
                if d['service']:
                    items.insert(0,('network','Diagnostic service capabilities','Grant only the existing Linux service capabilities for capture and privileged networking.','toggle'))
                return items
            items = [('pf','macOS multicast compatibility','Separate opt-in: dedicated PF anchor, backup and restart guidance; no live reload.','toggle')]
            if d['pf']:
                items += [('pf_'+name,name,'Include this interface in the optional PF rule.','toggle') for name in self.interface_choices]
            return items
        return []

    def value(self, key):
        return self.location() if key == 'location' else self.data[key]

    def validate(self, key, value):
        if key=='hostname':
            try:
                normalize_preferred_fqdn(value)
                return ''
            except ValueError as exc:
                return str(exc)
        if not value or any(ord(c) < 32 for c in value):
            return 'Enter a value without control characters.'
        if key == 'location':
            if not (value.startswith('/') or value.startswith('~/')):
                return 'Use an absolute path or a path starting with ~/.'
            parts = {p.casefold() for p in value.split('/')}
            if self.data['platform'] == 2 and self.data['service'] and parts & {'desktop','documents','downloads','cloudstorage','mobile documents','icloud drive'}:
                return 'macOS service: choose a local folder outside protected or cloud directories.'
        if key == 'timezone' and value.lower() != 'follow host':
            try:
                ZoneInfo(value)
            except (ZoneInfoNotFoundError, ValueError):
                return 'Use an IANA timezone such as Europe/London, UTC, or Follow host.'
        return ''

    def plan(self):
        return SetupPlan(self.location(),service=self.data['service'],
                         packages=[row['id'] for row in self.optional if self.data['tool_'+row['id']]],
                         hostname=self.data['hostname'],timezone='' if self.data['timezone']=='Follow host' else self.data['timezone'],
                         network=self.data['network'] if self.data['service'] and self.host['system']=='Linux' else False,
                         lldpd=self.data['lldpd'],pf_interfaces=[name for name in self.interface_choices if self.data['pf'] and self.data['pf_'+name]])

    def summary(self):
        try:
            return review(self.plan(),self.root,self.host)
        except ValueError as exc:
            return [('Plan needs attention',str(exc))]

    def rain(self, top, bottom, left, right):
        tick = int((time.monotonic()-self.started)*10) if self.motion else 12
        height = max(1, bottom-top)
        for x in range(left, right, 3):
            rng = random.Random(x*721)
            head = (tick*(1+x%3)/2 + rng.randrange(height*2)) % (height+9)
            for tail in range(8):
                y = int(head)-tail
                if 0 <= y < height:
                    self.put(top+y, x, rng.choice('01:<>/{}*+'), 2 if tail == 0 else 7)

    def draw(self):
        self.s.erase()
        self.hits = []
        h, w = self.s.getmaxyx()
        if h < 24 or w < 68:
            self.put(1, 2, 'TWN / GUIDED INSTALLER', 2, True)
            self.para(3, 2, 'Enlarge your terminal to at least 68 columns × 24 rows. Your choices are preserved. Press Q to exit.', w-5)
            self.s.refresh()
            return
        self.put(1, 3, 'TWN  /  INITIALIZE', 2, True)
        self.put(1, w-24, 'GUIDED INSTALLATION', 6)
        self.put(2, 3, '─'*(w-6), 7)
        if self.page == -1:
            self.rain(4, h-7, 3, w-3)
            x, y = max(5, (w-52)//2), max(4, (h-19)//2)
            for n in range(11):
                self.put(y+n, x-2, ' '*54)
            for n, line in enumerate(LOGO):
                self.put(y+n, x, line, 2, True)
            self.put(y+7, x, 'YOUR NETWORK. YOUR TOOLKIT.', 1, True)
            self.put(y+9, x, 'A guided installation, tuned to the way you work.', 3)
            self.put(h-7, 5, 'Detected: '+self.host_label, 2)
            self.put(h-6, 5, 'Review first. Install only the options you choose.', 3)
        else:
            sidebar = w >= 98
            x = 27 if sidebar else 5
            width = w-x-5
            if sidebar:
                self.put(4, 3, 'INSTALLATION PLAN', 3, True)
                for n, name in enumerate(PAGES):
                    self.put(7+n*2, 3, ('●' if n == self.page else '✓' if n < self.page else '·')+f' {n+1:02d}  '+name,
                             2 if n == self.page else 3, n == self.page)
                self.put(h-7, 3, 'YOUR SETUP', 7)
            self.put(4, x, f'{self.page+1:02d} / 07    {PAGES[self.page].upper()}', 2, True)
            descriptions = [
                'Detected automatically. These checks do not execute package managers.',
                'Choose how it runs first. Then we can recommend where it should live.',
                'Choose a stable home for your toolkit.',
                'Choose each tool independently. Found binaries are kept; missing tools are opt-in.',
                'Make it yours. Operating-system settings remain untouched.',
                'Choose the optional setup you want. These choices require OS authorization at install time.',
                'Your plan, ready for review. Go back to change anything.'
            ]
            y = self.para(6, x, descriptions[self.page], width) + 1
            if self.page == 0:
                manager_status = (self.manager+' found on PATH') if self.manager_path else (self.manager+' not found') if self.manager else 'No supported package-manager adapter'
                rows = [('Operating system', self.host_label), ('Python', platform.python_version()),
                        ('Package manager', manager_status), ('Privilege prompts', 'Only for selected steps that need them')]
                for label, value in rows:
                    y = self.para(y, x, label+': '+value, width, 1)+1
                self.para(y, x, 'No package manager? Use the platform instructions or skip optional packages. Native package tools will show their transaction before installation.', width, 6)
            elif self.page == 6:
                self.review_lines = []
                for label, value in self.summary():
                    self.review_lines.extend(textwrap.wrap(f'{label}: {value}', width))
                self.review_lines.extend(textwrap.wrap('Authorization: the OS will request approval only for privileged steps. No passwords are collected by the wizard.', width))
                capacity = max(1, h-8-y)
                self.row = min(self.row, max(0, len(self.review_lines)-capacity))
                for line in self.review_lines[self.row:self.row+capacity]:
                    self.put(y, x, line, 1, limit=width)
                    y += 1
                if len(self.review_lines) > capacity:
                    self.put(h-7, x, '↑ / ↓ Scroll plan · ← Back to edit', 3)
            else:
                items = self.items()
                # Keep focused field visible even in a short terminal.
                capacity = max(1, (h-8-y)//3)
                self.offset = min(self.offset, self.row)
                if self.row >= self.offset+capacity:
                    self.offset = self.row-capacity+1
                for index in range(self.offset, min(len(items), self.offset+capacity)):
                    key, label, help_, value = items[index]
                    focused = self.focus == 0 and self.row == index
                    current = self.value(key)
                    mark = 'READY' if key.startswith('tool_') and self.tool_presence[key[5:]] else ('ON ' if current else 'OFF') if value == 'toggle' else ('●' if current == value else '○') if value is not None else '›'
                    line = f' {mark}  {label}'
                    if value is None:
                        line += '  '+(timezone_label(current) if key == 'timezone' else str(current))
                    self.put(y, x, line.ljust(width), 4 if focused else 5, focused, width)
                    self.put(y+1, x+2, help_, 3, limit=width-2)
                    self.hits.append((y, x, width, ('item', index)))
                    y += 3
                if len(items) > capacity:
                    self.put(y, x, '↑ / ↓  More fields', 3)
                    y += 1
                notes = ''
                if self.page == 1:
                    notes = 'Service setup requests OS authorization after review. Manual mode can be changed later.'
                if self.page == 2:
                    if self.data['platform'] == 2:
                        notes = ('SERVICE LOCATION: avoid Desktop, Documents, Downloads, iCloud Drive and Library/CloudStorage. Suggested: ~/twn-toolkit.'
                                 if self.data['service'] else 'MANUAL MODE: ~/twn-toolkit also makes a later move to service mode easier.')
                    else:
                        notes = 'Setup will check resolved paths, ownership, free space and existing files before continuing.'
                if self.page == 3:
                    notes = (self.manager+' detected. ' if self.manager_path else 'Package manager unavailable or unverified: offer setup/help/skip. ')+'Approve exact transactions before installation. Homebrew never runs as root.'
                if self.page == 4:
                    notes = 'Setup will explain hostname resolution and HTTPS certificates for the chosen name.'
                if self.page == 5 and self.data['platform'] == 2:
                    notes = 'PF compatibility: dedicated rules, interface selection, backup/removal and restart guidance. No live firewall reload.'
                if notes and y+1 < h-7:
                    for n, line in enumerate(textwrap.wrap(notes, width)):
                        if y+n >= h-7:
                            break
                        self.put(y+n, x, line, 6 if self.page == 2 else 3)
        self.footer(h, w)
        if self.editing:
            self.draw_edit(h, w)
        if self.tz_open:
            self.draw_timezone(h, w)
        if self.confirm_exit:
            self.modal(h, w, 'CANCEL SETUP?', ['Your choices exist only in this session.', 'Enter: exit    Esc: return to setup'])
        self.s.refresh()

    def footer(self, h, w):
        self.put(h-5, 3, self.error, 6, limit=w-6)
        self.put(h-4, 3, '─'*(w-6), 7)
        left = ' Back ' if self.page >= 0 else ' Exit '
        right = ' Begin setup → ' if self.page == -1 else ' Install → ' if self.page == 6 else ' Next → '
        self.put(h-3, 4, left, 4 if self.focus == 1 else 5, True)
        if self.install_start is None or self.done:
            self.put(h-3, w-len(right)-4, right, 4 if self.focus == 2 or self.page == -1 else 5, True)
            self.hits += [(h-3, w-len(right)-4, len(right), ('next', 0))]
        self.hits += [(h-3, 4, len(left), ('back', 0))]
        self.put(h-2, 4, '↑↓ Select  Enter Choose/Edit  Tab Buttons  ← Back  → Next  Q Exit  M Motion', 3, limit=w-8)

    def modal(self, h, w, title, lines):
        width = min(70, w-8)
        x, y = (w-width)//2, (h-8)//2
        for n in range(8):
            self.put(y+n, x, ' '*width, 5)
        self.put(y, x, '┌'+'─'*(width-2)+'┐', 2)
        self.put(y+1, x+2, title, 2, True)
        for n, line in enumerate(lines):
            self.put(y+3+n, x+2, line, 1, limit=width-4)
        self.put(y+7, x, '└'+'─'*(width-2)+'┘', 2)
        return y, x, width

    def draw_edit(self, h, w):
        y, x, width = self.modal(h, w, 'EDIT / '+self.editing.upper(), ['', '', 'Enter Save · Esc Cancel · Ctrl+U Clear'])
        self.put(y+3, x+2, (self.buffer[-(width-6):]+'▌').ljust(width-4), 4, limit=width-4)
        if self.error:
            self.put(y+5, x+2, self.error, 6, limit=width-4)

    def timezone_matches(self):
        words = self.tz_query.casefold().split()
        return [z for z in self.zones if all(word in (timezone_label(z)+' '+z).casefold().replace('_',' ') for word in words)]

    def draw_timezone(self, h, w):
        width, height = min(76, w-8), min(20, h-4)
        x, y = (w-width)//2, (h-height)//2
        for n in range(height):
            self.put(y+n, x, ' '*width, 5)
        self.put(y, x, '┌'+'─'*(width-2)+'┐', 2)
        self.put(y+1, x+2, 'TIMEZONE / FIND YOUR CITY', 2, True)
        self.put(y+3, x+2, ('Search: '+self.tz_query+'▌').ljust(width-4), 4, limit=width-4)
        matches = self.timezone_matches()
        capacity = height-8
        self.tz_row = min(self.tz_row, max(0,len(matches)-1))
        start = max(0,self.tz_row-capacity+1)
        for n, zone in enumerate(matches[start:start+capacity], start):
            self.put(y+5+n-start, x+2, timezone_label(zone).ljust(width-4), 4 if n == self.tz_row else 5, limit=width-4)
        if not matches:
            self.put(y+5, x+2, 'No matches. Try a nearby city or region.', 6)
        self.put(y+height-3, x+2, f'{len(matches)} choices · ↑↓ Move · Enter Select · Esc Cancel', 3, limit=width-4)
        self.put(y+height-2, x+2, 'Type to search · Backspace / Ctrl+U clear', 3)
        self.put(y+height-1, x, '└'+'─'*(width-2)+'┘', 2)

    def timezone_key(self, key):
        matches = self.timezone_matches()
        if key == '\x1b':
            self.tz_open = False
        elif key in ('\n','\r',curses.KEY_ENTER):
            if matches:
                self.data['timezone'] = matches[self.tz_row]
                self.tz_open, self.error = False, ''
        elif key in (curses.KEY_UP,curses.KEY_DOWN):
            self.tz_row = (self.tz_row+(1 if key == curses.KEY_DOWN else -1)) % max(1,len(matches))
        elif key in (curses.KEY_BACKSPACE,'\x7f','\b'):
            self.tz_query, self.tz_row = self.tz_query[:-1], 0
        elif key == '\x15':
            self.tz_query, self.tz_row = '', 0
        elif isinstance(key,str) and key.isprintable() and len(self.tz_query) < 80:
            self.tz_query += key
            self.tz_row = 0
        return True

    def advance(self):
        if self.page>=2:
            try:
                validate(self.plan(),self.root,self.host,prerequisites=self.page >= 3)
                if self.data['pf'] and not self.plan().pf_interfaces:
                    raise ValueError('Select at least one interface or disable PF compatibility.')
            except (ValueError,RuntimeError,OSError) as exc:
                self.error = str(exc)
                return True
        if self.page == 6:
            self.accepted = True
            return False
        self.page += 1
        self.row, self.offset, self.focus = 0, 0, 0
        self.error = ''
        return True

    def back(self):
        if self.install_start is not None:
            self.install_start, self.done = None, False
        elif self.page >= 0:
            self.page -= 1
        else:
            self.confirm_exit = True
        self.row, self.offset, self.focus = 0, 0, 0
        self.error = ''

    def activate(self):
        items = self.items()
        if not items:
            return self.advance()
        key, _, _, value = items[self.row]
        self.error = ''
        if key.startswith('tool_') and self.tool_presence[key[5:]]:
            self.error = 'Already found on PATH. Setup will verify its version and permissions.'
        elif key.startswith('tool_') and (not self.manager_path or (not getattr(self.specs[key[5:]],self.manager,()) and key!='tool_bpf')):
            self.error = 'No supported package manager/mapping. Install prerequisites manually or skip this option.'
        elif key == 'timezone':
            self.tz_open, self.tz_query = True, ''
            self.tz_row = self.zones.index(self.data['timezone']) if self.data['timezone'] in self.zones else 0
        elif value is None:
            self.editing, self.buffer = key, str(self.value(key))
        elif value == 'toggle':
            self.data[key] = not self.data[key]
        else:
            self.data[key] = value
        return True

    def key(self, key):
        if self.tz_open:
            return self.timezone_key(key)
        if self.confirm_exit:
            if key in ('\n','\r',curses.KEY_ENTER):
                return False
            if key == '\x1b':
                self.confirm_exit = False
            return True
        if self.editing:
            if key == '\x1b':
                self.editing, self.error = None, ''
            elif key in ('\n','\r',curses.KEY_ENTER):
                value = self.buffer.strip()
                self.error = self.validate(self.editing, value)
                if not self.error:
                    if self.editing == 'location':
                        self.locations[(self.data['platform'], self.data['service'])] = value
                    else:
                        self.data[self.editing] = 'Follow host' if self.editing == 'timezone' and value.lower() == 'follow host' else value
                    self.editing = None
            elif key in (curses.KEY_BACKSPACE, '\x7f', '\b'):
                self.buffer = self.buffer[:-1]
            elif key == '\x15':
                self.buffer = ''
            elif isinstance(key, str) and key.isprintable() and len(self.buffer) < 180:
                self.buffer += key
            return True
        if key in ('q','Q','\x1b'):
            self.confirm_exit = True
        elif key in ('m','M'):
            self.motion = not self.motion
        elif key == curses.KEY_MOUSE:
            try:
                _, x, y, _, event = curses.getmouse()
                if event & (curses.BUTTON1_CLICKED | curses.BUTTON1_RELEASED):
                    for row, col, width, (action, index) in self.hits:
                        if y == row and col <= x < col+width:
                            if action == 'next':
                                return self.advance()
                            if action == 'back':
                                self.back()
                            if action == 'item':
                                self.row, self.focus = index, 0
                                return self.activate()
                            break
            except curses.error:
                pass
        elif key in ('\t',curses.KEY_BTAB):
            self.focus = (self.focus + (1 if key == '\t' else -1)) % 3
        elif key in (curses.KEY_LEFT,'p','P'):
            self.back()
        elif key in (curses.KEY_RIGHT,'n','N'):
            return self.advance()
        elif key in (curses.KEY_UP,curses.KEY_DOWN):
            self.focus = 0
            if self.page == 6:
                self.row = max(0, self.row+(1 if key == curses.KEY_DOWN else -1))
            else:
                self.row = (self.row+(1 if key == curses.KEY_DOWN else -1)) % max(1,len(self.items()))
        elif key in ('\n','\r',curses.KEY_ENTER,' '):
            if self.focus == 1:
                self.back()
            elif self.focus == 2 or self.page == -1:
                return self.advance()
            elif self.install_start is not None:
                if self.done:
                    return False
            else:
                return self.activate()
        return True

    def run(self):
        while True:
            self.draw()
            try:
                key = self.s.get_wch()
            except curses.error:
                continue
            h, w = self.s.getmaxyx()
            if h < 24 or w < 68:
                if key in ('q','Q','\x1b'):
                    break
                continue
            if not self.key(key):
                break


def edit_plan(root, host, plan, *, motion=True):
    def run(screen):
        wizard = Wizard(screen,root,host,plan,motion)
        wizard.run()
        return wizard.plan() if wizard.accepted else None
    return curses.wrapper(run)
