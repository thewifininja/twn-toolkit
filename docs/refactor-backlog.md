# Refactor backlog

This is the working audit trail for cleanup and future-proofing. The goal is to
make new internal tools easier to add without breaking the current app or
turning the codebase into a rewrite project.

## Guiding standard

- Keep the internal registry as the source of truth for tools, navigation,
  favorites, access-profile assignment, and route authorization.
- Keep route handlers thin: validate form/request data, call a service/helper,
  then render or return the result.
- Put tool-specific logic in service modules, not directly in Flask route
  handlers.
- Prefer small, tested moves over broad rewrites.
- Any route that performs a restricted action should be mapped in
  `twn_toolkit/tool_modules/`.
- Any user-facing server-side action that can take noticeable time should use
  `data-loading-message`.

## Current scan findings

### 0. Formalize SQLite migrations before the next schema expansion

Automation schema expansion now uses the numbered
`automation_schema_migrations` ledger. Pipeline migration 1 adds ordered action
stages and transactionally converts existing flat action lists into one default
parallel stage. Migration 2 persists first-generation SNMP definitions as
per-host AND rules. Activity still uses its earlier one-time legacy import marker;
introduce the same numbered pattern there before its next material schema change.

Remaining before 1.0:

1. Expand upgrade tests from constructed legacy rows to representative older
   database snapshots.
2. Add a matching numbered migration ledger to activity SQLite before its next
   schema expansion.
3. Keep startup failures explicit and transactional as additional versions are
   introduced.

### 1. `app.py` was the main gravity well

`twn_toolkit/app.py` previously held most of the application wiring plus many
route handlers. It has been reduced to the app factory, authentication flow,
shared context, CLI reset commands, homepage, favorites, and route
registration. The biggest clusters extracted from it were:

- authentication and settings
- backup/import/export
- FortiGate profiles
- FortiGate switch ordering
- wireless client history
- FortiAuthenticator profiles and workflows
- generic FortiGate task execution

This works, but it makes unrelated features feel coupled and increases the
chance that future UI or access-control changes need to be fixed in multiple
places.

Recommended direction:

1. Keep shared app factories/stores in one small composition layer.
2. Avoid adding new domain route handlers directly to `app.py`.
3. Continue preserving existing endpoint names when route groups move.

### 2. `tools.py` should become smaller tool blueprints over time

`twn_toolkit/tools.py` is still large and contains many independent network
tools. The current service/helper split is decent, but the route file is
becoming a second mini-app.

Recommended direction:

1. Keep `tools_bp` as the URL prefix owner for now.
2. Move large route groups into focused modules when they are touched:
   - Done: NTP route/profile handlers extracted to `twn_toolkit/ntp_routes.py`
   - Done: Traceroute route/profile/live-run handlers extracted to
     `twn_toolkit/traceroute_routes.py`
   - Done: TCP port scanner route/profile handlers extracted to
     `twn_toolkit/port_scanner_routes.py`
   - Done: Ping route/profile/live-run handlers extracted to
     `twn_toolkit/ping_routes.py`
   - Done: DNS lookup route/profile handlers extracted to
     `twn_toolkit/dns_routes.py`
   - Done: Packet replay route extracted to
     `twn_toolkit/packet_replay_routes.py`
   - Done: Path MTU route extracted to `twn_toolkit/path_mtu_routes.py`
   - Done: Webhook/API tester route extracted to
     `twn_toolkit/api_request_routes.py`
   - Done: Syslog receiver/sender route extracted to
     `twn_toolkit/syslog_routes.py`
   - Done: DHCP Discover route extracted to `twn_toolkit/dhcp_routes.py`
   - Done: What's My IP route extracted to `twn_toolkit/ip_info_routes.py`
   - Done: Certificate Inspector route extracted to
     `twn_toolkit/certificate_routes.py`
   - Done: Speed Test routes extracted to `twn_toolkit/speed_test_routes.py`
   - Done: Subnet Excluder route extracted to `twn_toolkit/subnet_routes.py`
   - Done: SSH command runner route extracted to `twn_toolkit/ssh_routes.py`
   - Done: SNMP tester and profile handlers extracted to
     `twn_toolkit/snmp_routes.py`
   - Done: RADIUS tester and profile handlers extracted to
     `twn_toolkit/radius_routes.py`
   - SNMP
3. Preserve existing endpoint names where possible so registry IDs, tests, and
   bookmarks remain stable.

### 3. Route registry coverage is mostly good, but admin routes need consistency

The registry now maps most tool action endpoints. The scan showed unmapped
logged-in endpoints including:

- `settings`
- `update_theme`
- `change_user_password`
- `update_user_access`
- `save_access_profile`
- `delete_access_profile`
- `toggle_tool_favorite`
- `fortigate_home`
- `fortiauthenticator_home`
- `tools.index`

Some of these are intentionally self-service or category landing pages. Others
are already protected by explicit admin checks. Still, it would be cleaner to
make this policy explicit in one place so future work does not accidentally
copy an unmapped route pattern.

Recommended direction:

1. Add a registry/audit test that lists intentionally unmapped endpoints.
2. Map system-administrator-only settings actions to `admin.settings` where appropriate.
3. Leave self-service endpoints intentionally unmapped, but document them in
   the test.
4. Continue using category checks for Fortinet landing pages.

### 4. External request timeout behavior should be standardized

FortiAuthenticator and FortiGate now use split connect/read timeouts so
unreachable hosts fail quickly while slower API responses can still use the
configured/read timeout window. The shared helper lives in
`twn_toolkit/http_client.py`. Some other tools still have their own timeout
styles.

Recommended direction:

1. Give HTTP/TLS/connection/read failures friendly messages consistently across
   any remaining HTTP-style clients.
2. Audit tools that call sockets, subprocesses, Paramiko, pysnmp, or external
   binaries for bounded timeouts.

### 5. Profile stores are duplicated

`ProfileStore` and `PingProfileStore` now share a common `JsonListStore` base
with configurable filenames and overridable default records. Public store class
names stayed intact so routes, backup/import code, and tests did not need broad
churn.

Recommended direction:

1. Move merge/replace behavior at the store layer so backup/import is simpler.
2. Consider whether store classes should expose labels/sensitivity for backup
   registration.

### 6. Backup catalog registration is domain-owned

The backup catalog assembly, encryption helpers, validation, and merge/replace
import logic now live in `twn_toolkit/profile_backup.py`. Individual backup
groups are registered near their related tool/domain modules through
`backup_items(instance_path)`.

Recommended direction:

1. Keep the encryption rule: sensitive groups require encrypted backups.
2. Consider a tiny typed backup-item helper if more domains register groups.

### 7. Shared UI patterns are centralized for common workspaces

The launch cards and newer collapsible sections now share Jinja macros for
workspace introductions, section headers, standalone empty states, profile
sections, create controls, saved-record cards, and action rows. The first
migration covers certificate automation, SNMP, RADIUS, automations, settings,
diagnostics, updates, FortiGate, FortiAuthenticator, the dashboard, and the
datastore text viewer.

Recommended direction:

1. Use `templates/components/ui.html` when adding or touching these patterns;
   extend a shared macro before introducing equivalent local markup.
2. Keep `data-loading-message` required for slow server-side actions.
3. Continue opportunistic migration of specialized legacy pages without forcing
   distinct operational displays into one visual shape.

### 8. Large risky tools need preview-first consistency

Packet replay, MAC cleanup, switch ordering, and bulk rename tasks all have
different preview/confirmation shapes.

Recommended direction:

1. Define a shared “dangerous action” UI pattern.
2. Require preview, explicit confirmation, and clear success/error summaries.
3. Keep `risk="high"` or `risk="advanced"` accurate in the registry.

## Suggested implementation order

### Phase 1: Guardrails

- Add a route registry audit test with an explicit allowlist for unmapped
  self-service/category endpoints.
- Map missing system-administrator-only settings endpoints to `admin.settings`.
- Standardize FortiGate HTTP timeout/error behavior.
- Confirm all slow forms have loading messages.

Status:

- Done: route registry audit test.
- Done: missing admin settings endpoint mappings.
- Done: FortiGate and FortiAuthenticator split HTTP connect/read timeouts.

### Phase 2: Low-risk extraction

- Extract backup catalog/build/import/export helpers from `app.py`.
- Extract FortiAuthenticator routes into a blueprint.
- Extract FortiGate profile routes into a blueprint.

Status:

- Done: backup catalog, encryption/decryption, validation, and merge/replace
  import helpers extracted to `twn_toolkit/profile_backup.py`.
- Done: FortiAuthenticator routes and MAC cleanup helpers extracted to
  `twn_toolkit/fortiauthenticator_routes.py` while preserving existing URLs and
  endpoint names.
- Done: FortiGate profile, task, switch-order, and wireless-history routes
  extracted to `twn_toolkit/fortigate_routes.py` while preserving existing URLs
  and endpoint names.
- Done: admin/settings/user/access-profile/server/backup routes extracted to
  `twn_toolkit/admin_routes.py` while preserving existing URLs and endpoint
  names.

### Phase 3: Store and module cleanup

- Consolidate profile store base classes.
- Move backup group registration closer to the relevant tool/domain module.
- Use domain-owned profile registration for reset-data cleanup.
- Split `tools.py` route groups only as those tools are touched.

Status:

- Done: profile/list stores consolidated under `JsonListStore` while preserving
  existing public store classes, filenames, default SNMP OID profiles, and
  owner-readable file permissions.
- Done: backup group registration moved to FortiGate, FortiAuthenticator, and
  Network tool modules via `backup_items(instance_path)`, with the central
  backup service only assembling and processing the catalog.
- Done: reset-data cleanup now clears the same domain-registered profile stores
  through `build_reset_stores(instance_path)` instead of keeping a second
  hardcoded store list in `app.py`.
- Done: NTP tool routes extracted from `tools.py` to `twn_toolkit/ntp_routes.py`
  while preserving `/tools/ntp-test` URLs and `tools.*` endpoint names.
- Done: Traceroute tool routes extracted from `tools.py` to
  `twn_toolkit/traceroute_routes.py` while preserving `/tools/traceroute` URLs,
  live-run streaming, and `tools.*` endpoint names.
- Done: TCP port scanner routes extracted from `tools.py` to
  `twn_toolkit/port_scanner_routes.py` while preserving `/tools/port-scanner`
  URLs, host/port profile CRUD, and `tools.*` endpoint names.
- Done: Ping tool routes extracted from `tools.py` to `twn_toolkit/ping_routes.py`
  while preserving `/tools/ping` URLs, live-run JSON responses, profile CRUD,
  and `tools.*` endpoint names.
- Done: DNS lookup routes extracted from `tools.py` to `twn_toolkit/dns_routes.py`
  while preserving `/tools/dns-response` URLs, host/server profile CRUD, and
  `tools.*` endpoint names.
- Done: Packet replay route extracted from `tools.py` to
  `twn_toolkit/packet_replay_routes.py` while preserving `/tools/packet-replay`
  URL and `tools.packet_replay` endpoint name.
- Done: Path MTU, Webhook/API tester, and Syslog receiver/sender routes
  extracted from `tools.py` to focused route modules while preserving their
  existing URLs and `tools.*` endpoint names.
- Done: DHCP Discover, What's My IP, Certificate Inspector, Speed Test, and
  Subnet Excluder routes extracted from `tools.py` to focused route modules
  while preserving their existing URLs and `tools.*` endpoint names.
- Done: SSH command runner route extracted from `tools.py` to
  `twn_toolkit/ssh_routes.py` while preserving `/tools/multi-ssh` URL and
  `tools.multi_ssh` endpoint name.
- Done: SNMP tester and profile handlers extracted from `tools.py` to
  `twn_toolkit/snmp_routes.py` while preserving `/tools/snmp-test` URLs and
  `tools.*` endpoint names.
- Done: RADIUS tester and profile handlers extracted from `tools.py` to
  `twn_toolkit/radius_routes.py` while preserving `/tools/radius-test` URLs and
  `tools.*` endpoint names.

### Phase 4: UI component pass

- Done: add Jinja macros for common workspace introductions, section headers,
  empty states, collapsible profile cards, create controls, and action rows.
- Done: migrate the certificate, SNMP, RADIUS, automation, administration,
  Fortinet profile, dashboard, and datastore text-viewer patterns touched by the
  system audit.
- Continue converting specialized older templates opportunistically when their
  surrounding workflows are touched.
- Keep the homepage/category card design as the visual baseline.

Status:

- Done: the automation page's condition evidence/forms and action forms were
  extracted into focused Jinja macro partials while preserving one shared page
  layout.
- Done: SNMP rule-builder behavior was extracted from the shared automation
  script into `automation-snmp.js`, and condition evidence moved into its own
  Jinja partial.
- Done: automation type models and trusted implementations were extracted from
  the registry facade and grouped under `automation_types/condition_types/`.
  Each registered type now owns form parsing, and action
  types declare secret fields used by the encrypted store/masked UI path.
- Done: automation save routes dispatch through registry-owned parsers instead
  of branching on every condition/action type.

## Do-not-do list

- Do not rename stable tool IDs casually; they are used for favorites and
  access profiles.
- Do not make dynamic third-party plugin loading part of this cleanup.
- Do not do a broad blueprint migration without tests around route names and
  permissions.
- Do not rely on hidden navbar links as security.
