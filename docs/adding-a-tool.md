# Adding an internal tool

The toolkit uses an internal registry so navigation, favorites, access profiles,
and route authorization are driven from one tool definition instead of scattered
template conditionals.

This is intentionally not a dynamic third-party plugin loader. New tools are
trusted project code that register themselves explicitly.

## Current architecture standard

- Keep route handlers in the existing Flask blueprints unless a larger refactor
  is intentionally underway.
- Put reusable tool logic in a small service/helper module instead of directly in
  the route.
- Register tool metadata and route ownership in `twn_toolkit/tool_modules/`.
- Let the registry drive homepage cards, category pages, favorites, navbar
  visibility, access profiles, and server-side authorization.
- Add tests for the service logic and at least one route/permission path.

## Registration modules

Domain registration modules live in:

```text
twn_toolkit/tool_modules/
```

Existing examples:

- `fortigate.py`
- `fortiauthenticator.py`
- `network.py`
- `admin.py`

Each module exposes:

```python
def register_tools(registry):
    ...
```

`twn_toolkit/tool_catalog.py` imports those modules and calls their registration
functions from `build_registry()`.

## Tool metadata

Register a tool with `ToolLink`:

```python
from twn_toolkit.tool_catalog import ToolLink

ToolLink(
    "tools.example",
    "Example Tool",
    "Short description used on cards and access-profile screens.",
    "tools.example",
    "network",
    "Network Tools",
)
```

Fields:

- `id`: stable permission/favorite ID. Do not rename casually.
- `label`: user-facing tool name.
- `description`: card/access-profile description.
- `endpoint`: Flask endpoint for the main page.
- `category`: broad workspace key, such as `network` or `fortigate`.
- `category_label`: group heading inside a category page.
- `endpoint_values`: required URL values, such as `{"task_id": "export-aps"}`.
- `risk`: `standard`, `advanced`, or `high`.
- `admin_only`: hide from standard users by default, but still grantable unless
  `grantable=False`.
- `grantable`: whether admins can assign this tool in a custom access profile.
- `show_on_home`: whether the tool itself appears in homepage tool areas. Many
  Fortinet leaf workflows use `False` because the homepage links to the parent
  Fortinet area instead.

## Route ownership

Every route that performs a tool action must map to the owning tool ID:

```python
registry.map_endpoints(
    {
        "tools.example": "tools.example",
        "tools.example_run": "tools.example",
        "tools.example_profiles": "tools.example",
    }
)
```

For FortiGate task routes like `/tasks/<task_id>`, the mapping is derived from
`endpoint_values={"task_id": "..."}` on the `ToolLink`.

If a route should remain self-service or public after login, do not map it to a
restricted tool. Example: Settings is visible to standard users for password
changes, while backup/user/admin actions map to `admin.settings`.

## UI expectations

New tools should inherit the current visual language:

- Use homepage/category launch cards via the registry where possible.
- Use `.panel`, `.panel-head`, `.home-hero`, `.home-section`, or existing tool
  page patterns rather than inventing a new card system.
- Use shared form grids and `.button-row` action clusters; add a named modifier
  only when the tool has a documented layout need that the base pattern should
  not impose everywhere.
- Use `data-loading-message` for actions that may take noticeable server time.
- For dangerous actions, use preview-first flows, explicit confirmation, and
  `risk="high"` in the registry.

## Activity and audit expectations

Every new endpoint that accepts a mutating HTTP method must be classified in
`twn_toolkit/audit_policy.py`. The route-registry audit test is the enforcement
boundary: the pending set is a temporary burn-down list and should remain empty
in ordinary feature work.

- Annotate meaningful operator actions with a bounded resource identity,
  outcome, counts/modes, and curated before/after values.
- Suppress high-frequency polling, previews, helper calls, and interface noise;
  record the user-visible lifecycle boundary instead.
- Explicitly exclude only endpoints whose omission is intentional and document
  the reason in the policy.
- Never copy request bodies, commands, targets, payloads, returned records, or
  secret fields into audit context. Use the shared secret-safe profile and tool
  helpers, with storage-time sanitization as defense in depth.
- Design non-route work separately: background jobs, scheduled work, CLI
  commands, and sensitive reads/exports are not inferred by the route policy.
- Add a deliberate activity metric only for user-initiated executions; raw
  protocol counters and activity score are different signals.

## Access expectations

- Admin users always have implicit full access.
- Operators receive the union of assigned access profiles.
- UI hiding is not security. Route endpoints must also be registered so
  `before_request` can enforce access.
- If a standard user should be able to visit a category landing page because
  they have one tool in that category, do not map the landing page itself to a
  narrow tool permission. Let the category page filter visible cards.

## Testing checklist

For every new tool:

- Service/helper tests for parsing, validation, and core behavior.
- Route smoke test for the page or action.
- Registry test or assertion that the tool appears in `TOOL_BY_ID`.
- Permission test that an allowed user gets `200` and an unallowed user gets
  `403` for action routes.
- If the tool has extra profile/save/delete endpoints, confirm those endpoints
  map to the same tool ID.
- Audit-policy coverage for every mutating endpoint, plus assertions that the
  intended action is recorded or suppressed and that secrets/raw content are
  absent from stored event details.

Run:

```bash
.venv/bin/python -m unittest discover -s tests
```

## Compacted-context reminder

When continuing work after context compaction:

1. Read `docs/agent-continuity.md` for current product and activity rules.
2. Inspect `twn_toolkit/tool_catalog.py` and `twn_toolkit/tool_modules/`.
3. Register new internal tools in the correct domain module.
4. Keep UI cards registry-driven.
5. Keep route authorization server-side.
6. Preserve admin implicit all-access.
7. Keep standard-user access profile behavior as union-of-profiles.
8. Run the full unittest suite before handoff.
