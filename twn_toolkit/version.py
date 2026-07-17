APP_VERSION = "0.11.1"

RELEASE_NOTES = (
    {
        "version": "0.11.1",
        "date": "2026-07-17",
        "title": "Certificate automation beta and scalable network workflows",
        "summary": (
            "Introduces a clearly labeled beta certificate-lifecycle workflow, "
            "higher-capacity Multi-Ping, shared IP-range entry, and a cohesive "
            "interface component pass while providing the first production test "
            "of the verified in-app upgrade path."
        ),
        "groups": (
            {
                "title": "Certificate Automation beta",
                "items": (
                    "Added reusable encrypted enrollment credentials, PKI server profiles, certificate templates, managed private keys, CSR generation, AD CS Web Enrollment submission, pending-request collection, renewal tracking, and certificate/key export formats.",
                    "Labeled Certificate Automation as Beta throughout navigation, Help, and the tool itself because enrollment, renewal, and end-to-end RADIUS deployment have not completed broad production validation.",
                    "Kept HTTPS verification enabled by default with an explicit per-server exception, encrypted saved credentials and managed keys locally, and warned that downloaded archives contain unencrypted private-key material.",
                    "Excluded Certificate Automation data from profile backups so customer-specific PKI endpoints, identities, keys, and credentials cannot be unintentionally transported.",
                ),
            },
            {
                "title": "Multi-Ping capacity and target entry",
                "items": (
                    "Added an optional single-process fping engine for bounded high-capacity rounds up to 250 targets, with a tested 100-target system-ping compatibility fallback when fping is unavailable or unusable.",
                    "Exposed separate round interval and probe timeout controls, sub-second accelerated timeouts, engine and round-duration diagnostics, and adaptive browser-history retention.",
                    "Reworked live results into a searchable status navigator and uncapped user-selected response-time graphs while monitoring and history collection continue for every target.",
                    "Added shared inclusive IPv4 range expansion to Multi-Ping and other bounded host-entry workflows, including deterministic friendly names such as Name-0001.",
                ),
            },
            {
                "title": "Interface consistency",
                "items": (
                    "Standardized reusable profile collections, create/cancel controls, aligned action rows, nested surfaces, empty states, warning spacing, and calm green action styling across administration, Fortinet, SNMP, automation, PKI, and network-tool pages.",
                    "Corrected dashboard metric overflow, form-label alignment, responsive update/recovery layouts, TCP scanner profile alignment, and scroll containment for large Multi-Ping target lists.",
                    "Retained accessible text status alongside color, responsive stacking, dark-theme treatment, and user-controlled graph density without imposing an arbitrary chart limit.",
                ),
            },
            {
                "title": "Compatibility and upgrade validation",
                "items": (
                    "Introduced no incompatible migration of existing application databases or configuration; Certificate Automation uses a separate owner-only local data store.",
                    "Kept installation functional without fping and never invokes a system package manager or sudo automatically; diagnostics explain how to enable accelerated mode.",
                    "Prepared this release as the first production exercise of stable-release discovery, verified bundle installation, matched recovery-point creation, service restart validation, and rollback introduced in v0.11.0.",
                ),
            },
        ),
    },
    {
        "version": "0.11.0",
        "date": "2026-07-15",
        "title": "In-app upgrades, recovery points, and service lifecycle hardening",
        "summary": (
            "Adds a verified, user-facing upgrade and rollback path that does not "
            "depend on locally installed GitHub tools, while making background "
            "service ownership and restart behavior more reliable."
        ),
        "groups": (
            {
                "title": "Updates and recovery",
                "items": (
                    "Added Administration → Updates & Recovery and matching CLI commands to discover stable official releases, review notes, install verified bundles, inspect progress after a restart, and upload an official bundle manually for disconnected hosts.",
                    "Created matched code-and-instance recovery points before an upgrade, with bundle and per-file integrity checks, process/version/database validation, automatic rollback after failed validation, and explicit operator rollback.",
                    "Added release automation that builds the toolkit ZIP, internal file manifest, and external SHA-256 asset required by the updater.",
                    "Documented the bootstrap transition: v0.10.2 and older installations need one final conventional upgrade to v0.11.0; later releases can use the built-in workflow.",
                ),
            },
            {
                "title": "Service lifecycle reliability",
                "items": (
                    "Hardened singleton ownership for the automation scheduler, worker supervisor, and managed transfer services so concurrent starts cannot create duplicate workers or steal active ports.",
                    "Added ownership-aware PID and heartbeat handling plus exact-instance orphan cleanup for safer restarts and recovery validation.",
                    "Stopped installer subprocesses from retaining sensitive or inherited output channels and deferred FTP process resources until after daemonization to avoid macOS resource-tracker and kqueue failures.",
                ),
            },
            {
                "title": "Administration, audit, and interface",
                "items": (
                    "Recorded initiating administrators and terminal outcomes for upgrade, backup, and rollback operations without exposing secrets or bundle contents.",
                    "Exposed upgrade status, recovery points, and failure details consistently in the web interface and CLI so recovery remains available when the web service is restarting or unavailable.",
                    "Separated checkbox labels from supporting help text for readable spacing and accessible interaction across forms.",
                ),
            },
            {
                "title": "Compatibility",
                "items": (
                    "Introduced no database-schema or configuration incompatibility; existing instance data remains in place through a successful upgrade and is restored as a matched pair during rollback.",
                    "Kept secure defaults, legacy SSH exceptions, tool behavior, and existing user workflows unchanged outside the new update and recovery surfaces.",
                ),
            },
        ),
    },
    {
        "version": "0.10.2",
        "date": "2026-07-15",
        "title": "Legacy SSH compatibility controls",
        "summary": (
            "Restores deliberate access to trusted legacy SSH devices without "
            "weakening the toolkit's secure defaults for modern equipment."
        ),
        "groups": (
            {
                "title": "SSH and file-transfer compatibility",
                "items": (
                    "Added explicit legacy SSH compatibility controls to Multi-SSH, Multi-Transfer, SSH/SFTP/SCP automation actions, and the managed SFTP/SCP service.",
                    "Kept legacy algorithms disabled by default and scoped interactive exceptions to a single run; saved automations and service settings remain visibly enabled until an operator disables them.",
                    "Added actionable guidance when a peer rejects all offered host-key algorithms and recorded legacy compatibility use in the audit trail without retaining credentials or remote paths.",
                ),
            },
            {
                "title": "Engineering policy",
                "items": (
                    "Centralized SSH algorithm policy so every Paramiko client and server path follows the same secure-default and explicit-exception behavior.",
                    "Added regression coverage for scoped client exceptions, automation forwarding, managed-service persistence, UI routing, and audit annotations.",
                ),
            },
        ),
    },
    {
        "version": "0.10.1",
        "date": "2026-07-15",
        "title": "Login origin compatibility hotfix",
        "summary": (
            "A focused authentication fix for legitimate same-origin logins made "
            "through hostname aliases, alternate access URLs, or reverse proxies."
        ),
        "groups": (
            {
                "title": "Authentication and request security",
                "items": (
                    "Accepted browser-verified same-origin form submissions even when Flask's backend Host differs from the browser-visible origin.",
                    "Continued to reject browser-classified cross-site mutations and retained strict Origin/Referer comparison as the fallback for clients without same-origin fetch metadata.",
                    "Added a regression test for login through a host alias alongside an explicit cross-site rejection test.",
                ),
            },
            {
                "title": "Test coverage",
                "items": (
                    "Changed local and CI test execution to pytest so unittest classes and fixture-based authentication/server tests run together.",
                    "Activated 27 previously uncollected tests and pinned the development test runner separately from runtime dependencies.",
                    "Corrected an imported NTP helper's test-like alias and one obsolete backup-help assertion exposed by the complete suite.",
                ),
            },
        ),
    },
    {
        "version": "0.10.0",
        "date": "2026-07-15",
        "title": "SNMP interface monitoring, audit completeness, and release hardening",
        "summary": (
            "A pre-1.0 feature release centered on practical live SNMP interface "
            "monitoring, complete secret-safe audit coverage, and safer upgrades and "
            "high-impact operations."
        ),
        "groups": (
            {
                "title": "SNMP interface monitoring",
                "items": (
                    "Added a browser-lived monitor set for up to 20 standard IF-MIB interfaces across saved SNMP hosts, with adjustable 1–60 second polling and retained-window navigation.",
                    "Added compact mirrored download/upload graphs, nearest-sample inspection, observed peaks, link state, speed, errors, and discards.",
                    "Preferred 64-bit high-capacity counters, re-baselined safely after counter or device resets, and isolated sampling failures to the affected interface.",
                    "Improved responsive monitor controls with shared wrapping action rows, consistent spacing, and phone-width layouts without horizontal overflow.",
                ),
            },
            {
                "title": "Audit trail and safer workflows",
                "items": (
                    "Completed route-level audit classification so every mutating endpoint is intentionally annotated, conditionally recorded, suppressed as noise, or explicitly excluded with a reason.",
                    "Added bounded resource context and curated before/after values while recursively redacting credentials, tokens, keys, communities, authorization data, request payloads, and returned content.",
                    "Required explicit preview and confirmation before packet replay, FortiGate bulk rename, and managed-switch reorder changes, with clearer partial-success summaries.",
                    "Recorded deliberate SNMP monitor start and stop boundaries while suppressing high-frequency discovery and polling noise.",
                ),
            },
            {
                "title": "Reliability, upgrade, and recovery",
                "items": (
                    "Added representative v0.9.1 upgrade fixtures, migration compatibility coverage, and a documented backup, verification, and rollback procedure.",
                    "Changed installer upgrades to restart an active toolkit after dependency refresh so the running service cannot remain on stale code or libraries.",
                    "Bounded silent traceroutes, packet replay volume and duration, SCP idle time, and FortiAuthenticator pagination, with prompt cancellation and operator-facing failures.",
                    "Verified managed web, scheduler, supervisor, and transfer-service restart behavior against an existing installation.",
                ),
            },
            {
                "title": "Security and compatibility",
                "items": (
                    "Updated Flask, Requests, and Paramiko and added an audited dependency gate to release CI.",
                    "Rejected cross-origin state-changing requests and added defensive response headers and no-store behavior for authenticated pages.",
                    "Disabled legacy SHA-1 ssh-rsa keys by default across SSH and SFTP/SCP connections; a temporary environment-only compatibility override is available for controlled legacy devices.",
                    "Added documented, reviewed exceptions for dependency advisories whose affected features are disabled or unused by the toolkit.",
                ),
            },
        ),
    },
    {
        "version": "0.9.1",
        "date": "2026-07-13",
        "title": "Managed service reliability hotfix",
        "summary": (
            "A focused reliability update that prevents overlapping service restarts "
            "from orphaning transfer workers or losing their PID ownership state."
        ),
        "groups": (
            {
                "title": "Managed service lifecycle",
                "items": (
                    "Serialized start, stop, and restart operations for managed TFTP, SFTP/SCP, FTP, automation, and supervisor workers.",
                    "Made worker PID-file cleanup ownership-aware so a failed duplicate process cannot remove the active worker's PID file.",
                    "Added supervisor retry backoff and clearer current startup-error reporting when a managed service cannot start.",
                ),
            },
        ),
    },
    {
        "version": "0.9.0",
        "date": "2026-07-13",
        "title": "Local services, transfer workflows, and operational hardening",
        "summary": (
            "A release focused on contained local file services, reusable multi-host "
            "transfers, richer automation, and safer day-to-day operation."
        ),
        "groups": (
            {
                "title": "Datastore and local file services",
                "items": (
                    "Added a contained Datastore browser with list/grid views, drag-and-drop and bulk uploads, multi-select move/delete/download, folder drop targets, and collision-safe filenames.",
                    "Added managed TFTP, SFTP/SCP, and FTP services with selectable datastore roots or runtime-only one-file staging, trusted-client networks, bounded transfer history, and safe incoming filename templates.",
                    "Added atomic uploads, protocol-specific resource limits, persistent SSH host keys, hashed service passwords, passive FTP port controls, and explicit warnings for plaintext protocols.",
                ),
            },
            {
                "title": "Multi-host transfers and automation",
                "items": (
                    "Added Multi-Transfer for concurrent SFTP, SCP, and FTP collection from named hosts into the Datastore or an ephemeral ZIP with per-transfer results.",
                    "Added reusable SSH/FTP file-collection actions with per-host folders, token-based filenames, datastore output, or retained downloadable action artifacts.",
                    "Added user-defined action pipelines: actions run in parallel within each stage, stages run sequentially, and bounded earlier-stage results can feed later Webhook/API notifications.",
                    "Added per-host SNMP AND rules and calculated values, certificate-health conditions, calendar schedules, and richer ICMP/DNS/TCP condition evidence.",
                ),
            },
            {
                "title": "Operations and reliability",
                "items": (
                    "Added global automation worker and queue limits, overlap prevention, check/run retention, datastore and artifact quotas, and a configurable minimum free-disk reserve.",
                    "Added worker heartbeats and supervision, numbered transactional migrations with pre-change snapshots, System Diagnostics, and a structured secret-free administrative audit trail.",
                    "Improved launcher access URLs, hostname/FQDN identity, HTTPS-first fresh installs, permission repair, transfer-service recovery, and clearer partial/failure reporting.",
                    "Added validated and updatable Multi-Host Ping target snapshots so invalid entries do not block valid hosts or mutate an active run while typing.",
                ),
            },
            {
                "title": "Navigation, Help, and interface",
                "items": (
                    "Reorganized the sidebar into functional Network Tool groups, added meaningful icons, and made collapsed navigation hide completely instead of leaving an unusable icon rail.",
                    "Separated Automations, reusable Conditions, and reusable Actions into focused pages under one persistent Automation navigation group.",
                    "Expanded the built-in Help guide for automation, local services, transfers, operations, and release history, with improved search behavior and consistent topic cards.",
                    "Added a custom protocol-themed loading visualization with immediate motion, calmer rotating messages, stable text layout, and reduced-motion support.",
                    "Reorganized Administration settings into coherent system, operations, authentication, access-profile, user, backup, and recovery sections.",
                ),
            },
        ),
    },
    {
        "version": "0.8.0",
        "date": "2026-07-11",
        "title": "Operational dashboard and automation milestone",
        "summary": (
            "A major pre-1.0 milestone that turns the toolkit into a persistent, "
            "profile-aware operations and automation workspace."
        ),
        "groups": (
            {
                "title": "Navigation and dashboard",
                "items": (
                    "Replaced the tool-grid homepage with a persistent, responsive sidebar and operational dashboard.",
                    "Added personal Favorites, global dashboard layout editing, time-filtered metrics, recent activity, and user scoreboards.",
                    "Expanded the built-in Help page into a searchable field guide with release notes.",
                ),
            },
            {
                "title": "Accounts, profiles, and portability",
                "items": (
                    "Added reusable custom access profiles, multi-profile user assignment, and permission-aware navigation.",
                    "Added selectable encrypted backup/restore with combine or replace behavior; secret-bearing exports require encryption.",
                    "Added dashboard-layout and automation-definition backup support while excluding runtime history and captured output.",
                ),
            },
            {
                "title": "Automation",
                "items": (
                    "Added a dedicated scheduler process with reusable conditions, reusable actions, retained checks, and downloadable action runs.",
                    "Added manual, calendar, multi-host ICMP, DNS lookup, per-host TCP service, and saved-profile SNMP conditions.",
                    "Added prompt-aware multi-host SSH collection, RFC 5424 Syslog notifications, and encrypted templated Webhook/API notifications.",
                    "Added one-second monitoring intervals, trigger/recovery debounce, cooldowns, missed-schedule policies, and timezone-aware calendar rules.",
                ),
            },
            {
                "title": "Network, Fortinet, and platform",
                "items": (
                    "Expanded FortiGate/FortiAuthenticator workflows, managed-device exports, rename/reorder tasks, and wireless client history.",
                    "Added or expanded DNS, SNMP, RADIUS, NTP, traceroute, TCP scan, certificate, Path MTU, DHCP, Syslog, Webhook/API, speed-test, and Multi-SSH tools.",
                    "Made Packet Replay functional across macOS and Linux with multi-packet PCAP replay, VLAN fanout/ranges, rewrites, detailed preview, and profile-based access.",
                    "Moved activity tracking to SQLite and made generated self-signed HTTPS the default for fresh installations while preserving existing deployments.",
                ),
            },
        ),
    },
)
