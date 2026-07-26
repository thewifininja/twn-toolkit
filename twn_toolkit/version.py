APP_VERSION = "0.13.2"

RELEASE_NOTES = (
    {
        "version": "0.13.2",
        "date": "2026-07-26",
        "title": "Safe CLI recovery for orphaned servers",
        "summary": (
            "Adds a guarded `./twn recover` workflow that identifies orphaned "
            "web processes across Linux and macOS, escalates only when required, "
            "repairs sudo-created ownership, and restores service without "
            "terminating unrelated listeners."
        ),
        "groups": (
            {
                "title": "Server recovery workflow",
                "items": (
                    "Added `./twn recover` to restore a correctly running toolkit after a mismatched privileged start and unprivileged restart leaves Gunicorn bound to the configured port without a usable PID file.",
                    "Detects the saved or configured endpoint, stops managed services cleanly, removes verified orphaned toolkit servers, confirms the port is available, and starts the complete service set again.",
                    "Recognizes Linux and macOS listener tooling, with Linux `/proc` socket inspection as a fallback when `ss`, `lsof`, or `fuser` cannot provide process details.",
                ),
            },
            {
                "title": "Privilege and process safety",
                "items": (
                    "Verifies the Gunicorn application marker, installation-specific executable path or working directory, configured-port ownership, and stale PID-file target before sending a signal.",
                    "Requests sudo only when root-owned processes, hidden listener details, or instance ownership require it; after cleanup it repairs `instance/` ownership and restarts as the invoking user.",
                    "Refuses to terminate a listener that does not match the current toolkit installation and reports the host operating system plus available process details for manual diagnosis.",
                ),
            },
            {
                "title": "Compatibility and operations",
                "items": (
                    "Introduces no application-database, profile, configuration, or dependency migration; the recovery helper uses the Python standard library and host process-inspection facilities.",
                    "Documents the recovery command in the CLI usage, README, Quick Start, and built-in Help while retaining `./twn fix-permissions` for ownership-only repair.",
                    "Retains guided ACME issuance, durable automation, packet capture, upgrade recovery points, and the existing pre-1.0 compatibility policy from v0.13.1.",
                ),
            },
        ),
    },
    {
        "version": "0.13.1",
        "date": "2026-07-25",
        "title": "Guided ACME certificate automation",
        "summary": (
            "Adds a durable, browser-guided Certbot DNS-01 workflow for Let's "
            "Encrypt, makes resolver caching visible alongside authoritative DNS, "
            "and delivers protected certificate material without a time-sensitive "
            "terminal session."
        ),
        "groups": (
            {
                "title": "Guided Let's Encrypt issuance",
                "items": (
                    "Added a background Certbot DNS-01 workflow that pauses for each TXT challenge, survives normal page navigation, and lets operators resume, cancel, inspect, or download a request from retained history.",
                    "Supports Let's Encrypt staging and production, multiple DNS names and wildcards, ECDSA P-256 or RSA 2048 keys, explicit Subscriber Agreement acceptance, and bounded request validation.",
                    "Replaced the time-sensitive manual-auth terminal workflow with copy-ready record names and values, deliberate propagation checks, and an explicit continue action for each challenge.",
                ),
            },
            {
                "title": "DNS propagation clarity",
                "items": (
                    "Checks the workstation or server's configured recursive resolver and the domain's public authoritative nameservers separately so stale local cache answers are visible instead of blocking an otherwise propagated challenge.",
                    "Requires the expected TXT value from every reachable authoritative nameserver before reporting authoritative readiness, while retaining an explicit advisory override for operators who have verified propagation another way.",
                    "Preserves all displayed TXT challenge values until Certbot completes, including sequential challenges that share the same `_acme-challenge` record.",
                ),
            },
            {
                "title": "Protected artifacts and focused interface",
                "items": (
                    "Keeps Certbot account data, request state, logs, and certificate artifacts in owner-only toolkit storage; private keys use mode 0600 and downloads provide leaf, chain, full-chain, key, and combined PEM files in a ready-to-use ZIP.",
                    "Separated ACME and Microsoft AD CS into focused tabs, expanded certificate pages to the full application width, and reflowed the request wizard for narrow screens.",
                    "Graduated the tested ACME workflow from Beta while keeping the Beta label and production-validation guidance scoped to Microsoft AD CS.",
                ),
            },
            {
                "title": "Compatibility and operational safety",
                "items": (
                    "Pins Certbot in the toolkit runtime and invokes noninteractive manual hooks without requiring `/etc/letsencrypt`, sudo, DNS-provider credentials, or changes to operating-system permissions.",
                    "Introduces no application-database or configuration migration; ACME state remains in separate owner-only instance storage and is excluded from profile backups.",
                    "Generic DNS-01 renewal remains a guided workflow. Fully unattended renewal still requires a separately configured DNS-provider API integration with least-privilege credentials.",
                ),
            },
        ),
    },
    {
        "version": "0.13.0",
        "date": "2026-07-25",
        "title": "Reliable automation, packet capture, and email notifications",
        "summary": (
            "Strengthens automation scheduling and multi-condition workflows, "
            "adds bounded standalone and automated packet capture with lightweight "
            "inspection, and delivers metadata-only email notifications through "
            "installation-wide SMTP settings."
        ),
        "groups": (
            {
                "title": "Automation scheduling and conditions",
                "items": (
                    "Hardened scheduled execution with durable SQLite claims, renewable leases, expired-claim recovery, bounded infrastructure retries, overlap protection, queue limits, and explicit missed-schedule policy so restarts and competing schedulers do not silently lose or duplicate work.",
                    "Separated reusable Conditions from Schedules and clarified each automation's run mode, next evaluation, claim state, and scheduler health throughout the interface and documentation.",
                    "Added ALL and ANY condition groups that evaluate multiple reusable conditions in one claimed worker run, preserve per-condition evidence, and migrate existing automations as compatible one-condition ALL groups.",
                    "Added Ping Quality conditions for loss, latency, and jitter across multiple targets plus DNS Performance conditions for response time, failures, and answer consistency across hostname-and-resolver matrices.",
                ),
            },
            {
                "title": "Packet capture and incident evidence",
                "items": (
                    "Added a standalone Packet Capture tool for bounded PCAP collection from local or switch SPAN/mirror-connected interfaces, with validated BPF filters, duration, packet-count, file-size, snapshot-length, and promiscuous-mode controls.",
                    "Runs standalone captures in dedicated background workers that survive browser navigation, enforce one active capture per interface, report live progress, and provide collapsed retained-capture controls.",
                    "Added a reusable Packet Capture automation action backed by the same capture engine, with retained run artifacts or token-named, collision-safe output beneath a selected datastore folder.",
                    "Added a floating, minimizable live and retained PCAP header viewer with auto-scroll, showing bounded source/destination MAC and IP addresses, ports, protocols, VLANs, timestamps, and lengths without exposing packet payloads.",
                    "Added custom Save to datastore controls and direct Inspect PCAP actions beside `.pcap`, `.pcapng`, and `.cap` files in Local Datastore.",
                    "Counts standalone and automated PCAPs against the configured artifact quota and minimum free-disk reserve without installing tcpdump, invoking sudo, or changing host capture permissions.",
                ),
            },
            {
                "title": "Email notification actions",
                "items": (
                    "Added installation-wide SMTP delivery settings with STARTTLS, implicit TLS, or deliberate plaintext transport; encrypted write-only passwords; certificate verification; sender identity; bounded timeouts; and a metadata-free connection test.",
                    "Added templated Email Notification automation actions with validated To, Cc, and Bcc recipients plus subject, message, trigger, condition, timestamp, and earlier-action-result variables.",
                    "Email actions send plain text metadata only and never attach collected files or PCAPs; retained action results record delivery status, subject, recipient counts, and message ID rather than the message body.",
                ),
            },
            {
                "title": "Administration interface",
                "items": (
                    "Split System Settings into focused System, Email, Operations, and Accounts & access views while preserving the correct category after every save or validation error.",
                    "Reorganized Updates & Recovery into Updates, Recovery points, and Profile backups; moved local bundle installation behind progressive disclosure and collapsed individual recovery-point controls.",
                    "Polished responsive form sizing, panel spacing, empty states, status summaries, action buttons, and navigation ordering across administration and automation pages.",
                ),
            },
            {
                "title": "Compatibility and operational safety",
                "items": (
                    "Introduces compatible automation schema migrations for scheduling claims, run modes, schedules, and condition groups; existing definitions, actions, history, and profile data remain in place.",
                    "Packet capture depends on the host's existing packet/BPF access. The toolkit reports permission failures but never installs capture software, invokes sudo, or broadens operating-system privileges.",
                    "Retains verified release bundles, matched recovery points, automatic failed-upgrade restoration, secret-safe audit handling, and the existing pre-1.0 compatibility policy.",
                ),
            },
        ),
    },
    {
        "version": "0.12.0",
        "date": "2026-07-25",
        "title": "Persistent live monitoring and Wake-on-LAN workflows",
        "summary": (
            "Adds a bounded Wake-on-LAN sender and turns live Ping and SNMP "
            "monitoring into durable operator workspaces that continue through "
            "navigation, restore cleanly, and use wide screens more effectively."
        ),
        "groups": (
            {
                "title": "Wake-on-LAN",
                "items": (
                    "Added a grantable Wake-on-LAN tool with reusable device groups, normalized MAC-address entry, selectable IPv4 source interfaces, one to five bounded packets per device, UDP ports 7 and 9, and optional ping confirmation.",
                    "Supports local interface broadcasts plus custom directed-broadcast or relay destinations while clearly distinguishing successful local UDP delivery from proof that a router, relay, firmware, or powered device accepted the request.",
                    "Records secret-safe audit and activity summaries without retaining target MAC addresses or verification hosts in the audit database, and includes saved device groups in selectable profile backups.",
                    "Placed Wake-on-LAN under Services & Protocols throughout navigation, Help, README, and Quick Start guidance.",
                ),
            },
            {
                "title": "Persistent Ping and SNMP monitoring",
                "items": (
                    "Added owner-scoped live-tool sessions and worker-side scheduling so Multi-Ping and SNMP interface monitoring continue while operators navigate elsewhere in the toolkit.",
                    "Added a collapsed-by-default footer dock with rename, card-based restore, and compact stop controls; restored views reload bounded server-side history without storing SNMP credentials in the live-session database.",
                    "Anchored polling to monotonic round deadlines, avoided replaying missed work after long pauses, and increased visible-page refresh cadence so one-second Ping and SNMP intervals render smoothly without dropping collected samples.",
                    "Preserved selected Ping graphs across navigation and condensed each graph header into an adaptive single-row identity, statistics, state, and accessible close control.",
                ),
            },
            {
                "title": "Operator interface and field validation",
                "items": (
                    "Raised the shared page-content ceiling from 1180 to 1600 pixels so graphs, tables, and operational workspaces use wide displays while intentionally narrow forms retain their focused widths.",
                    "Validated the standard system-ping fallback on Linux without fping, then confirmed that installing fping and restarting the toolkit enables high-capacity mode through the existing capability check.",
                    "Completed real-device SNMP interface-monitor validation and retained Certificate Automation as the only explicitly labeled Beta workflow.",
                ),
            },
            {
                "title": "Compatibility and upgrade safety",
                "items": (
                    "Introduces no incompatible migration of existing application databases, profiles, or configuration; live monitoring uses a separate owner-only transient session store.",
                    "Keeps Multi-Ping functional without fping and does not install system packages or request elevated privileges automatically.",
                    "Retains the verified release-bundle, recovery-point, service validation, and rollback workflow successfully exercised by the v0.11.1 production upgrade.",
                ),
            },
        ),
    },
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
