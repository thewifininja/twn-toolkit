APP_VERSION = "0.10.0"

RELEASE_NOTES = (
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
