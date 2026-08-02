APP_VERSION = "0.16.3"

RELEASE_NOTES = (
    {
        "version": "0.16.3",
        "date": "2026-08-02",
        "title": "Safe service-managed upgrade finalization",
        "summary": (
            "Finalizes upgrades and recovery before systemd or launchd reloads "
            "the boot-managed launcher, preventing a successful installation "
            "from remaining stuck in validating state."
        ),
        "groups": (
            {
                "title": "Finalization before launcher reload",
                "items": (
                    "Keeps the existing boot-managed launcher paused while the replacement web process, automation scheduler, worker supervisor, enabled listeners, installed version, and SQLite databases are validated.",
                    "Records terminal status and audit evidence, cleans the staged request and bundle, and removes the operation lock before systemd or launchd reloads twn from the finalized files on disk.",
                    "Prevents systemd KillMode=mixed and equivalent service-job cleanup from terminating the detached updater before its final status and cleanup writes complete.",
                ),
            },
            {
                "title": "Rollback-safe service handoff",
                "items": (
                    "Prepares the deferred handoff before replacing or restoring application files and withholds launcher discovery even when a matched instance recovery point contains an older launcher PID file.",
                    "Suppresses the validation-only startup generation so the final OS-managed start emits exactly one toolkit-start automation event; a successful automatic rollback can instead let the matching original launcher adopt the validated restored processes.",
                    "Bounds the finalization wait, retains a healthy validated process set if handoff times out, and writes diagnostics to .twn-upgrades/service-reload.log.",
                ),
            },
            {
                "title": "Compatible v0.16.2 hotfix",
                "items": (
                    "Includes a request-scoped compatibility bridge that recognizes upgrades launched by the already-installed v0.16.2 updater before the new lifecycle code is available to it.",
                    "Introduces no Python dependency, database migration, profile-format, server-setting, capability, BPF-policy, or command-line incompatibility and supports direct upgrade from v0.16.2.",
                    "Preserves ordinary ./twn restart pause-and-resume behavior, synchronous manual installer reloads outside an active upgrade, service ownership, managed listeners, instance data, and matched rollback guarantees.",
                ),
            },
        ),
    },
    {
        "version": "0.16.2",
        "date": "2026-08-02",
        "title": "Reliable service-managed upgrades",
        "summary": (
            "Reloads the boot-managed launcher after application upgrades so "
            "systemd and launchd installations run the newly installed lifecycle "
            "code without a separate administrator service restart."
        ),
        "groups": (
            {
                "title": "Automatic launcher replacement",
                "items": (
                    "Marks installer-driven starts as code-changing restarts, while preserving the lightweight pause-and-resume behavior of an ordinary ./twn restart.",
                    "Makes a paused boot-service launcher exit deliberately after an upgrade so systemd or launchd starts a fresh copy of the newly installed twn script from disk.",
                    "Leaves manual installations on their existing lifecycle and does not install, remove, or rewrite an optional OS service definition.",
                ),
            },
            {
                "title": "Verified service continuity",
                "items": (
                    "Waits for the service launcher PID to change and for the web process, automation scheduler, worker supervisor, and endpoint metadata to become ready before installation succeeds.",
                    "Returns through the OS service manager with the configured normal account and existing Linux capability or macOS BPF policy instead of prompting for another administrator operation.",
                    "Bounds launcher-reload waiting and points failed upgrades to the existing service status and service logs commands for actionable diagnosis.",
                ),
            },
            {
                "title": "Compatible maintenance upgrade",
                "items": (
                    "Introduces no Python dependency, database migration, profile-format, server-setting, permission-policy, or command-line incompatibility and supports direct upgrade from v0.16.1.",
                    "Preserves startup automations, managed listeners, service ownership, optional network capabilities, instance data, and the verified matched recovery-point workflow.",
                    "Updates installer regression coverage, launcher lifecycle assertions, built-in Help, Quick Start, and service and upgrade documentation around the corrected behavior.",
                ),
            },
        ),
    },
    {
        "version": "0.16.1",
        "date": "2026-08-02",
        "title": "Startup announcements and system identity",
        "summary": (
            "Adds durable host-boot and toolkit-start automations with bounded "
            "system identity, making a boot-managed Raspberry Pi easy to find "
            "and announce after it receives a DHCP address."
        ),
        "groups": (
            {
                "title": "Startup-triggered automations",
                "items": (
                    "Adds Once per host boot and Every complete toolkit start run modes. Arming records the current startup as a baseline instead of firing immediately, and a scheduler-only restart does not create another startup event.",
                    "Commits each new startup generation and its execution job atomically, deduplicates delivery across scheduler crashes and restarts, and waits up to 120 seconds for a usable non-loopback address before running even if networking remains unavailable.",
                    "Adds a baseline-preserving Test now action plus startup-specific status and history, so a notification can be verified without consuming the next real boot or toolkit-start event.",
                ),
            },
            {
                "title": "Identity-aware notifications",
                "items": (
                    "Collects a bounded configured instance name, hostname, toolkit version, current IPv4 and IPv6 addresses, and reachable toolkit URLs without exposing credentials or internal startup generation IDs.",
                    "Makes toolkit.* and startup.* variables available to Webhook/API, Email, and Syslog templates; exact JSON address and URL tokens remain typed lists while embedded and text substitutions use compact JSON text.",
                    "Supports DHCP appliance announcements such as a Raspberry Pi posting its current address and access URL to Discord, email, another webhook, or a Syslog collector after boot.",
                ),
            },
            {
                "title": "Compatible, snapshot-backed upgrade",
                "items": (
                    "Adds toolkit migration 3 and automation schema migration 7 for durable startup-event state. The migration creates a pre-change database snapshot before changing the automation schema and preserves existing definitions, pipelines, history, and retained output.",
                    "Introduces no Python dependency, profile-format, server-setting, or command-line incompatibility and supports direct upgrade from v0.16.0 through the verified release-bundle workflow.",
                    "Keeps rollback paired with its matched recovery snapshot; do not run older v0.16.0 code directly against an instance after its automation database has migrated.",
                ),
            },
        ),
    },
    {
        "version": "0.16.0",
        "date": "2026-08-02",
        "title": "Boot-managed service and macOS network-tool parity",
        "summary": (
            "Adds a production-oriented boot service for systemd Linux and macOS, "
            "keeps powerful network access scoped to the service account, and makes "
            "the complete navigation usable across mobile browser viewport behavior."
        ),
        "groups": (
            {
                "title": "Cross-platform boot service",
                "items": (
                    "Adds ./twn service install, status, logs, start, stop, restart, and uninstall for systemd-based Linux—including Ubuntu and Raspberry Pi OS—and a system LaunchDaemon on macOS.",
                    "Runs the managed toolkit as the selected normal account, verifies the web process, scheduler, and supervisor before declaring macOS installation successful, restarts after an unexpected process failure, and returns automatically after reboot.",
                    "Keeps ordinary ./twn start, stop, restart, upgrade, rollback, and recovery coordinated with the loaded OS supervisor; uninstall removes only the service definition and retains instance data, Datastore files, captures, certificates, and logs.",
                ),
            },
            {
                "title": "Explicit, least-privilege network access",
                "items": (
                    "Offers an opt-in Linux --network-capabilities service mode bounded to CAP_NET_RAW, CAP_NET_ADMIN, and CAP_NET_BIND_SERVICE for packet capture, replay, DHCP client-port access, promiscuous mode, and low-numbered listeners without running the toolkit as root.",
                    "Keeps the macOS LaunchDaemon unprivileged and documents persistent administrator-managed BPF access, including Wireshark's optional ChmodBPF service and access_bpf group, for packet capture, Packet Replay, and DHCP Discover.",
                    "Moves macOS DHCP Discover to one BPF-transmitted Ethernet/IPv4/UDP Discover with matching Offer capture, avoiding a privileged port-68 bind while never sending a Request or accepting a lease.",
                ),
            },
            {
                "title": "Reliable responsive navigation",
                "items": (
                    "Keeps Help, release notes, the configured instance name, and installed version reachable at the bottom of the mobile sidebar under Android Chrome and other browsers whose visual viewport changes with zoom or browser controls.",
                    "Makes the desktop sidebar more compact without hiding instance identity and aligns direct tools with nested tools through the same indentation and guide treatment.",
                    "Refreshes the sidebar script by application version so upgraded browsers do not retain the older viewport behavior from cache.",
                ),
            },
            {
                "title": "Compatible, opt-in upgrade",
                "items": (
                    "Introduces no Python dependency, application-database schema, profile, configuration, or automation migration and supports direct upgrade from v0.15.1 through the verified release-bundle and matched rollback workflow.",
                    "Leaves existing manual installations manual until an administrator explicitly installs the OS service, and preserves existing toolkit data and high-port listener defaults.",
                    "Requires macOS service installations to live outside Desktop, Documents, Downloads, iCloud Drive, and ~/Library/CloudStorage; manual installations may remain there, while relocated checkouts need a rebuilt virtual environment because it contains absolute paths.",
                ),
            },
        ),
    },
    {
        "version": "0.15.1",
        "date": "2026-08-02",
        "title": "Reliable automation cadence and Datastore packet replay",
        "summary": (
            "Keeps fast automation Ping monitoring on a stable, non-overlapping "
            "cadence and lets authorized operators replay compatible captures "
            "directly from the contained Datastore."
        ),
        "groups": (
            {
                "title": "Reliable one-second automation monitoring",
                "items": (
                    "Anchors condition deadlines to their intended start-to-start cadence and prevents a due round from being claimed and discarded while the preceding check is still finishing.",
                    "Keeps rounds for one automation non-overlapping, starts a waiting round promptly after completion, resumes long pauses without replaying a backlog, and timestamps history when observation begins rather than after a timeout returns.",
                    "Brings Multi-Ping's capability-aware timeout validation to Automation Ping: a verified accelerated fping engine accepts 0.1–10 second values such as 0.9 seconds, while the standard compatibility engine retains its honest one-second minimum.",
                ),
            },
            {
                "title": "Packet Replay from retained captures",
                "items": (
                    "Adds a contained Datastore picker beside local upload and raw-frame hex so compatible classic .pcap and .cap files can be previewed without downloading and uploading them again.",
                    "Requires both Packet Replay and Datastore access for non-administrators, recursively lists only contained regular capture files, ignores symbolic links, and keeps the existing 256 KiB capture limit visible before selection.",
                    "Supports multi-packet captures and carries the prepared packet sequence into the confirmed send step, applying MAC rewriting, VLAN handling, fanout, repeat, frame-count, and scheduled-duration limits to every source packet.",
                ),
            },
            {
                "title": "Compatible maintenance upgrade",
                "items": (
                    "Introduces no application-database schema, dependency, profile, configuration, command-line, or automation migration and supports direct upgrade from v0.15.0.",
                    "Preserves upload and raw-hex Packet Replay sources, existing replay authorization confirmation, saved automation definitions and state, retained history, Datastore contents, and the host's current packet-transmit permission boundary.",
                    "Keeps PCAPNG available for retained capture inspection but explicitly limits replay selection to classic Ethernet PCAP until that parser is supported.",
                ),
            },
        ),
    },
    {
        "version": "0.15.0",
        "date": "2026-08-01",
        "title": "Multicast diagnostics and durable automation orchestration",
        "summary": (
            "Adds a purpose-built live multicast testing workspace and durable "
            "delayed automation stages, with bounded webhook retries plus "
            "stronger responsive and background-service behavior."
        ),
        "groups": (
            {
                "title": "Purpose-built multicast diagnostics",
                "items": (
                    "Adds authorized IPv4 ASM and SSM listening on an explicit interface with live packet, byte, rate, source, elapsed-time, and one-second timeline telemetry instead of a blocking loading screen.",
                    "Adds bounded Send and dual-interface End-to-end modes with controllable rate, payload, TTL, DSCP, and source port; TWN sequence reports expose loss, duplication, and reordering, while RTP inspection adds SSRC, payload-type, gap, ordering, and jitter evidence.",
                    "Provides protocol quick setups, reusable-port support, cancelable runs, bounded JSON reports, detailed interpretation guidance, and a separately authorized macOS PF helper that can detect, install, verify, update, and uninstall only TWN-managed IGMP compatibility rules.",
                ),
            },
            {
                "title": "Durable automation pacing and delivery evidence",
                "items": (
                    "Lets every automation stage after the first wait from zero seconds through 24 hours after its continuation policy succeeds, making planned recovery windows part of the saved pipeline.",
                    "Persists encrypted completed-stage progress, moves delayed jobs into a visible waiting state, releases the worker and lease instead of sleeping, and resumes the correct next stage after its due time or a toolkit restart.",
                    "Validates Webhook/API success statuses and adds optional bounded exponential-backoff retries for network failures or selected HTTP responses, retaining each endpoint's delivery attempts while keeping one attempt as the default.",
                ),
            },
            {
                "title": "Responsive diagnostics and reliable local services",
                "items": (
                    "Keeps Multi-Ping response graphs, statistics, status controls, and close actions inside their cards and redraws each canvas when its workspace changes width across wide, narrow, and phone layouts.",
                    "Adds exact readiness markers for TFTP, FTP, and SFTP/SCP workers so status and supervision distinguish a bound listener from a process that merely started, while stale and zombie processes no longer appear healthy.",
                    "Starts and stops independent transfer services concurrently, scopes daemon locks to the installation instance, avoids unnecessary Flask application imports in command-line workers, and coordinates supervisor recovery with active service operations.",
                ),
            },
            {
                "title": "Compatible, explicit upgrade behavior",
                "items": (
                    "Adds transactional automation migration 6 and toolkit migration 2 for encrypted delayed-stage progress, including the existing pre-change SQLite snapshot path and compatibility for older single-stage or staged definitions.",
                    "Uses native multicast sockets without adding a dependency and never changes the host firewall from the web interface or general installer; macOS PF changes occur only through the explicit privileged helper and remain independently removable.",
                    "Introduces no destructive profile or configuration conversion, preserves existing iPerf3, automation, transfer, dashboard, and diagnostic data, and supports direct upgrade from v0.14.4 through the verified release-bundle and rollback workflow.",
                ),
            },
        ),
    },
    {
        "version": "0.14.4",
        "date": "2026-07-27",
        "title": "iPerf3 diagnostics and supervised listeners",
        "summary": (
            "Adds bounded iPerf3 client testing plus a supervised background "
            "listener that survives navigation and toolkit restarts while "
            "collecting private, detailed results from sequential clients."
        ),
        "groups": (
            {
                "title": "Flexible, bounded client diagnostics",
                "items": (
                    "Adds authorization-confirmed TCP and UDP client tests using only an iPerf3 binary already installed on the toolkit host; the toolkit never installs the dependency.",
                    "Supports forward or reverse direction, IPv4 or IPv6 selection, an optional source address, as many as 20 parallel streams, and an explicit bounded UDP target rate.",
                    "Caps each client run at 60 seconds and presents normalized connection, throughput, transfer, retransmit or loss/jitter, interval, CPU, command, and bounded raw-JSON details.",
                ),
            },
            {
                "title": "A supervised background listener",
                "items": (
                    "Replaces one-shot server behavior with explicit On/Off management for a listener that accepts multiple sequential tests independently of the page.",
                    "Shows the owner’s active listener and completed-test count in Live tools, dashboard status, system diagnostics, toolkit status, and managed logs.",
                    "Restores enabled listeners after toolkit restarts and safely verifies and removes exact recorded worker or native iPerf3 processes before recovering from a crash or legacy orphan.",
                ),
            },
            {
                "title": "Private retained server results",
                "items": (
                    "Retains the newest 50 completed server tests per user as collapsed source-address cards with expandable endpoints, sender and receiver metrics, intervals, CPU use, and bounded full JSON.",
                    "Rejects busy bind addresses or ports synchronously, limits listener ports to 1024–65535, permits one managed listener per user, and caps each accepted server test at ten minutes.",
                    "Adds an owner-only iPerf3 SQLite database on first use without changing existing application databases, dependencies, profiles, configuration, or automation data, and supports direct upgrade from v0.14.3.",
                ),
            },
        ),
    },
    {
        "version": "0.14.3",
        "date": "2026-07-27",
        "title": "Ordered Favorites and DNS performance testing",
        "summary": (
            "Makes personal Favorites directly reorderable and rebuilds DNS "
            "testing as a clear comparison workspace with an explicitly "
            "authorized, bounded resolver load-test mode."
        ),
        "groups": (
            {
                "title": "Favorites in your preferred order",
                "items": (
                    "Adds always-available drag handles whenever two or more Favorites are visible, with automatic saving instead of a separate reorder mode or text link.",
                    "Supports pointer dragging plus keyboard up/down arrows on the same focused handles, while keeping each star action vertically aligned with its tool label.",
                    "Preserves user-specific and permission-filtered Favorites, safely retains temporarily hidden entries, and applies the saved order to dashboard Quick launch.",
                ),
            },
            {
                "title": "A clearer DNS testing workspace",
                "items": (
                    "Reorganizes DNS testing into matched query and resolver cards plus a full-width run configuration, eliminating the mismatched fields and action rows from the earlier page.",
                    "Keeps multi-resolver answer comparison while adding at-a-glance query, success, average-response, and slowest-response summaries before the detailed result table.",
                    "Moves saved-list management into compact expandable controls and carries profile selections, validation messages, and submitted values cleanly across each workflow.",
                ),
            },
            {
                "title": "Bounded DNS load diagnostics",
                "items": (
                    "Adds an authorization-gated load-test mode with per-resolver target rate, duration, global concurrency, and a live total-query estimate.",
                    "Caps each run at 500 QPS per resolver, 30 seconds, five resolvers, 100 concurrent queries, and 50,000 planned queries; saturated runs stop submitting at the requested deadline rather than creating a catch-up burst.",
                    "Reports achieved throughput, success rate, response statuses, and successful-query average, p50, p95, p99, and maximum latency without introducing an application-database, dependency, profile, configuration, command-line, or automation migration.",
                ),
            },
        ),
    },
    {
        "version": "0.14.2",
        "date": "2026-07-26",
        "title": "Operator workspace dashboard",
        "summary": (
            "Refocuses the dashboard into a calmer daily workspace for "
            "launching permitted tools, spotting work that needs attention, "
            "and reviewing recent activity without making team scores the "
            "center of the experience."
        ),
        "groups": (
            {
                "title": "A clearer daily starting point",
                "items": (
                    "Replaces the former command-center presentation with a compact operator workspace organized around quick launch, workspace health, and recent work.",
                    "Adds permission-aware dashboard search and a four-card quick launch that uses the current operator's Favorites first, then offers common diagnostics when no Favorites are set.",
                    "Summarizes the current operator's persistent live tools plus administrator-visible automation state and selected-range activity in one restrained status strip.",
                ),
            },
            {
                "title": "Activity without the leaderboard feel",
                "items": (
                    "Pairs a readable recent-activity timeline with a four-metric snapshot so the most useful operational context remains visible without presenting the full counter wall up front.",
                    "Keeps every existing metric, reset control, time range, and administrator-managed drag-and-drop layout in an expandable All activity metrics section.",
                    "Moves team comparison into an optional collapsed section that appears only when multiple operators or contributors make it relevant.",
                ),
            },
            {
                "title": "Responsive, compatible polish",
                "items": (
                    "Adds cohesive light and dark styling across desktop, narrow, and phone layouts, improves activity timestamps, and lets workspace status open the persistent live-tools tray directly.",
                    "Preserves permission filtering, personal Favorites, activity attribution, custom ranges, metric visibility, ranking choices, and existing dashboard backup behavior.",
                    "Introduces no application-database schema, dependency, profile, configuration, command-line, or automation migration and remains a direct upgrade from v0.14.1.",
                ),
            },
        ),
    },
    {
        "version": "0.14.1",
        "date": "2026-07-26",
        "title": "Unified Multi-SSH workflow and compact host import",
        "summary": (
            "Streamlines Multi-SSH into one preview-first target-matrix "
            "workflow while retaining friendly host lists and inclusive IP "
            "ranges through a compact importer that stays out of the way until "
            "needed."
        ),
        "groups": (
            {
                "title": "One clear Multi-SSH workflow",
                "items": (
                    "Removes the separate Basic and Advanced page modes so every run follows the same target-matrix, command-template, signed-preview, and credential-entry sequence.",
                    "Keeps the spreadsheet-style table, Raw Matrix editor, per-host variables, Stored Commandlets, result exports, and prompt-aware execution available without first choosing or loading a mode.",
                    "Continues supporting as many as 5,000 targets, submitted in batches of 50 with no more than 10 simultaneous SSH connections and bounded output capture.",
                ),
            },
            {
                "title": "Compact host and range import",
                "items": (
                    "Adds a deliberately understated host importer beneath the target table that expands friendly `Name = host` entries plus inclusive IPv4 and IPv6 ranges into editable matrix rows.",
                    "Lets an operator append imported targets or replace the current rows while preserving custom variable columns for the resulting matrix.",
                    "Reuses the existing validated host and range parser, reports malformed or descending ranges inline, and keeps importer requests out of the audit trail because they do not connect to or modify a target.",
                ),
            },
            {
                "title": "Safe compatibility",
                "items": (
                    "Redirects older Basic and Advanced mode links to the unified page while preserving requested Commandlet load and duplication parameters.",
                    "Converts a legacy Basic form submission into a signed command preview instead of executing immediately; its submitted password is neither retained nor rendered.",
                    "Introduces no application-database schema, dependency, profile, configuration, command-line, or automation migration and remains a direct upgrade from v0.14.0.",
                ),
            },
        ),
    },
    {
        "version": "0.14.0",
        "date": "2026-07-26",
        "title": "Variable-aware Multi-SSH Commandlets and fleet automation",
        "summary": (
            "Adds reusable SSH command templates, spreadsheet-style per-host "
            "variables, signed execution previews, and bounded fleet processing "
            "for interactive and automated diagnostics across as many as "
            "5,000 targets."
        ),
        "groups": (
            {
                "title": "Reusable command authoring",
                "items": (
                    "Adds Advanced Multi-SSH with a spreadsheet-style target table, fixed Name and Host columns, operator-defined variable columns, keyboard navigation, multi-cell paste, and a Raw Matrix editor for pipe-, tab-, or comma-separated data.",
                    "Renders literal `{{ variable }}` references independently for every target, provides built-in name, host, and row_number values, and supports an explicit escape when braces must remain literal.",
                    "Adds Stored Commandlets with a name, platform, description, commands, default timeout, duplication, and an optional saved target matrix; Commandlets are included in profile backup and restore but never contain credentials.",
                ),
            },
            {
                "title": "Preview-first fleet execution",
                "items": (
                    "Requires a signed per-host preview before Advanced Multi-SSH exposes credentials or permits execution, and invalidates that approval when the target matrix, rendered commands, or timeout changes.",
                    "Accepts up to 5,000 targets and processes them in batches of 50 with no more than 10 simultaneous SSH connections while preserving target order.",
                    "Applies bounded aggregate and per-host output capture so large diagnostic fleets cannot produce unbounded retained output; previews summarize oversized fleets without hiding the execution scale.",
                ),
            },
            {
                "title": "Automation action integration",
                "items": (
                    "Extends SSH collection actions with the same target matrix, per-host variable rendering, spreadsheet editor, fleet batching, and output limits used by interactive Multi-SSH.",
                    "Makes direct target and command authoring the default automation flow while offering Stored Commandlet loading as an explicitly optional shortcut.",
                    "Copies a loaded Commandlet into the action as an independent snapshot, keeps saved credentials encrypted and write-only, and continues accepting legacy SSH action host lists.",
                ),
            },
            {
                "title": "Compatibility and scope",
                "items": (
                    "Keeps Basic Multi-SSH as the default straightforward host-list workflow, including friendly names, inclusive IP ranges, prompt-aware completion, per-command timeouts, exports, and explicit legacy-algorithm exceptions.",
                    "Introduces no application-database schema, dependency, command-line, or existing configuration migration; the optional owner-only Commandlet profile file is created only when Commandlets are saved.",
                    "Retains guided ACME issuance, durable automation scheduling, packet workflows, safe CLI recovery, verified upgrades, and the existing pre-1.0 compatibility policy from v0.13.3.",
                ),
            },
        ),
    },
    {
        "version": "0.13.3",
        "date": "2026-07-26",
        "title": "Faster macOS CI and SMTP hostname handling",
        "summary": (
            "Removes unnecessary host-name resolution from SMTP Message-ID "
            "generation and isolates host-sensitive tests from transient CI "
            "runner names, cutting the macOS validation job from more than "
            "four minutes to under one minute."
        ),
        "groups": (
            {
                "title": "SMTP delivery reliability",
                "items": (
                    "Generates each SMTP Message-ID with the already validated sender-address domain instead of resolving the toolkit host's fully qualified domain name.",
                    "Avoids long DNS timeouts on macOS and other hosts whose local or transient hostname is intentionally absent from DNS.",
                    "Preserves the configured recipients, sender, authentication, encryption policy, message body, and per-recipient delivery reporting.",
                ),
            },
            {
                "title": "Faster, observable validation",
                "items": (
                    "Isolates managed-certificate route validation from the GitHub macOS runner's transient hostname while continuing to exercise real certificate generation and signing.",
                    "Avoids loading the macOS system trust store in the fully mocked SMTP transport test, where no real TLS connection is made.",
                    "Reports the 50 slowest tests in every CI job so future platform-specific performance regressions are visible in the job log.",
                ),
            },
            {
                "title": "Compatibility and scope",
                "items": (
                    "Introduces no application-database, profile, configuration, command-line, or dependency migration.",
                    "Retains safe CLI server recovery, guided ACME issuance, durable automation, packet capture, verified upgrades, and the existing pre-1.0 compatibility policy from v0.13.2.",
                ),
            },
        ),
    },
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
                    "Requests sudo only when root-owned processes, hidden listener details, or runtime ownership require it; after cleanup it repairs `instance/`, updater workspace, and release-manifest ownership before restarting as the invoking user.",
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
