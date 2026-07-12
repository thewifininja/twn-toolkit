APP_VERSION = "0.8.0"

RELEASE_NOTES = (
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
                    "Added manual, calendar, multi-host ICMP, DNS lookup, per-host TCP service, and saved-profile SNMP OID value conditions.",
                    "Added prompt-aware multi-host SSH collection and RFC 5424 Syslog notification actions.",
                    "Added encrypted, templated Webhook/API notifications with JSON-safe trigger variables and per-endpoint delivery results.",
                    "Added one-second monitoring intervals, trigger/recovery debounce, cooldowns, missed-schedule policies, and timezone-aware calendar rules.",
                    "Added user-defined action stages: actions run in parallel within a stage, stages run sequentially, and bounded earlier-stage results can feed later Webhook/API notifications.",
                    "Added per-host AND logic and reusable calculated values for SNMP conditions, including percentage, remaining-percentage, difference, and sum formulas over scalar OIDs.",
                    "Added multi-target certificate health conditions with expiration, hostname, system-trust, chain-order, and connection-failure policies.",
                ),
            },
            {
                "title": "Network and Fortinet tooling",
                "items": (
                    "Expanded FortiGate/FortiAuthenticator profile workflows, managed device exports, rename/reorder tasks, and wireless client history.",
                    "Added or expanded DNS, SNMP, RADIUS, NTP, traceroute, TCP scan, certificate, Path MTU, DHCP, Syslog, Webhook/API, speed test, and Multi-SSH tools.",
                    "Made Packet Replay functional across macOS/Linux with multi-packet PCAP replay, VLAN fanout/ranges, rewrites, detailed preview, and profile-based access.",
                ),
            },
            {
                "title": "Operations and reliability",
                "items": (
                    "Added bounded device/API timeouts, shared loading feedback, clearer per-target test results, and responsive card patterns.",
                    "Improved the launcher with separate web/scheduler status, dependency checks, permission diagnostics, and fix-permissions support.",
                    "Moved activity tracking to SQLite with time-window queries and retained automatic compatibility for older saved formats.",
                    "Made generated self-signed HTTPS the default for fresh installations while preserving existing deployments, with strict private-key validation, secure session cookies, and an HTTP fallback switch.",
                    "Added configurable short instance names and preferred FQDNs for browser titles, sidebar identity, launcher URLs, and explicit self-signed certificate regeneration without DNS lookup validation.",
                ),
            },
        ),
    },
)
