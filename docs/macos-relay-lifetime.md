# macOS relay lifetime

The native network broker no longer terminates every connected relay after 3,700 seconds. That absolute alarm could disconnect an active Remote Terminal session despite its eight-hour idle policy.

Once a connection has been handed to the application, the setup alarm is cancelled. The relay uses monotonic time since the last byte transfer or connection progress:

- Fully open connections expire after eight hours without progress (`RELAY_IDLE_TIMEOUT_MS`).
- Half-closed connections retain the existing five-second idle cleanup (`RELAY_HALF_CLOSE_IDLE_MS`).
- Connection setup retains its 35-second watchdog and bounded connection timeout.
- The 256-child admission limit and privilege/group restrictions remain unchanged.

Traffic resets the relay timer; elapsed connection age alone does not terminate it. The application still controls its own session idle policy and closes its descriptor on session teardown. These are distinct policies: broker activity means stream progress, while application activity follows the terminal session's existing rules. Constants are centralized at the top of `native/macos_network_broker.c`; no new wire protocol or GUI setting is introduced.

The compiled regression harness uses shortened idle intervals to verify bidirectional traffic beyond the idle interval, clean idle expiry while both ends remain open, and half-close/abandonment cleanup. It runs on Linux and macOS; Linux supplies an explicitly failing, test-only peer-authorization stub and exercises only relay behavior. Native macOS authorization and a real active session beyond 62 minutes remain deployment acceptance checks.

Deploying source files or restarting Python workers does not update an installed native helper. Rebuild/reinstall the macOS service/helper using the documented service installation procedure, preserving the installation's options, then validate a new connection. Replacing/restarting the helper can interrupt existing relay connections; coordinate that operation. No helper was deployed or restarted as part of these automated tests.
