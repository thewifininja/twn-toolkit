# v0.16.0 release checklist

## Boot-managed service lifecycle

- [x] `./twn service` installs, starts, stops, restarts, inspects, logs, and
  uninstalls a systemd unit on supported Linux or a system LaunchDaemon on
  macOS while running the toolkit as the selected normal account.
- [x] Service installation validates the checkout, virtual environment, service
  account, existing runtime ownership, platform, and macOS protected-folder
  boundary before changing the host service definition.
- [x] macOS installation declares success only after launchd is active and the
  web process, scheduler, and supervisor are ready; a failed definition is
  removed instead of remaining in a crash loop.
- [x] Normal `./twn start`, `stop`, and `restart` coordinate with a loaded OS
  supervisor, and upgrade/recovery lifecycle tests preserve that context.
- [x] Ubuntu/Raspberry Pi systemd field validation covered reboot autostart,
  stop/start, deliberate Gunicorn termination and recovery, status/logging,
  uninstall, and a clean not-installed result afterward.
- [x] macOS LaunchDaemon field validation covered protected-path rejection,
  installation from an unprotected checkout, readiness/status, normal launcher
  pause/resume, uninstall, reinstall, and data-retaining removal.

## Scoped packet permissions and DHCP parity

- [x] The default Linux unit has no added capabilities; explicit
  `--network-capabilities` bounds the service tree to `CAP_NET_RAW`,
  `CAP_NET_ADMIN`, and `CAP_NET_BIND_SERVICE` with `NoNewPrivileges=true` and
  never modifies the reusable Python interpreter.
- [x] Raspberry Pi field validation exercised Packet Capture, Packet Replay,
  and DHCP Discover through the capability-enabled normal-user service.
- [x] macOS remains a normal-user service and documents persistent,
  administrator-managed BPF access rather than elevating the web application;
  low-numbered listeners retain their documented high-port alternative.
- [x] macOS DHCP opens its BPF listener before transmission, sends one valid
  Ethernet/IPv4/UDP Discover, accepts only matching Offers, deduplicates them,
  and never sends a Request or configures an address.
- [x] A real no-sudo macOS hardware probe and the installed LaunchDaemon web UI
  both received an Offer through BPF with the service account in the
  `access_bpf` group.

## Responsive navigation

- [x] The mobile sidebar follows `visualViewport` height, retains an independent
  scrolling tool tree, and keeps Help/release notes, instance identity, and the
  installed version reachable across Android Chrome zoom and browser controls.
- [x] Coarse-pointer layouts receive the mobile navigation treatment even when
  browser zoom changes the CSS viewport width.
- [x] Desktop navigation is more compact without removing the configured
  instance name, and direct tool rows use the same indentation guide and spacing
  as nested tools.
- [x] Sidebar JavaScript is application-version cache-busted and the viewport,
  footer, labeling, and indentation contracts have regression coverage.

## Compatibility, documentation, and release gates

- [x] v0.16.0 introduces no Python dependency, application-database schema,
  profile, configuration, or automation migration and supports direct upgrade
  from v0.15.1.
- [x] The service is opt-in: existing manual installations remain manual, and
  uninstall removes only OS boot management while retaining toolkit data.
- [x] Feature PRs #89, #90, and #91 passed their platform CI before squash merge,
  and merged `main` CI passed before release preparation.
- [x] `APP_VERSION`, README, Quick Start, built-in Help, structured release
  notes, service/DHCP/capture/replay/upgrade guides, tests, and continuity
  guidance all describe the v0.16.0 behavior.
- [x] Build the v0.16.0 bundle from release-preparation source and verify its
  internal manifest and external SHA-256 checksum.
- [x] Pass the complete pytest suite and release-specific metadata tests both in
  the working checkout and in a clean clone with a fresh virtual environment.
- [ ] Pass release-preparation pull-request CI and merged-main CI.
- [ ] Create and push the exact annotated `v0.16.0` tag only after the project
  owner explicitly approves release publication.
- [ ] Pass tag CI/version validation and publish the GitHub release.
- [ ] Verify the published release contains `twn-toolkit-v0.16.0.zip` and
  `twn-toolkit-v0.16.0.zip.sha256` before announcing upgrade availability.

Do not tag or publish from this preparation branch. The project owner explicitly
approves release publication after reviewing the release PR and merged-main CI.
